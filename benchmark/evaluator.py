"""Independent binary packet evaluator and fixed-window truth summaries."""

from __future__ import annotations

from dataclasses import dataclass

from . import SCHEMA_VERSION
from .contracts import (
    AttackEvent, ContractError, GroundTruth, Label, Observation, Prediction,
    RunMetadata, TrafficProvenance, Unit,
)


def _index(records, record_type, key, run_id):
    result = {}
    for record in records:
        if not isinstance(record, record_type):
            raise ContractError(f"expected {record_type.__name__}")
        if record.run_id != run_id:
            raise ContractError("record belongs to a different run")
        identifier = getattr(record, key)
        if identifier in result:
            raise ContractError(f"duplicate {key}: {identifier}")
        result[identifier] = record
    return result


def _validate(run, observations, truths, predictions, provenance, events):
    if not isinstance(run, RunMetadata):
        raise ContractError("expected RunMetadata")
    obs = _index(observations, Observation, "sample_id", run.run_id)
    truth = _index(truths, GroundTruth, "sample_id", run.run_id)
    pred = _index(predictions, Prediction, "sample_id", run.run_id)
    origins = _index(provenance, TrafficProvenance, "provenance_id", run.run_id)
    attacks = _index(events, AttackEvent, "event_id", run.run_id)
    sources = {source.source_id for source in run.sources}
    if not set(truth).issubset(obs) or not set(pred).issubset(obs):
        raise ContractError("truth/prediction references an absent observation")
    for observation in obs.values():
        if observation.unit is not Unit.PACKET:
            raise ContractError("this evaluator supports packet observations only")
        if observation.source_id not in sources:
            raise ContractError("observation references an undeclared source")
        if observation.clock_id != run.clock_id:
            raise ContractError("observation clock mismatch")
        if not run.start_ns <= observation.timestamp_ns < run.end_ns:
            raise ContractError("observation outside run interval")
    for event in attacks.values():
        if event.clock_id != run.clock_id:
            raise ContractError("event clock mismatch")
        if not run.start_ns <= event.start_ns < event.end_ns <= run.end_ns:
            raise ContractError("event outside run interval")
    for origin in origins.values():
        for event_id in origin.attack_event_ids:
            if event_id not in attacks or origin.actor_id not in attacks[event_id].actor_ids:
                raise ContractError("provenance has absent event or invalid event actor")
    for record in truth.values():
        if any(identifier not in origins for identifier in record.provenance_ids):
            raise ContractError("truth references absent provenance")
        if any(identifier not in attacks for identifier in record.attack_event_ids):
            raise ContractError("truth references absent attack event")
        evidence = [origins[identifier] for identifier in record.provenance_ids]
        if record.state is not Label.UNKNOWN:
            if any(origin.state is not record.state for origin in evidence):
                raise ContractError("known truth conflicts with independent provenance")
            memberships = {event_id for origin in evidence for event_id in origin.attack_event_ids}
            if set(record.attack_event_ids) != memberships:
                raise ContractError("truth event membership differs from provenance")
        # Arrival time need not be within an emission event: transit delay is legitimate.
    for record in pred.values():
        observation = obs[record.sample_id]
        if record.unit is not observation.unit or record.clock_id != observation.clock_id:
            raise ContractError("prediction unit or clock mismatch")
        if record.intake_ns < observation.timestamp_ns:
            raise ContractError("prediction intake precedes observation")
        if record.emitted_ns > run.end_ns:
            raise ContractError("prediction emission exceeds run including drain")
        if record.model_sha256 != run.model_sha256:
            raise ContractError("prediction model differs from run manifest")
        if record.threshold != run.decision_threshold:
            raise ContractError("prediction threshold differs from run manifest")
    return obs, truth, pred


def _ratio(numerator, denominator):
    return numerator / denominator if denominator else None


@dataclass(frozen=True)
class Evaluation:
    tn: int
    fp: int
    fn: int
    tp: int
    n_observations: int
    n_known_truth: int
    n_unknown_truth: int
    n_missing_truth: int
    n_predictions: int
    n_missing_predictions: int
    n_evaluated: int
    n_known_without_prediction: int
    precision: float | None
    recall: float | None
    f1: float | None
    fpr: float | None
    fnr: float | None
    evaluation_coverage: float | None
    truth_coverage: float | None
    prediction_coverage: float | None
    known_prediction_coverage: float | None
    schema_version: str = SCHEMA_VERSION

    @property
    def confusion_matrix(self):
        return ((self.tn, self.fp), (self.fn, self.tp))


def evaluate(run, observations, truths, predictions, provenance, events=()) -> Evaluation:
    """Score each observed packet once; unknown/missing truth never becomes benign.

    Missing predictions are coverage failures, not invented classification decisions.
    None means a metric's mathematical denominator is zero.
    """
    obs, truth, pred = _validate(run, observations, truths, predictions, provenance, events)
    tn = fp = fn = tp = 0
    known = {key for key, record in truth.items() if record.state is not Label.UNKNOWN}
    for key in known.intersection(pred):
        positive = truth[key].state is Label.MALICIOUS
        predicted_positive = pred[key].decision is Label.MALICIOUS
        if positive and predicted_positive:
            tp += 1
        elif positive:
            fn += 1
        elif predicted_positive:
            fp += 1
        else:
            tn += 1
    n = len(obs)
    evaluated = tn + fp + fn + tp
    return Evaluation(
        tn=tn, fp=fp, fn=fn, tp=tp, n_observations=n,
        n_known_truth=len(known), n_unknown_truth=len(truth) - len(known),
        n_missing_truth=n - len(truth), n_predictions=len(pred),
        n_missing_predictions=n - len(pred), n_evaluated=evaluated,
        n_known_without_prediction=len(known) - evaluated,
        precision=_ratio(tp, tp + fp), recall=_ratio(tp, tp + fn),
        f1=_ratio(2 * tp, 2 * tp + fp + fn), fpr=_ratio(fp, fp + tn),
        fnr=_ratio(fn, fn + tp), evaluation_coverage=_ratio(evaluated, n),
        truth_coverage=_ratio(len(known), n), prediction_coverage=_ratio(len(pred), n),
        known_prediction_coverage=_ratio(evaluated, len(known)),
    )


@dataclass(frozen=True)
class WindowSummary:
    index: int
    start_ns: int
    end_ns: int
    sample_ids: tuple[str, ...]
    n_benign: int
    n_malicious: int
    n_unknown: int
    n_missing_truth: int
    attack_event_ids: tuple[str, ...]
    state: str
    schema_version: str = SCHEMA_VERSION


def summarize_windows(run, observations, truths, provenance, events=(), *, width_ns):
    """Summarize [start + k*width, start + (k+1)*width), retaining mixed truth.

    Emit empty windows too. The final window is clipped at run.end_ns.
    """
    if type(width_ns) is not int or width_ns <= 0:
        raise ContractError("width_ns must be a positive integer")
    obs, truth, _ = _validate(run, observations, truths, (), provenance, events)
    buckets = {}
    for observation in obs.values():
        index = (observation.timestamp_ns - run.start_ns) // width_ns
        buckets.setdefault(index, []).append(observation.sample_id)
    result = []
    count = (run.end_ns - run.start_ns + width_ns - 1) // width_ns
    for index in range(count):
        ids = tuple(sorted(buckets.get(index, ())))
        labels = [truth[key].state for key in ids if key in truth]
        benign = labels.count(Label.BENIGN)
        malicious = labels.count(Label.MALICIOUS)
        unknown = labels.count(Label.UNKNOWN)
        missing = len(ids) - len(labels)
        if not ids:
            state = "empty"
        elif unknown or missing:
            state = "uncertain"
        elif benign and malicious:
            state = "mixed"
        else:
            state = "benign_only" if benign else "malicious_only"
        memberships = tuple(sorted({
            event_id for key in ids if key in truth for event_id in truth[key].attack_event_ids
        }))
        start = run.start_ns + index * width_ns
        result.append(WindowSummary(
            index, start, min(start + width_ns, run.end_ns), ids,
            benign, malicious, unknown, missing, memberships, state,
        ))
    return tuple(result)
