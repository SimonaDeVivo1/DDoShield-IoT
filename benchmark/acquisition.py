"""Offline reconciliation of declared benign-probe evidence; no capture backend.

Tokens and payload digests associate evidence. Approval and attributable origin
observations establish scoped provenance; neither a token nor a send call is truth.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass, replace
from enum import Enum

from . import SCHEMA_VERSION
from .contracts import (
    ContractError, ExperimentMetadata, GroundTruth, Label, Observation, SourceArtifact,
    TrafficProvenance, Unit, _enum, _integer, _sha, _strings, _text, _version, to_json,
)
from .evaluator import evaluate


class Point(str, Enum):
    ORIGIN = "origin"
    TARGET = "target"
    SENSOR = "sensor"


class Status(str, Enum):
    MATCHED = "matched"
    UNCONFIRMED = "unconfirmed"
    AMBIGUOUS = "ambiguous"
    DUPLICATE = "duplicate"
    UNMATCHED = "unmatched"
    TIMING_INCOMPATIBLE = "timing_incompatible"


def _record(run_id, evidence_ids, schema_version):
    _version(schema_version)
    _text(run_id, "run_id")
    _strings(evidence_ids, "evidence_ids", required=True)


def _resolution(value):
    _integer(value, "resolution_ns")
    if value == 0:
        raise ContractError("timestamp resolution must be positive")


@dataclass(frozen=True)
class TrafficActor:
    run_id: str
    actor_id: str
    generator_sha256: str
    identity_evidence_ids: tuple[str, ...]
    benign_approval_evidence_ids: tuple[str, ...] = ()
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self):
        _record(self.run_id, self.identity_evidence_ids, self.schema_version)
        _text(self.actor_id, "actor_id")
        _sha(self.generator_sha256)
        _strings(self.benign_approval_evidence_ids, "benign_approval_evidence_ids")


@dataclass(frozen=True)
class Acquisition:
    run_id: str
    source: SourceArtifact
    point: Point
    actor_id: str | None
    clock_id: str
    resolution_ns: int
    evidence_ids: tuple[str, ...]
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self):
        _record(self.run_id, self.evidence_ids, self.schema_version)
        if not isinstance(self.source, SourceArtifact) or self.source.alias_of is not None:
            raise ContractError("acquisition requires a canonical SourceArtifact")
        _enum(self.point, Point, "point")
        _text(self.clock_id, "clock_id")
        _resolution(self.resolution_ns)
        if self.point is Point.ORIGIN:
            _text(self.actor_id, "origin actor_id")
        elif self.actor_id is not None:
            raise ContractError("target/sensor acquisition must not assert generator identity")


@dataclass(frozen=True)
class GeneratorEvidence:
    """A recorded send attempt; confirmation is derived from origin observation."""

    run_id: str
    emission_id: str
    actor_id: str
    token: str
    payload_sha256: str
    attempt_ns: int
    clock_id: str
    resolution_ns: int
    evidence_ids: tuple[str, ...]
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self):
        _record(self.run_id, self.evidence_ids, self.schema_version)
        for name in ("emission_id", "actor_id", "token", "clock_id"):
            _text(getattr(self, name), name)
        _sha(self.payload_sha256)
        _integer(self.attempt_ns, "attempt_ns")
        _resolution(self.resolution_ns)


@dataclass(frozen=True)
class CapturedOccurrence:
    """Existing raw Observation plus correlation evidence outside IDS features."""

    observation: Observation
    token: str | None
    payload_sha256: str
    evidence_ids: tuple[str, ...]
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self):
        _version(self.schema_version)
        if not isinstance(self.observation, Observation) or self.observation.unit is not Unit.PACKET:
            raise ContractError("capture occurrence requires a packet Observation")
        if self.token is not None:
            _text(self.token, "token")
        _sha(self.payload_sha256)
        _strings(self.evidence_ids, "evidence_ids", required=True)


@dataclass(frozen=True)
class ClockMapping:
    """Externally validated, bounded constant-offset mapping directly to run clock."""

    run_id: str
    source_clock_id: str
    target_clock_id: str
    offset_ns: int
    valid_from_ns: int
    valid_until_ns: int
    uncertainty_ns: int
    evidence_ids: tuple[str, ...]
    validated: bool
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self):
        _record(self.run_id, self.evidence_ids, self.schema_version)
        _text(self.source_clock_id, "source_clock_id")
        _text(self.target_clock_id, "target_clock_id")
        if type(self.offset_ns) is not int or type(self.validated) is not bool:
            raise ContractError("offset must be an integer and validated must be boolean")
        for name in ("valid_from_ns", "valid_until_ns", "uncertainty_ns"):
            _integer(getattr(self, name), name)
        if self.valid_until_ns <= self.valid_from_ns or self.source_clock_id == self.target_clock_id:
            raise ContractError("clock mapping requires different clocks and a nonempty interval")


@dataclass(frozen=True)
class MatchOutcome:
    sample_id: str
    point: Point
    status: Status
    candidate_emission_ids: tuple[str, ...]
    reason: str
    evidence_ids: tuple[str, ...]
    schema_version: str = SCHEMA_VERSION


@dataclass(frozen=True)
class EmissionOutcome:
    emission_id: str
    actor_id: str
    status: Status
    origin_sample_ids: tuple[str, ...]
    target_sample_ids: tuple[str, ...]
    sensor_sample_ids: tuple[str, ...]
    missing_points: tuple[Point, ...]
    duplicate_acquisition_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    schema_version: str = SCHEMA_VERSION

    @property
    def confirmed(self):
        return self.status is Status.MATCHED


@dataclass(frozen=True)
class Reconciliation:
    experiment: ExperimentMetadata
    run_id: str
    actors: tuple[TrafficActor, ...]
    acquisitions: tuple[Acquisition, ...]
    generator_evidence: tuple[GeneratorEvidence, ...]
    occurrences: tuple[CapturedOccurrence, ...]
    clock_mappings: tuple[ClockMapping, ...]
    observations: tuple[Observation, ...]
    truths: tuple[GroundTruth, ...]
    provenance: tuple[TrafficProvenance, ...]
    matches: tuple[MatchOutcome, ...]
    emissions: tuple[EmissionOutcome, ...]
    schema_version: str = SCHEMA_VERSION

    @property
    def experiment_id(self):
        return self.experiment.experiment_id

    @property
    def protocol_version(self):
        return self.experiment.protocol_version

    @property
    def sensor_observations(self):
        ids = {item.source.acquisition_id for item in self.acquisitions if item.point is Point.SENSOR}
        return tuple(item for item in self.observations if item.acquisition_id in ids)

    @property
    def sensor_truths(self):
        ids = {item.sample_id for item in self.sensor_observations}
        return tuple(item for item in self.truths if item.sample_id in ids)


def _proof(*groups):
    return tuple(sorted({item for group in groups for item in group}))


def _index(records, record_type, key, run_id):
    indexed = {}
    for record in records:
        if not isinstance(record, record_type) or record.run_id != run_id:
            raise ContractError(f"expected {record_type.__name__} from the selected run")
        value = key(record)
        if value in indexed:
            raise ContractError(f"duplicate {record_type.__name__} identity: {value}")
        indexed[value] = record
    return indexed


def _temporal_order(before, after):
    # (mapped center, conservative uncertainty); ties with zero uncertainty are allowed.
    if after[0] - after[1] >= before[0] + before[1]:
        return Status.MATCHED
    if after[0] + after[1] < before[0] - before[1]:
        return Status.TIMING_INCOMPATIBLE
    return Status.AMBIGUOUS


def reconcile(experiment, run_id, actors, acquisitions, emissions, occurrences, clock_mappings=()):
    """Match declared probe evidence conservatively, without performing any I/O."""
    if not isinstance(experiment, ExperimentMetadata):
        raise ContractError("expected ExperimentMetadata")
    run = next((item for item in experiment.runs if item.run_id == run_id), None)
    if run is None:
        raise ContractError("run absent from experiment")
    actors = _index(actors, TrafficActor, lambda item: item.actor_id, run_id)
    acquisitions = _index(acquisitions, Acquisition, lambda item: item.source.acquisition_id, run_id)
    emissions = _index(emissions, GeneratorEvidence, lambda item: item.emission_id, run_id)
    mappings = _index(clock_mappings, ClockMapping, lambda item: item.source_clock_id, run_id)
    sources = {item.source_id: item for item in run.sources}
    for acquisition in acquisitions.values():
        if sources.get(acquisition.source.source_id) != acquisition.source:
            raise ContractError("acquisition source differs from run manifest")
        if acquisition.point is Point.ORIGIN and acquisition.actor_id not in actors:
            raise ContractError("origin acquisition references absent actor")
    for mapping in mappings.values():
        if not mapping.validated or mapping.target_clock_id != run.clock_id:
            raise ContractError("mapping must be validated and directly target the run clock")
    for acquisition in acquisitions.values():
        if acquisition.clock_id != run.clock_id and acquisition.clock_id not in mappings:
            raise ContractError("acquisition clock domain lacks a validated mapping, including empty captures")

    def time(timestamp, clock_id, resolution):
        error = resolution - 1
        proof = ()
        if clock_id != run.clock_id:
            mapping = mappings.get(clock_id)
            if mapping is None:
                raise ContractError("incompatible clock domain without validated mapping")
            if not (mapping.valid_from_ns <= timestamp - error
                    and timestamp + error < mapping.valid_until_ns):
                raise ContractError("timestamp outside clock mapping validity")
            timestamp += mapping.offset_ns
            error += mapping.uncertainty_ns
            proof = mapping.evidence_ids
        if not run.start_ns <= timestamp < run.end_ns:
            raise ContractError("normalized timestamp outside run interval")
        return (timestamp, error), proof

    captured = {}
    normalized = {}
    capture_times, capture_proofs = {}, {}
    buckets = defaultdict(list)
    by_key = defaultdict(list)
    attempt_times, attempt_proofs = {}, {}
    for emission in emissions.values():
        if emission.actor_id not in actors:
            raise ContractError("generator evidence references absent actor")
        attempt_times[emission.emission_id], attempt_proofs[emission.emission_id] = time(
            emission.attempt_ns, emission.clock_id, emission.resolution_ns)
        by_key[(emission.token, emission.payload_sha256)].append(emission.emission_id)
    for occurrence in occurrences:
        if not isinstance(occurrence, CapturedOccurrence):
            raise ContractError("expected CapturedOccurrence")
        observation = occurrence.observation
        if observation.run_id != run_id or observation.sample_id in captured:
            raise ContractError("foreign run or duplicate captured occurrence, including source aliases")
        source = sources.get(observation.source_id)
        acquisition = acquisitions.get(observation.acquisition_id)
        if (source is None or source.acquisition_id != observation.acquisition_id or acquisition is None
                or observation.clock_id != acquisition.clock_id):
            raise ContractError("captured occurrence has inconsistent source/acquisition/clock identity")
        stamp, proof = time(observation.timestamp_ns, observation.clock_id, acquisition.resolution_ns)
        captured[observation.sample_id] = occurrence
        normalized[observation.sample_id] = replace(observation, timestamp_ns=stamp[0], clock_id=run.clock_id)
        capture_times[observation.sample_id], capture_proofs[observation.sample_id] = stamp, proof
        buckets[(observation.acquisition_id, occurrence.token, occurrence.payload_sha256)].append(observation.sample_id)

    candidates = {}
    for sample_id, occurrence in captured.items():
        acquisition = acquisitions[occurrence.observation.acquisition_id]
        ids = by_key.get((occurrence.token, occurrence.payload_sha256), ())
        if acquisition.point is Point.ORIGIN:
            ids = [identifier for identifier in ids if emissions[identifier].actor_id == acquisition.actor_id]
        candidates[sample_id] = tuple(sorted(ids))

    def sample_proof(sample_id):
        occurrence = captured[sample_id]
        acquisition = acquisitions[occurrence.observation.acquisition_id]
        return _proof(occurrence.evidence_ids, acquisition.evidence_ids, capture_proofs[sample_id],
                      (f"artifact-sha256:{acquisition.source.sha256}", f"occurrence:{sample_id}"))

    emission_reports, origins_by_emission = {}, {}
    for identifier in sorted(emissions):
        emission = emissions[identifier]
        points = {point: [] for point in Point}
        duplicates = set()
        for sample_id in sorted(captured):
            if identifier not in candidates[sample_id]:
                continue
            occurrence = captured[sample_id]
            acquisition = acquisitions[occurrence.observation.acquisition_id]
            points[acquisition.point].append(sample_id)
            if len(buckets[(occurrence.observation.acquisition_id, occurrence.token, occurrence.payload_sha256)]) > 1:
                duplicates.add(occurrence.observation.acquisition_id)
        origin_ids = points[Point.ORIGIN]
        origins_by_emission[identifier] = tuple(origin_ids)
        if not origin_ids:
            status = Status.UNCONFIRMED
        elif any(len(candidates[sample_id]) != 1 for sample_id in origin_ids):
            status = Status.AMBIGUOUS
        elif any(captured[sample_id].observation.acquisition_id in duplicates for sample_id in origin_ids):
            status = Status.DUPLICATE
        else:
            orders = {_temporal_order(attempt_times[identifier], capture_times[sample_id]) for sample_id in origin_ids}
            status = (Status.TIMING_INCOMPATIBLE if Status.TIMING_INCOMPATIBLE in orders else
                      Status.AMBIGUOUS if Status.AMBIGUOUS in orders else Status.MATCHED)
        actor = actors[emission.actor_id]
        proof = _proof(emission.evidence_ids, actor.identity_evidence_ids, actor.benign_approval_evidence_ids,
                       attempt_proofs[identifier], (f"generator-sha256:{actor.generator_sha256}",),
                       *(sample_proof(sample_id) for ids in points.values() for sample_id in ids))
        emission_reports[identifier] = EmissionOutcome(
            identifier, emission.actor_id, status, tuple(origin_ids), tuple(points[Point.TARGET]),
            tuple(points[Point.SENSOR]), tuple(point for point in Point if not points[point]),
            tuple(sorted(duplicates)), proof)

    provenance = {}
    for identifier, report in emission_reports.items():
        actor = actors[report.actor_id]
        state = Label.BENIGN if report.confirmed and actor.benign_approval_evidence_ids else Label.UNKNOWN
        provenance_id = "emission:" + hashlib.sha256(to_json((run_id, identifier)).encode()).hexdigest()
        provenance[identifier] = TrafficProvenance(run_id, provenance_id, actor.actor_id, state,
                                                 report.evidence_ids)

    matches, truths = [], []
    for sample_id in sorted(captured):
        occurrence = captured[sample_id]
        acquisition = acquisitions[occurrence.observation.acquisition_id]
        ids = candidates[sample_id]
        duplicate = len(buckets[(occurrence.observation.acquisition_id, occurrence.token, occurrence.payload_sha256)]) > 1
        if not ids:
            status, reason = Status.UNMATCHED, "No supported generator correlation evidence; background remains unknown."
        elif duplicate:
            status, reason = Status.DUPLICATE, "Multiple distinct occurrences in one acquisition share correlation evidence."
        elif len(ids) > 1:
            status, reason = Status.AMBIGUOUS, "Multiple generator candidates; no first-match attribution."
        else:
            identifier = ids[0]
            report = emission_reports[identifier]
            status = report.status
            if status is Status.MATCHED and acquisition.point is not Point.ORIGIN:
                orders = {_temporal_order(capture_times[origin], capture_times[sample_id])
                          for origin in origins_by_emission[identifier]}
                status = (Status.TIMING_INCOMPATIBLE if Status.TIMING_INCOMPATIBLE in orders else
                          Status.AMBIGUOUS if Status.AMBIGUOUS in orders else Status.MATCHED)
            reason = {
                Status.MATCHED: "Unique declared generator association with attributable observable origin evidence.",
                Status.UNCONFIRMED: "Send attempt without attributable observable origin emission.",
                Status.DUPLICATE: "Origin evidence contains duplicate occurrences; confirmation remains unresolved.",
                Status.AMBIGUOUS: "Origin attribution or timestamp uncertainty prevents unique causal association.",
                Status.TIMING_INCOMPATIBLE: "Declared chronology is incompatible; no loss stage is inferred.",
            }[status]
        proof = _proof(sample_proof(sample_id), *(emission_reports[identifier].evidence_ids for identifier in ids))
        matches.append(MatchOutcome(sample_id, acquisition.point, status, ids, reason, proof))
        known = status is Status.MATCHED and len(ids) == 1 and provenance[ids[0]].state is Label.BENIGN
        provenance_ids = tuple(provenance[identifier].provenance_id for identifier in ids)
        explanation = reason if not (status is Status.MATCHED and not known) else "Actor lacks independent benign approval evidence."
        truths.append(GroundTruth(run_id, sample_id, Label.BENIGN if known else Label.UNKNOWN,
                                  provenance_ids, ambiguity_reason=None if known else explanation))

    observations = tuple(normalized[key] for key in sorted(normalized))
    origins = tuple(provenance[key] for key in sorted(provenance))
    evaluate(run, observations, truths, (), origins)
    return Reconciliation(
        experiment, run_id, tuple(actors[key] for key in sorted(actors)),
        tuple(acquisitions[key] for key in sorted(acquisitions)),
        tuple(emissions[key] for key in sorted(emissions)), tuple(captured[key] for key in sorted(captured)),
        tuple(mappings[key] for key in sorted(mappings)), observations, tuple(truths), origins,
        tuple(matches), tuple(emission_reports[key] for key in sorted(emission_reports)))
