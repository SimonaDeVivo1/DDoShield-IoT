"""Explicit fixture oracles for contracts, provenance, windows, and metrics."""

import hashlib
import json
import unittest
from dataclasses import replace

from benchmark.contracts import (
    AttackEvent, ContractError, ExperimentMetadata, GroundTruth, Label, Observation, Prediction,
    RunMetadata, SourceArtifact, Split, TrafficProvenance, Unit,
    stable_sample_id, to_json, validate_partitions,
)
from benchmark.evaluator import evaluate, summarize_windows


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


MODEL = digest("fixture model; no model is loaded")


def manifest(run_id="run-1", split=Split.TEST, source=None):
    source = source or SourceArtifact(
        f"capture-{run_id}", f"acquisition-{run_id}", digest(run_id),
        f"fixture://{run_id}", (f"acquisition-{run_id}",),
    )
    return RunMetadata(
        experiment_id="experiment-1", run_id=run_id, scenario_id="fixture-scenario",
        random_seed=42, split=split, start_ns=0, end_ns=1000,
        clock_id="fixture-clock", sources=(source,), model_sha256=MODEL, decision_threshold=0.5,
        network={"type": "synthetic; no network"}, traffic={"fixture_version": "1"},
        attack_scenario={"planned": ["event-1", "event-2"]},
        ids={"implementation": "fixture scores"},
        software={"dependencies": "Python standard library"},
        hardware={"mode": "unit test; unmeasured"},
    )


def observation(run, ordinal, timestamp=10, port=80, unit=Unit.PACKET):
    source = run.sources[0]
    return Observation(
        run.run_id, source.source_id, source.acquisition_id, ordinal,
        stable_sample_id(run.run_id, source.acquisition_id, ordinal, unit),
        timestamp, run.clock_id, unit, {"DstPort": port, "PacketSize": 64},
    )


def prediction(run, obs, score):
    return Prediction(
        run.run_id, obs.sample_id, obs.unit, score, 0.5,
        obs.timestamp_ns, obs.timestamp_ns + 1, obs.timestamp_ns + 2,
        run.clock_id, MODEL,
    )


def evidence(run):
    events = (
        AttackEvent(run.run_id, "event-1", ("attack-actor",), "fixture-A", 10, 40,
                    run.clock_id, ("independent-execution-1",)),
        AttackEvent(run.run_id, "event-2", ("attack-actor",), "fixture-B", 20, 50,
                    run.clock_id, ("independent-execution-2",)),
    )
    origins = (
        TrafficProvenance(run.run_id, "benign-origin", "benign-actor", Label.BENIGN,
                          ("benign-generator-log",)),
        TrafficProvenance(run.run_id, "attack-origin", "attack-actor", Label.MALICIOUS,
                          ("attack-generator-log",), ("event-1",)),
        TrafficProvenance(run.run_id, "overlap-origin", "attack-actor", Label.MALICIOUS,
                          ("independent-overlap-attribution",), ("event-1", "event-2")),
    )
    return origins, events


def truth(run, obs, state, overlap=False):
    if state is Label.UNKNOWN:
        return GroundTruth(run.run_id, obs.sample_id, state,
                           ("benign-origin", "attack-origin"),
                           candidate_event_ids=("event-1",),
                           ambiguity_reason="two unresolved provenance candidates")
    if state is Label.BENIGN:
        return GroundTruth(run.run_id, obs.sample_id, state, ("benign-origin",))
    return GroundTruth(
        run.run_id, obs.sample_id, state,
        ("overlap-origin" if overlap else "attack-origin",),
        ("event-1", "event-2") if overlap else ("event-1",),
    )


class EvaluationTests(unittest.TestCase):
    def setUp(self):
        self.run = manifest()
        self.origins, self.events = evidence(self.run)

    def evaluate(self, obs, truths, predictions):
        return evaluate(self.run, obs, truths, predictions, self.origins, self.events)

    def test_benign_port_9_and_malicious_service_port(self):
        benign = observation(self.run, 0, port=9)
        malicious = observation(self.run, 1, port=80)
        labels = (truth(self.run, benign, Label.BENIGN),
                  truth(self.run, malicious, Label.MALICIOUS))
        result = self.evaluate((benign, malicious), labels,
                               (prediction(self.run, benign, 0.1),
                                prediction(self.run, malicious, 0.9)))
        self.assertEqual(result.confusion_matrix, ((1, 0), (0, 1)))
        # Change ports only: neither independently assigned truth nor metrics change.
        changed = (replace(benign, features={"DstPort": 80}),
                   replace(malicious, features={"DstPort": 9}))
        self.assertEqual(result, self.evaluate(changed, labels,
                         (prediction(self.run, benign, 0.1),
                          prediction(self.run, malicious, 0.9))))

    def test_explicit_metric_and_coverage_oracle(self):
        # Independently specified states and predictions, not inferred from packet fields.
        rows = (
            (Label.BENIGN, 9, 0.1), (Label.MALICIOUS, 80, 0.9),
            (Label.BENIGN, 80, 0.9), (Label.MALICIOUS, 9, 0.1),
            (Label.BENIGN, 9, 0.1), (Label.MALICIOUS, 80, 0.9),
            (Label.UNKNOWN, 9, 0.9), (None, 80, 0.9),
            (Label.BENIGN, 80, None),
        )
        obs, labels, predictions = [], [], []
        for i, (state, port, score) in enumerate(rows):
            item = observation(self.run, i, timestamp=10 + i * 10, port=port)
            obs.append(item)
            if state is not None:
                labels.append(truth(self.run, item, state))
            if score is not None:
                predictions.append(prediction(self.run, item, score))
        result = self.evaluate(obs, labels, predictions)
        self.assertEqual(result.confusion_matrix, ((2, 1), (1, 2)))
        for metric in (result.precision, result.recall, result.f1):
            self.assertAlmostEqual(metric, 2 / 3)
        self.assertAlmostEqual(result.fpr, 1 / 3)
        self.assertAlmostEqual(result.fnr, 1 / 3)
        self.assertEqual((result.n_observations, result.n_known_truth,
                          result.n_unknown_truth, result.n_missing_truth), (9, 7, 1, 1))
        self.assertEqual((result.n_predictions, result.n_missing_predictions,
                          result.n_evaluated, result.n_known_without_prediction), (8, 1, 6, 1))
        self.assertAlmostEqual(result.evaluation_coverage, 6 / 9)
        self.assertAlmostEqual(result.truth_coverage, 7 / 9)
        self.assertAlmostEqual(result.prediction_coverage, 8 / 9)
        self.assertAlmostEqual(result.known_prediction_coverage, 6 / 7)

    def test_ambiguous_provenance_is_excluded(self):
        item = observation(self.run, 0)
        label = truth(self.run, item, Label.UNKNOWN)
        result = self.evaluate((item,), (label,), (prediction(self.run, item, 0.9),))
        self.assertEqual(result.confusion_matrix, ((0, 0), (0, 0)))
        self.assertEqual(result.n_unknown_truth, 1)
        self.assertEqual(result.evaluation_coverage, 0)
        self.assertIsNone(result.fpr)
        with self.assertRaises(ContractError):
            self.evaluate((item,), (replace(label, state=Label.MALICIOUS,
                ambiguity_reason=None, confirmed_event_ids=("event-1",)),), ())

    def test_overlapping_events_count_packet_once(self):
        item = observation(self.run, 0, timestamp=25)
        label = truth(self.run, item, Label.MALICIOUS, overlap=True)
        result = self.evaluate((item,), (label,), (prediction(self.run, item, 0.9),))
        self.assertEqual(result.tp, 1)
        self.assertEqual(result.n_evaluated, 1)
        window = summarize_windows(self.run, (item,), (label,), self.origins,
                                   self.events, width_ns=100)[0]
        self.assertEqual(window.n_malicious, 1)
        self.assertEqual(window.confirmed_event_ids, ("event-1", "event-2"))

    def test_mixed_packet_window_retains_both_labels(self):
        items = (observation(self.run, 0, timestamp=20, port=80),
                 observation(self.run, 1, timestamp=30, port=80))
        labels = (truth(self.run, items[0], Label.BENIGN),
                  truth(self.run, items[1], Label.MALICIOUS))
        windows = summarize_windows(self.run, items, labels, self.origins,
                                    self.events, width_ns=100)
        self.assertEqual(windows[0].state, "mixed")
        self.assertEqual((windows[0].n_benign, windows[0].n_malicious), (1, 1))
        self.assertEqual(windows[1].state, "empty")
        result = self.evaluate(items, labels, (prediction(self.run, items[0], 0.1),
                                               prediction(self.run, items[1], 0.9)))
        self.assertEqual(result.confusion_matrix, ((1, 0), (0, 1)))

    def test_exact_window_boundaries_and_final_partial_window(self):
        run = replace(self.run, end_ns=250)
        items = tuple(observation(run, i, timestamp=t) for i, t in enumerate((0, 99, 100, 200, 249)))
        labels = tuple(truth(run, item, Label.BENIGN) for item in items)
        windows = summarize_windows(run, items, labels, self.origins,
                                    self.events, width_ns=100)
        self.assertEqual(tuple(len(w.sample_ids) for w in windows), (2, 1, 2))
        self.assertEqual(tuple((w.start_ns, w.end_ns) for w in windows),
                         ((0, 100), (100, 200), (200, 250)))
        self.assertEqual(len({key for w in windows for key in w.sample_ids}), 5)
        outside = observation(run, 99, timestamp=250)
        with self.assertRaises(ContractError):
            evaluate(run, (outside,), (), (), self.origins, self.events)

    def test_uncertain_window_reports_unknown_and_missing_truth(self):
        items = (observation(self.run, 0), observation(self.run, 1))
        windows = summarize_windows(self.run, items, (truth(self.run, items[0], Label.UNKNOWN),),
                                    self.origins, self.events, width_ns=100)
        self.assertEqual(windows[0].state, "uncertain")
        self.assertEqual((windows[0].n_unknown, windows[0].n_missing_truth), (1, 1))

    def test_undefined_metrics_and_mathematically_defined_zero_f1(self):
        benign = observation(self.run, 0)
        result = self.evaluate((benign,), (truth(self.run, benign, Label.BENIGN),),
                               (prediction(self.run, benign, 0.1),))
        self.assertIsNone(result.precision)
        self.assertIsNone(result.recall)
        self.assertIsNone(result.f1)
        self.assertIsNone(result.fnr)
        self.assertEqual(result.fpr, 0)
        malicious = observation(self.run, 1)
        missed = self.evaluate((malicious,), (truth(self.run, malicious, Label.MALICIOUS),),
                               (prediction(self.run, malicious, 0.1),))
        self.assertIsNone(missed.precision)
        self.assertEqual(missed.recall, 0)
        self.assertEqual(missed.f1, 0)  # 2TP/(2TP+FP+FN) has nonzero denominator
        self.assertEqual(missed.fnr, 1)
        self.assertIsNone(missed.fpr)

    def test_empty_input_has_undefined_coverage(self):
        result = self.evaluate((), (), ())
        for name in ("precision", "recall", "f1", "fpr", "fnr", "evaluation_coverage",
                     "truth_coverage", "prediction_coverage", "known_prediction_coverage"):
            self.assertIsNone(getattr(result, name))
        self.assertEqual(result.n_evaluated, 0)
        self.assertIsNone(json.loads(to_json(result))["precision"])

    def test_missing_prediction_is_coverage_failure_not_invented_fn(self):
        item = observation(self.run, 0)
        result = self.evaluate((item,), (truth(self.run, item, Label.MALICIOUS),), ())
        self.assertEqual((result.fn, result.n_known_without_prediction), (0, 1))
        self.assertEqual(result.evaluation_coverage, 0)
        self.assertIsNone(result.recall)

    def test_duplicate_or_foreign_records_fail(self):
        item = observation(self.run, 0)
        label = truth(self.run, item, Label.BENIGN)
        pred = prediction(self.run, item, 0.1)
        for obs, labels, predictions in (
            ((item, item), (label,), (pred,)),
            ((item,), (label, label), (pred,)),
            ((item,), (label,), (pred, pred)),
            ((), (label,), ()),
            ((), (), (pred,)),
            ((item,), (replace(label, run_id="foreign"),), ()),
        ):
            with self.subTest(records=(obs, labels, predictions)):
                with self.assertRaises(ContractError):
                    self.evaluate(obs, labels, predictions)

    def test_rejects_absent_provenance_event_and_wrong_actor(self):
        item = observation(self.run, 0)
        label = truth(self.run, item, Label.MALICIOUS)
        for broken in (replace(label, provenance_ids=("absent",)),
                       replace(label, confirmed_event_ids=("absent",)),
                       replace(label, confirmed_event_ids=("event-2",))):
            with self.assertRaises(ContractError):
                self.evaluate((item,), (broken,), ())
        origins = (replace(self.origins[1], actor_id="unrelated-actor"),)
        with self.assertRaises(ContractError):
            evaluate(self.run, (item,), (label,), (), origins, self.events)

    def test_rejects_clock_unit_timing_and_model_mismatch(self):
        item = observation(self.run, 0)
        pred = prediction(self.run, item, 0.1)
        for broken in (replace(pred, clock_id="another-clock"),
                       replace(pred, unit=Unit.FLOW),
                       replace(pred, intake_ns=9),
                       replace(pred, emitted_ns=1001),
                       replace(pred, threshold=0.7),
                       replace(pred, model_sha256=digest("different-model"))):
            with self.assertRaises(ContractError):
                self.evaluate((item,), (), (broken,))
        flow = observation(self.run, 1, unit=Unit.FLOW)
        with self.assertRaises(ContractError):
            self.evaluate((flow,), (), ())

    def test_threshold_boundary_is_positive(self):
        item = observation(self.run, 0)
        self.assertEqual(prediction(self.run, item, 0.5).decision, Label.MALICIOUS)


class ContractTests(unittest.TestCase):
    def test_experiment_validates_run_membership_and_partitions(self):
        runs = (manifest("train-run", Split.TRAIN), manifest("test-run", Split.TEST))
        experiment = ExperimentMetadata("experiment-1", "M0-v01", "independent runs", runs)
        self.assertEqual(len(experiment.runs), 2)
        with self.assertRaises(ContractError):
            replace(experiment, experiment_id="different-experiment")
        with self.assertRaises(ContractError):
            replace(experiment, runs=())
        with self.assertRaises(ContractError):
            replace(experiment, runs=(runs[0], manifest("test-run", Split.TEST, runs[0].sources[0])))

    def test_independent_partitions_pass(self):
        runs = (manifest("train-run", Split.TRAIN),
                manifest("validation-run", Split.VALIDATION),
                manifest("test-run", Split.TEST))
        validate_partitions(runs)

    def test_shared_acquisition_or_ancestor_fails(self):
        train = manifest("train-run", Split.TRAIN)
        original = train.sources[0]
        reused_acquisition = replace(original, source_id="renamed-source", uri="fixture://copy")
        derived = SourceArtifact("derived-source", "derived-acquisition", digest("derived"),
                                 "fixture://derived", original.root_acquisition_ids)
        for source in (reused_acquisition, derived):
            with self.subTest(source=source.source_id):
                with self.assertRaises(ContractError):
                    validate_partitions((train, manifest("test-run", Split.TEST, source)))
        with self.assertRaises(ContractError):
            validate_partitions((train, replace(train, split=Split.TEST)))

    def test_same_partition_replay_is_allowed(self):
        first = manifest("run-A", Split.TRAIN)
        validate_partitions((first, manifest("run-B", Split.TRAIN, first.sources[0])))

    def test_stable_identity_distinguishes_identical_packet_occurrences(self):
        run = manifest()
        first, second = observation(run, 0), observation(run, 1)
        self.assertEqual(first.features, second.features)
        self.assertNotEqual(first.sample_id, second.sample_id)
        self.assertEqual(first.sample_id, observation(run, 0, port=9).sample_id)
        self.assertEqual(first.sample_id, observation(run, 0).sample_id)
        with self.assertRaises(ContractError):
            replace(first, sample_id="arbitrary-id")

    def test_versions_types_intervals_and_hashes_are_validated(self):
        run = manifest()
        for changes in ({"schema_version": "9"}, {"random_seed": True},
                        {"end_ns": 0}, {"split": "test"}, {"sources": ()},
                        {"model_sha256": "bad"}, {"network": {}},
                        {"software": {"bad": float("nan")}}, {"decision_threshold": True}):
            with self.subTest(changes=changes):
                with self.assertRaises(ContractError):
                    replace(run, **changes)
        item = observation(run, 0)
        pred = prediction(run, item, 0.1)
        for changes in ({"score": float("nan")}, {"score": True}, {"score": 1.1},
                        {"threshold": -0.1}, {"features_ready_ns": 9},
                        {"emitted_ns": -1}):
            with self.assertRaises(ContractError):
                replace(pred, **changes)
        with self.assertRaises(ContractError):
            GroundTruth(run.run_id, item.sample_id, Label.UNKNOWN, ())
        with self.assertRaises(ContractError):
            GroundTruth(run.run_id, item.sample_id, Label.BENIGN, ())

    def test_features_and_settings_are_separate_immutable_snapshots(self):
        run = manifest()
        settings = {"nested": {"items": [1, 2]}}
        frozen = replace(run, network=settings)
        settings["nested"]["items"].append(3)
        self.assertEqual(frozen.network["nested"]["items"], (1, 2))
        with self.assertRaises(TypeError):
            frozen.network["nested"]["new"] = 3
        item = observation(run, 0)
        for name in ("Label", "ground_truth", "attack_event_ids", "confirmed_event_ids",
                     "candidate_event_ids", "provenance_ids", "split"):
            with self.assertRaises(ContractError):
                replace(item, features={name: "not observable"})
        self.assertNotIn("Label", json.loads(to_json(item))["features"])

    def test_json_export_is_deterministic(self):
        run = manifest()
        self.assertEqual(to_json(run), to_json(manifest()))
        self.assertEqual(json.loads(to_json(run))["split"], "test")

    def test_invalid_window_width_fails(self):
        run = manifest()
        for width in (0, -1, True, 1.5):
            with self.assertRaises(ContractError):
                summarize_windows(run, (), (), (), width_ns=width)


if __name__ == "__main__":
    unittest.main(verbosity=2)
