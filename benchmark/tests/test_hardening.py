"""M0.1 regressions, initially reproducing the three confirmed design gaps."""

import unittest
from dataclasses import replace

from benchmark.contracts import (
    ContractError, ExperimentMetadata, GroundTruth, Label, SourceArtifact, Split,
    TrafficProvenance, to_json, validate_partitions,
)
from benchmark.evaluator import evaluate, evaluate_result, summarize_windows
from benchmark.tests.test_core import digest, evidence, manifest, observation, prediction, truth


class HardeningTests(unittest.TestCase):
    def test_aliases_cannot_double_count_one_occurrence(self):
        run = manifest()
        source = run.sources[0]
        alias = replace(source, source_id="alias-of-capture", alias_of=source.source_id)
        another_alias = replace(alias, source_id="another-alias-of-capture")
        aliased = replace(run, sources=(source, alias, another_alias))
        first = observation(aliased, 0)
        second = replace(first, source_id=alias.source_id)
        third = replace(first, source_id=another_alias.source_id)
        self.assertEqual(first.sample_id, second.sample_id)
        self.assertEqual(first.sample_id, third.sample_id)
        origins, events = evidence(run)
        with self.assertRaises(ContractError):
            evaluate(aliased, (first, second, third),
                     tuple(truth(run, item, Label.BENIGN) for item in (first, second, third)),
                     tuple(prediction(run, item, 0.1) for item in (first, second, third)), origins, events)

    def test_aliases_accept_distinct_occurrences_and_alias_only_import(self):
        run = manifest()
        source = run.sources[0]
        alias = replace(source, source_id="alias", alias_of=source.source_id, uri="fixture://alias")
        run = replace(run, sources=(alias, source))  # Declaration order does not matter.
        first = replace(observation(run, 0), source_id=source.source_id)
        second = observation(run, 1)
        origins, events = evidence(run)
        result = evaluate(run, (first, second),
                          (truth(run, first, Label.BENIGN), truth(run, second, Label.BENIGN)),
                          (prediction(run, first, 0.1), prediction(run, second, 0.1)), origins, events)
        self.assertEqual(result.n_evaluated, 2)
        one = evaluate(run, (second,), (truth(run, second, Label.BENIGN),),
                       (prediction(run, second, 0.1),), origins, events)
        self.assertEqual(one.tn, 1)

    def test_independent_acquisitions_with_identical_content_count_separately(self):
        run = manifest()
        first_source = run.sources[0]
        independent = replace(first_source, source_id="independent-copy", acquisition_id="acq-B",
                              root_acquisition_ids=("acq-B",))
        run = replace(run, sources=(first_source, independent))
        first = observation(run, 0)
        second = observation(replace(run, sources=(independent,)), 0)
        self.assertEqual(first.features, second.features)
        self.assertEqual(first_source.sha256, independent.sha256)
        self.assertNotEqual(first.sample_id, second.sample_id)
        origins, events = evidence(run)
        result = evaluate(run, (first, second),
                          (truth(run, first, Label.BENIGN), truth(run, second, Label.BENIGN)),
                          (prediction(run, first, 0.1), prediction(run, second, 0.1)), origins, events)
        self.assertEqual(result.confusion_matrix, ((2, 0), (0, 0)))

    def test_same_content_independent_acquisitions_can_cross_partitions(self):
        train = manifest("train", Split.TRAIN)
        independent = replace(train.sources[0], acquisition_id="independent-test-acq",
                              root_acquisition_ids=("independent-test-acq",))
        test = manifest("test", Split.TEST, independent)
        validate_partitions((train, test))

    def test_alias_and_derived_acquisition_leakage_across_partitions_fails(self):
        train = manifest("train", Split.TRAIN)
        source = train.sources[0]
        alias = replace(source, source_id="test-alias", alias_of=source.source_id)
        test = replace(manifest("test", Split.TEST, source), sources=(source, alias))
        with self.assertRaises(ContractError):
            validate_partitions((train, test))
        derived = SourceArtifact("derived", "derived-acq", digest("derived bytes"),
                                 "fixture://derived", (source.acquisition_id,))
        with self.assertRaises(ContractError):
            validate_partitions((train, manifest("test", Split.TEST, derived)))

    def test_invalid_alias_targets_content_lineage_and_acquisition_fail(self):
        run = manifest()
        source = run.sources[0]
        alias = replace(source, source_id="alias", alias_of=source.source_id)
        for broken in (
            replace(alias, alias_of="absent"),
            replace(alias, sha256=digest("different bytes")),
            replace(alias, acquisition_id="different-acq"),
            replace(alias, root_acquisition_ids=("different-root",)),
        ):
            with self.subTest(broken=broken):
                with self.assertRaises(ContractError):
                    replace(run, sources=(source, broken))
        with self.assertRaises(ContractError):
            replace(alias, alias_of=alias.source_id)
        chain = replace(alias, source_id="chain", alias_of=alias.source_id)
        with self.assertRaises(ContractError):
            replace(run, sources=(source, alias, chain))
        with self.assertRaises(ContractError):
            replace(run, sources=(source, replace(alias, alias_of=None)))

    def test_observation_cannot_forge_acquisition_for_a_source_alias(self):
        run = manifest()
        other = replace(run.sources[0], acquisition_id="different-acq",
                        root_acquisition_ids=("different-acq",))
        item = observation(replace(run, sources=(other,)), 0)
        with self.assertRaises(ContractError):
            evaluate(run, (item,), (), (), ())

    def test_acquisition_definition_cannot_change_between_runs(self):
        first = manifest("first", Split.TRAIN)
        inconsistent = replace(first.sources[0], sha256=digest("different acquisition bytes"))
        with self.assertRaises(ContractError):
            validate_partitions((first, manifest("second", Split.TRAIN, inconsistent)))

    def test_unknown_cannot_claim_unrelated_confirmed_event(self):
        run = manifest()
        item = observation(run, 0)
        origins, events = evidence(run)
        with self.assertRaises(ContractError):
            label = GroundTruth(run.run_id, item.sample_id, Label.UNKNOWN,
                                ("benign-origin",), confirmed_event_ids=("event-2",),
                                ambiguity_reason="ambiguous")
            summarize_windows(run, (item,), (label,), origins, events, width_ns=100)

    def test_evaluation_envelope_retains_run_identity(self):
        results = []
        for run_id in ("run-A", "run-B"):
            run = manifest(run_id)
            experiment = ExperimentMetadata("experiment-1", "M0.1-v01", "independent runs", (run,))
            item = observation(run, 0)
            origins, events = evidence(run)
            results.append(evaluate_result(experiment, run_id, (item,),
                (truth(run, item, Label.BENIGN),), (prediction(run, item, 0.1),), origins, events))
        self.assertEqual(results[0].results, results[1].results)
        self.assertNotEqual(results[0].run_id, results[1].run_id)
        self.assertNotEqual(to_json(results[0]), to_json(results[1]))

    def test_unknown_candidates_remain_uncertain_in_window_summary(self):
        run = manifest()
        item = observation(run, 0)
        origins, events = evidence(run)
        label = truth(run, item, Label.UNKNOWN)
        window = summarize_windows(run, (item,), (label,), origins, events, width_ns=100)[0]
        self.assertEqual(label.ambiguity_reason, "two unresolved provenance candidates")
        self.assertEqual(window.confirmed_event_ids, ())
        self.assertEqual(window.candidate_event_ids, ("event-1",))
        self.assertEqual((window.state, window.n_unknown, window.n_malicious), ("uncertain", 1, 0))
        result = evaluate(run, (item,), (label,), (prediction(run, item, 0.9),), origins, events)
        self.assertEqual(result.n_evaluated, 0)

    def test_unknown_candidate_provenance_is_valid_without_confirmed_events(self):
        run = manifest()
        item = observation(run, 0)
        origins, events = evidence(run)
        uncertain = TrafficProvenance(run.run_id, "uncertain-origin", "attack-actor", Label.UNKNOWN,
                                      ("unresolved-generator-log",), candidate_event_ids=("event-2",))
        label = GroundTruth(run.run_id, item.sample_id, Label.UNKNOWN, (uncertain.provenance_id,),
                            candidate_event_ids=("event-2",), ambiguity_reason="unresolved origin")
        window = summarize_windows(run, (item,), (label,), (uncertain,), events, width_ns=100)[0]
        self.assertEqual(window.candidate_event_ids, ("event-2",))
        self.assertEqual(window.confirmed_event_ids, ())

    def test_unknown_unrelated_missing_or_omitted_candidates_fail(self):
        run = manifest()
        item = observation(run, 0)
        origins, events = evidence(run)
        label = truth(run, item, Label.UNKNOWN)
        for candidates in (("event-2",), ("absent",), ()):
            with self.subTest(candidates=candidates):
                with self.assertRaises(ContractError):
                    evaluate(run, (item,), (replace(label, candidate_event_ids=candidates),),
                             (), origins, events)

    def test_candidate_event_actors_validated_even_on_unused_provenance(self):
        run = manifest()
        origins, events = evidence(run)
        uncertain = TrafficProvenance(run.run_id, "uncertain-origin", "attack-actor", Label.UNKNOWN,
                                      ("independent-evidence",), candidate_event_ids=("event-1",))
        for broken in (replace(uncertain, actor_id="benign-actor"),
                       replace(uncertain, candidate_event_ids=("absent",))):
            with self.assertRaises(ContractError):
                evaluate(run, (), (), (), (*origins, broken), events)

    def test_confirmed_and_candidate_memberships_are_disjoint_per_record(self):
        run = manifest()
        item = observation(run, 0)
        origins, _ = evidence(run)
        with self.assertRaises(ContractError):
            replace(origins[1], candidate_event_ids=("event-1",))
        with self.assertRaises(ContractError):
            replace(truth(run, item, Label.MALICIOUS), candidate_event_ids=("event-1",))
        with self.assertRaises(ContractError):
            replace(origins[1], state=Label.UNKNOWN)

    def test_window_can_confirm_and_candidate_same_event_from_different_packets(self):
        run = manifest()
        items = (observation(run, 0), observation(run, 1))
        labels = (truth(run, items[0], Label.MALICIOUS), truth(run, items[1], Label.UNKNOWN))
        origins, events = evidence(run)
        window = summarize_windows(run, items, labels, origins, events, width_ns=100)[0]
        self.assertEqual(window.confirmed_event_ids, ("event-1",))
        self.assertEqual(window.candidate_event_ids, ("event-1",))
        self.assertEqual((window.n_malicious, window.n_unknown), (1, 1))

    def test_counts_windows_and_hashes_are_invariant_to_record_order(self):
        run = manifest()
        experiment = ExperimentMetadata(run.experiment_id, "M0.1-v01", "independent runs", (run,))
        items = tuple(observation(run, i, timestamp=20 + i * 10) for i in range(4))
        labels = tuple(truth(run, item, state) for item, state in zip(
            items, (Label.BENIGN, Label.MALICIOUS, Label.UNKNOWN, Label.BENIGN)))
        predictions = tuple(prediction(run, item, score) for item, score in zip(items, (0.1, 0.9, 0.9, 0.9)))
        origins, events = evidence(run)
        inputs = (items, labels, predictions, origins, events)
        reversed_inputs = tuple(tuple(reversed(records)) for records in inputs)
        expected = evaluate(run, *inputs)
        self.assertEqual(expected, evaluate(run, *reversed_inputs))
        window_inputs = (items, labels, origins, events)
        reversed_windows = tuple(tuple(reversed(records)) for records in window_inputs)
        self.assertEqual(summarize_windows(run, *window_inputs, width_ns=100),
                         summarize_windows(run, *reversed_windows, width_ns=100))
        envelope = evaluate_result(experiment, run.run_id, *inputs)
        self.assertEqual(envelope, evaluate_result(experiment, run.run_id, *reversed_inputs))
        # One-shot generators are snapshotted, not consumed by hashing before evaluation.
        self.assertEqual(envelope, evaluate_result(experiment, run.run_id,
                         *(iter(records) for records in inputs)))

    def test_envelope_records_and_validates_metadata_and_input_hashes(self):
        run = manifest()
        experiment = ExperimentMetadata(run.experiment_id, "M0.1-v01", "independent runs", (run,))
        item = observation(run, 0)
        label = truth(run, item, Label.BENIGN)
        pred = prediction(run, item, 0.1)
        origins, events = evidence(run)
        result = evaluate_result(experiment, run.run_id, (item,), (label,), (pred,), origins, events)
        self.assertEqual(result.protocol_version, "M0.1-v01")
        self.assertEqual(result.ids_id, run.ids["implementation"])
        self.assertEqual(result.model_sha256, run.model_sha256)
        self.assertEqual(dict(result.threshold_configuration),
                         {"threshold": 0.5, "comparison": ">=", "positive_class": "malicious"})
        self.assertEqual(result.input_artifact_hashes["run"], digest(to_json(run)))
        self.assertEqual(result.input_artifact_hashes[f"source:{run.sources[0].source_id}"],
                         run.sources[0].sha256)
        changed = replace(item, features={"DstPort": 9})
        alternate = evaluate_result(experiment, run.run_id, (changed,), (label,), (pred,), origins, events)
        self.assertEqual(result.results, alternate.results)
        self.assertNotEqual(result.input_artifact_hashes["observations"],
                            alternate.input_artifact_hashes["observations"])
        with self.assertRaises(TypeError):
            result.input_artifact_hashes["run"] = digest("tampered")
        for changes in ({"schema_version": "0.1"}, {"input_artifact_hashes": {}},
                        {"threshold_configuration": {"threshold": 0.5}},
                        {"input_artifact_hashes": {**result.input_artifact_hashes, "run": "bad"}}):
            with self.assertRaises(ContractError):
                replace(result, **changes)
        with self.assertRaises(ContractError):
            evaluate_result(experiment, "absent-run", (), (), (), ())

    def test_nonzero_window_origin_preserves_time_reference(self):
        run = replace(manifest(), start_ns=100, end_ns=350)
        origins, events = evidence(run)
        events = tuple(replace(event, start_ns=event.start_ns + 100,
                               end_ns=event.end_ns + 100) for event in events)
        items = tuple(observation(run, i, timestamp=t) for i, t in enumerate((100, 199, 200, 349)))
        labels = tuple(truth(run, item, Label.BENIGN) for item in items)
        windows = summarize_windows(run, items, labels, origins, events, width_ns=100)
        self.assertEqual(tuple(len(window.sample_ids) for window in windows), (2, 1, 1))
        for window in windows:
            self.assertEqual(window.run_id, run.run_id)
            self.assertEqual(window.clock_id, run.clock_id)
            self.assertEqual(window.origin_ns, 100)


if __name__ == "__main__":
    unittest.main(verbosity=2)
