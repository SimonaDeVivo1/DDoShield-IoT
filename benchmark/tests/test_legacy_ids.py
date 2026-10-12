"""Offline fixtures in verified legacy CSV layouts; no detector or traffic runs."""

import csv
import io
import json
import tarfile
import unittest
from dataclasses import replace
from pathlib import Path

from benchmark.contracts import ContractError, Label, Unit, stable_sample_id, to_json
from benchmark.evaluator import evaluate
from benchmark.legacy_ids import (
    EXTRACTOR_COLUMNS, FEATURE_NAMES, LegacyFormat, ObservationBinding, PredictionBinding,
    import_observations, import_predictions, parse_legacy_csv, read_legacy_csv,
)
from benchmark.tests.test_core import digest, manifest


FIXTURES = Path(__file__).parent / "fixtures"
FEATURE_BYTES = (FIXTURES / "legacy_features.csv").read_bytes()
PREDICTION_BYTES = (FIXTURES / "legacy_predictions.csv").read_bytes()


def rewrite(data, mutate):
    rows = list(csv.reader(io.StringIO(data.decode())))
    mutate(rows)
    output = io.StringIO(newline="")
    csv.writer(output, lineterminator="\n").writerows(rows)
    return output.getvalue().encode()


class LegacyAdapterTests(unittest.TestCase):
    def setUp(self):
        self.table = parse_legacy_csv(FEATURE_BYTES, LegacyFormat.EXTRACTOR_CSV)
        self.prediction_table = parse_legacy_csv(PREDICTION_BYTES, LegacyFormat.OFFLINE_PREDICTION_CSV)
        self.run, self.bindings = self.context(self.table)
        self.imported = import_observations(self.run, self.table, self.run.sources[0].source_id, self.bindings)
        self.prediction_bindings = self.make_prediction_bindings(self.imported, self.prediction_table)

    def context(self, table):
        # Explicitly constructed fixture evidence, not recovered from the legacy CSV.
        run = manifest("legacy-fixture")
        source = replace(run.sources[0], sha256=table.sha256, uri="fixture://legacy-features")
        run = replace(run, sources=(source,))
        bindings = tuple(ObservationBinding(row.row_index, 100 + row.row_index,
                         10 + row.row_index * 10, run.clock_id, table.sha256,
                         (f"fixture-original-occurrence-{row.row_index}",)) for row in table.rows)
        return run, bindings

    def make_prediction_bindings(self, imported, table):
        return tuple(PredictionBinding(i, observation.sample_id, imported.table.sha256,
                     table.sha256, self.run.model_sha256, observation.timestamp_ns,
                     observation.timestamp_ns + 1, observation.timestamp_ns + 2,
                     self.run.clock_id, (f"fixture-prediction-execution-{i}",))
                     for i, observation in enumerate(imported.observations))

    def test_feature_schema_matches_actual_archived_model_metadata(self):
        repo = Path(__file__).resolve().parents[2]
        with tarfile.open(repo / "docker/IDS/.conf", "r:gz") as archive:
            metadata = json.load(archive.extractfile("ids-model-bundle/metadata.json"))
        self.assertEqual(tuple(metadata["feature_names"]), FEATURE_NAMES)
        self.assertEqual(len(FEATURE_NAMES), 38)
        self.assertEqual(EXTRACTOR_COLUMNS[14], "Label")

    def test_reads_actual_supported_csv_layouts(self):
        loaded = read_legacy_csv(FIXTURES / "legacy_features.csv", LegacyFormat.EXTRACTOR_CSV)
        self.assertEqual(loaded.sha256, self.table.sha256)
        self.assertEqual(len(loaded.rows), 2)
        self.assertEqual(tuple(loaded.rows[0].features), FEATURE_NAMES)
        self.assertEqual((self.prediction_table.rows[0].score, self.prediction_table.rows[0].decision), (0.9, 1))

    def test_import_preserves_external_identity_and_unknown_truth(self):
        for observation, truth, annotation, binding in zip(
            self.imported.observations, self.imported.truths, self.imported.annotations, self.bindings
        ):
            self.assertEqual(observation.acquisition_id, self.run.sources[0].acquisition_id)
            self.assertEqual(observation.ordinal, binding.ordinal)
            self.assertEqual(observation.timestamp_ns, binding.timestamp_ns)
            self.assertEqual(observation.unit, Unit.PACKET)
            self.assertEqual(observation.sample_id, stable_sample_id(self.run.run_id,
                             observation.acquisition_id, binding.ordinal, Unit.PACKET))
            self.assertNotIn("Label", observation.features)
            self.assertEqual(truth.state, Label.UNKNOWN)
            self.assertEqual(truth.provenance_ids, ())
            self.assertEqual(truth.confirmed_event_ids, ())
            self.assertIn("untrusted", truth.ambiguity_reason)
            self.assertEqual(annotation.sample_id, observation.sample_id)
            self.assertEqual(annotation.artifact_sha256, self.table.sha256)
        self.assertEqual(tuple(annotation.value for annotation in self.imported.annotations), (1, 0))

    def test_prediction_import_integrates_without_claiming_detection_effectiveness(self):
        result = import_predictions(self.run, self.prediction_table, self.imported, self.prediction_bindings)
        self.assertEqual(len(result.predictions), 2)
        self.assertEqual(tuple(prediction.sample_id for prediction in result.predictions),
                         tuple(observation.sample_id for observation in self.imported.observations))
        metrics = evaluate(self.run, self.imported.observations, self.imported.truths, result.predictions, ())
        self.assertEqual(metrics.n_unknown_truth, 2)
        self.assertEqual(metrics.prediction_coverage, 1)
        self.assertEqual(metrics.evaluation_coverage, 0)
        self.assertIsNone(metrics.precision)
        self.assertEqual(metrics.confusion_matrix, ((0, 0), (0, 0)))

    def test_csv_without_identity_or_timestamp_bindings_is_blocked(self):
        with self.assertRaisesRegex(ContractError, "CSV alone is insufficient"):
            import_observations(self.run, self.table, self.run.sources[0].source_id)
        with self.assertRaises(ContractError):
            import_observations(self.run, self.table, self.run.sources[0].source_id, self.bindings[:1])

    def test_missing_source_or_incorrect_content_hash_is_blocked(self):
        with self.assertRaisesRegex(ContractError, "source identity absent"):
            import_observations(self.run, self.table, "absent-source", self.bindings)
        source = replace(self.run.sources[0], sha256=digest("not these bytes"))
        with self.assertRaises(ContractError):
            import_observations(replace(self.run, sources=(source,)), self.table, source.source_id, self.bindings)

    def test_missing_prediction_execution_bindings_are_blocked(self):
        with self.assertRaises(ContractError):
            import_predictions(self.run, self.prediction_table, self.imported)
        with self.assertRaises(ContractError):
            replace(self.prediction_bindings[0], evidence_ids=())
        with self.assertRaises(ContractError):
            replace(self.bindings[0], evidence_ids=())

    def test_missing_extra_duplicate_or_reordered_columns_are_rejected(self):
        mutations = (
            lambda rows: [row.pop(0) for row in rows],
            lambda rows: [row.append("Extra" if i == 0 else "0") for i, row in enumerate(rows)],
            lambda rows: rows[0].__setitem__(0, "TCP"),
            lambda rows: rows[0].reverse(),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                with self.assertRaises(ContractError):
                    parse_legacy_csv(rewrite(FEATURE_BYTES, mutate), LegacyFormat.EXTRACTOR_CSV)

    def test_invalid_cells_and_wrong_row_width_are_rejected(self):
        cases = (("TTL", ""), ("FlowRate", "NaN"), ("FlowRate", "inf"),
                 ("FlowRate", "1e1000"), ("PacketCount", "1.2"), ("ACK", "2"),
                 ("Label", "malicious"), ("Label", "2"), ("Protocol", "1"))
        for field, value in cases:
            with self.subTest(field=field, value=value):
                changed = rewrite(FEATURE_BYTES, lambda rows: rows[1].__setitem__(rows[0].index(field), value))
                with self.assertRaises(ContractError):
                    parse_legacy_csv(changed, LegacyFormat.EXTRACTOR_CSV)
        with self.assertRaises(ContractError):
            parse_legacy_csv(rewrite(FEATURE_BYTES, lambda rows: rows[1].pop()), LegacyFormat.EXTRACTOR_CSV)

    def test_duplicate_feature_vectors_remain_distinct_occurrences(self):
        data = rewrite(FEATURE_BYTES, lambda rows: rows.__setitem__(2, list(rows[1])))
        table = parse_legacy_csv(data, LegacyFormat.EXTRACTOR_CSV)
        run, bindings = self.context(table)
        imported = import_observations(run, table, run.sources[0].source_id, bindings)
        self.assertEqual(imported.observations[0].features, imported.observations[1].features)
        self.assertNotEqual(imported.observations[0].sample_id, imported.observations[1].sample_id)

    def test_source_alias_import_preserves_identity_and_cannot_be_counted_twice(self):
        source = self.run.sources[0]
        alias = replace(source, source_id="alias", alias_of=source.source_id)
        run = replace(self.run, sources=(source, alias))
        alternate = import_observations(run, self.table, alias.source_id, self.bindings)
        self.assertEqual(tuple(item.sample_id for item in alternate.observations),
                         tuple(item.sample_id for item in self.imported.observations))
        with self.assertRaises(ContractError):
            evaluate(run, self.imported.observations + alternate.observations,
                     self.imported.truths + alternate.truths, (), ())

    def test_identical_csv_bytes_from_independent_acquisitions_keep_distinct_ids(self):
        source = replace(self.run.sources[0], source_id="independent-source", acquisition_id="independent-acq",
                         root_acquisition_ids=("independent-acq",))
        run = replace(self.run, sources=(self.run.sources[0], source))
        independent = import_observations(run, self.table, source.source_id, self.bindings)
        self.assertNotEqual(independent.observations[0].sample_id, self.imported.observations[0].sample_id)
        result = evaluate(run, self.imported.observations + independent.observations,
                          self.imported.truths + independent.truths, (), ())
        self.assertEqual(result.n_observations, 4)

    def test_missing_prediction_columns_are_rejected(self):
        for field in ("pred", "pred_proba"):
            def remove(rows):
                index = rows[0].index(field)
                for row in rows:
                    row.pop(index)
            with self.subTest(field=field):
                with self.assertRaises(ContractError):
                    parse_legacy_csv(rewrite(PREDICTION_BYTES, remove), LegacyFormat.OFFLINE_PREDICTION_CSV)

    def test_duplicate_occurrences_and_duplicate_row_bindings_are_rejected(self):
        for bindings in ((self.bindings[0], replace(self.bindings[1], ordinal=self.bindings[0].ordinal)),
                         (self.bindings[0], replace(self.bindings[1], row_index=0))):
            with self.assertRaises(ContractError):
                import_observations(self.run, self.table, self.run.sources[0].source_id, bindings)

    def test_observation_clock_time_and_artifact_gaps_are_rejected(self):
        for first in (replace(self.bindings[0], clock_id="unknown-clock"),
                      replace(self.bindings[0], timestamp_ns=self.run.end_ns),
                      replace(self.bindings[0], artifact_sha256=digest("wrong artifact"))):
            with self.assertRaises(ContractError):
                import_observations(self.run, self.table, self.run.sources[0].source_id, (first, self.bindings[1]))

    def test_prediction_reordering_and_changed_copied_fields_are_rejected(self):
        for mutation in (
            lambda rows: rows.__setitem__(slice(1, None), list(reversed(rows[1:]))),
            lambda rows: rows[1].__setitem__(rows[0].index("PacketSize"), "65"),
            lambda rows: rows[1].__setitem__(rows[0].index("Label"), "0"),
        ):
            changed = parse_legacy_csv(rewrite(PREDICTION_BYTES, mutation), LegacyFormat.OFFLINE_PREDICTION_CSV)
            bindings = self.make_prediction_bindings(self.imported, changed)
            with self.assertRaises(ContractError):
                import_predictions(self.run, changed, self.imported, bindings)

    def test_wrong_prediction_row_count_is_rejected(self):
        changed = parse_legacy_csv(rewrite(PREDICTION_BYTES, lambda rows: rows.pop()),
                                   LegacyFormat.OFFLINE_PREDICTION_CSV)
        with self.assertRaises(ContractError):
            import_predictions(self.run, changed, self.imported, self.prediction_bindings[:1])

    def test_incorrect_prediction_occurrence_model_clock_or_hash_is_rejected(self):
        first = self.prediction_bindings[0]
        broken = (replace(first, sample_id=self.prediction_bindings[1].sample_id),
                  replace(first, model_sha256=digest("another model")),
                  replace(first, clock_id="wrong-clock"),
                  replace(first, intake_ns=0),
                  replace(first, emitted_ns=1001),
                  replace(first, observation_artifact_sha256=digest("wrong original")),
                  replace(first, prediction_artifact_sha256=digest("wrong predictions")))
        for binding in broken:
            with self.subTest(binding=binding):
                with self.assertRaises(ContractError):
                    import_predictions(self.run, self.prediction_table, self.imported,
                                       (binding, self.prediction_bindings[1]))

    def test_threshold_score_and_decision_validation(self):
        with self.assertRaises(ContractError):
            import_predictions(replace(self.run, decision_threshold=0.7), self.prediction_table,
                               self.imported, self.prediction_bindings)
        for field, value in (("pred", "0"), ("pred_proba", "1.1"), ("pred_proba", "NaN")):
            changed = rewrite(PREDICTION_BYTES, lambda rows: rows[1].__setitem__(rows[0].index(field), value))
            with self.assertRaises(ContractError):
                parse_legacy_csv(changed, LegacyFormat.OFFLINE_PREDICTION_CSV)

    def test_numerically_equal_copied_lexemes_preserve_alignment(self):
        changed = parse_legacy_csv(rewrite(PREDICTION_BYTES, lambda rows: rows[1].__setitem__(0, "6.0")),
                                   LegacyFormat.OFFLINE_PREDICTION_CSV)
        result = import_predictions(self.run, changed, self.imported,
                                    self.make_prediction_bindings(self.imported, changed))
        self.assertEqual(len(result.predictions), 2)

    def test_online_stdout_and_incorrect_selected_formats_are_blocked(self):
        for data in (b"[12:00:00] packets=2 acc=1.000 f1=1.000 cm=[[1,0],[0,1]]\n",
                     b"=== Final Summary ===\npackets: 2\n", b"", b"\xff"):
            with self.assertRaises(ContractError):
                parse_legacy_csv(data, LegacyFormat.OFFLINE_PREDICTION_CSV)
        with self.assertRaises(ContractError):
            import_observations(self.run, self.prediction_table, self.run.sources[0].source_id, self.bindings)
        with self.assertRaises(ContractError):
            import_predictions(self.run, self.table, self.imported, self.prediction_bindings)

    def test_truncated_or_mismatched_import_wrapper_is_rejected(self):
        for changes in ({"observations": (), "truths": ()},
                        {"annotations": ()}, {"bindings": ()},
                        {"observations": tuple(reversed(self.imported.observations))}):
            with self.subTest(changes=changes):
                with self.assertRaises(ContractError):
                    broken = replace(self.imported, **changes)
                    import_predictions(self.run, self.prediction_table, broken, self.prediction_bindings)

    def test_import_records_can_be_exported_without_losing_evidence(self):
        decoded = json.loads(to_json(self.imported))
        self.assertEqual(decoded["truths"][0]["state"], "unknown")
        self.assertEqual(decoded["annotations"][0]["value"], 1)
        self.assertEqual(decoded["bindings"][0]["evidence_ids"], ["fixture-original-occurrence-0"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
