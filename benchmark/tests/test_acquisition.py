"""Offline acquisition fixtures with independently declared matching oracles.

No fixture emits traffic, parses a PCAP, or treats packet ports as truth.
"""

import unittest
from dataclasses import replace

from benchmark.acquisition import (
    Acquisition, CapturedOccurrence, ClockMapping, GeneratorEvidence, Point,
    Status, TrafficActor, reconcile,
)
from benchmark.contracts import (
    ContractError, ExperimentMetadata, Label, Observation, SourceArtifact, Unit,
    stable_sample_id, to_json,
)
from benchmark.evaluator import evaluate
from benchmark.tests.test_core import digest, manifest


PAYLOAD = digest("independently specified probe payload")


class AcquisitionTests(unittest.TestCase):
    def setUp(self):
        self.sources = tuple(
            SourceArtifact(
                "source-" + point, "acquisition-" + point,
                digest("synthetic artifact " + point), "fixture://" + point,
                ("acquisition-" + point,),
            ) for point in ("origin", "target", "sensor")
        )
        self.run = replace(manifest(), sources=self.sources)
        self.experiment = ExperimentMetadata(
            self.run.experiment_id, "fixture-protocol-1", "whole-run", (self.run,),
        )
        self.actor = TrafficActor(
            self.run.run_id, "approved-actor", digest("approved fixture generator"),
            ("independent-actor-binding",), ("approved-benign-profile",),
        )
        self.acquisitions = tuple(
            Acquisition(
                self.run.run_id, source, point,
                self.actor.actor_id if point is Point.ORIGIN else None,
                self.run.clock_id, 1, ("capture-evidence-" + point.value,),
            ) for source, point in zip(self.sources, (Point.ORIGIN, Point.TARGET, Point.SENSOR))
        )
        self.emission = GeneratorEvidence(
            self.run.run_id, "emission-1", self.actor.actor_id, "probe-1", PAYLOAD,
            10, self.run.clock_id, 1, ("independent-send-attempt-ledger",),
        )
        self.occurrences = tuple(
            self.packet(acquisition, timestamp=timestamp)
            for acquisition, timestamp in zip(self.acquisitions, (20, 30, 40))
        )

    def packet(self, acquisition, ordinal=0, timestamp=40, token="probe-1", payload=PAYLOAD):
        source = acquisition.source
        observation = Observation(
            self.run.run_id, source.source_id, source.acquisition_id, ordinal,
            stable_sample_id(self.run.run_id, source.acquisition_id, ordinal, Unit.PACKET),
            timestamp, acquisition.clock_id, Unit.PACKET,
            {"DstPort": 9, "PacketSize": 64},
        )
        return CapturedOccurrence(
            observation, token, payload,
            ("occurrence-evidence-" + source.acquisition_id + "-" + str(ordinal),),
        )

    def reconcile(self, occurrences=None, emissions=None, actors=None, acquisitions=None,
                  mappings=(), experiment=None):
        return reconcile(
            experiment or self.experiment, self.run.run_id,
            (self.actor,) if actors is None else actors,
            self.acquisitions if acquisitions is None else acquisitions,
            (self.emission,) if emissions is None else emissions,
            self.occurrences if occurrences is None else occurrences,
            mappings,
        )

    def assert_sensor_truth(self, result, state):
        self.assertTrue(result.sensor_truths)
        self.assertEqual({truth.state for truth in result.sensor_truths}, {state})
        if state is Label.UNKNOWN:
            for truth in result.sensor_truths:
                self.assertTrue(truth.ambiguity_reason)
                self.assertEqual(truth.confirmed_event_ids, ())

    def test_confirmed_benign_emission_matches_three_points(self):
        result = self.reconcile()
        self.assertEqual(len(result.observations), 3)
        self.assertEqual(tuple(match.status for match in result.matches),
                         (Status.MATCHED,) * 3)
        report = result.emissions[0]
        self.assertEqual(report.status, Status.MATCHED)
        self.assertEqual(report.origin_sample_ids, (self.occurrences[0].observation.sample_id,))
        self.assertEqual(report.target_sample_ids, (self.occurrences[1].observation.sample_id,))
        self.assertEqual(report.sensor_sample_ids, (self.occurrences[2].observation.sample_id,))
        self.assertEqual(report.missing_points, ())
        self.assertEqual(report.duplicate_acquisition_ids, ())
        self.assert_sensor_truth(result, Label.BENIGN)
        origin = result.provenance[0]
        self.assertEqual(origin.actor_id, self.actor.actor_id)
        self.assertEqual(origin.state, Label.BENIGN)
        self.assertIn("approved-benign-profile", origin.evidence_ids)
        self.assertIn("independent-send-attempt-ledger", origin.evidence_ids)
        self.assertEqual(result.sensor_truths[0].provenance_ids, (origin.provenance_id,))
        # Approved origin evidence, rather than destination port 9, assigns truth.
        metrics = evaluate(self.run, result.sensor_observations, result.sensor_truths,
                           (), result.provenance)
        self.assertEqual((metrics.n_observations, metrics.n_known_truth), (1, 1))

    def test_confirmed_emission_missing_sensor_creates_no_sensor_record(self):
        result = self.reconcile(occurrences=self.occurrences[:2])
        report = result.emissions[0]
        self.assertEqual(report.status, Status.MATCHED)
        self.assertEqual(report.missing_points, (Point.SENSOR,))
        self.assertEqual(report.sensor_sample_ids, ())
        self.assertEqual(result.sensor_observations, ())
        self.assertEqual(result.sensor_truths, ())
        self.assertEqual(len(result.observations), 2)

    def test_distinct_duplicate_sensor_occurrences_are_explicit_and_unknown(self):
        duplicate = self.packet(self.acquisitions[2], ordinal=1, timestamp=41)
        result = self.reconcile(occurrences=self.occurrences + (duplicate,))
        sensor_matches = [match for match in result.matches if match.point is Point.SENSOR]
        self.assertEqual(len(sensor_matches), 2)
        self.assertEqual({match.status for match in sensor_matches}, {Status.DUPLICATE})
        self.assertEqual(result.emissions[0].duplicate_acquisition_ids, ("acquisition-sensor",))
        self.assertEqual(len(result.sensor_observations), 2)
        self.assert_sensor_truth(result, Label.UNKNOWN)

    def test_independent_acquisitions_with_identical_contents_remain_distinct(self):
        original = self.acquisitions[2]
        independent_source = replace(
            original.source, source_id="independent-sensor", acquisition_id="independent-acquisition",
            root_acquisition_ids=("independent-acquisition",),
        )
        independent = replace(original, source=independent_source)
        run = replace(self.run, sources=self.run.sources + (independent_source,))
        experiment = replace(self.experiment, runs=(run,))
        extra = self.packet(independent)
        self.assertEqual(original.source.sha256, independent_source.sha256)
        self.assertEqual(extra.payload_sha256, self.occurrences[2].payload_sha256)
        result = self.reconcile(
            occurrences=self.occurrences + (extra,),
            acquisitions=self.acquisitions + (independent,), experiment=experiment,
        )
        self.assertEqual(len(result.sensor_observations), 2)
        self.assertEqual(len({item.sample_id for item in result.sensor_observations}), 2)
        self.assertEqual(result.emissions[0].duplicate_acquisition_ids, ())
        self.assert_sensor_truth(result, Label.BENIGN)

    def test_ambiguous_generator_attribution_preserves_all_candidates(self):
        other = replace(self.actor, actor_id="other-approved-actor")
        attempt = replace(self.emission, emission_id="emission-2", actor_id=other.actor_id)
        source = replace(self.sources[0], source_id="other-origin", acquisition_id="other-origin-acq",
                         root_acquisition_ids=("other-origin-acq",))
        acquisition = replace(self.acquisitions[0], source=source, actor_id=other.actor_id)
        run = replace(self.run, sources=self.run.sources + (source,))
        result = self.reconcile(
            emissions=(self.emission, attempt), actors=(self.actor, other),
            acquisitions=self.acquisitions + (acquisition,),
            occurrences=self.occurrences + (self.packet(acquisition, timestamp=20),),
            experiment=replace(self.experiment, runs=(run,)),
        )
        match = next(match for match in result.matches if match.point is Point.SENSOR)
        self.assertEqual(match.status, Status.AMBIGUOUS)
        self.assertEqual(match.candidate_emission_ids, ("emission-1", "emission-2"))
        self.assert_sensor_truth(result, Label.UNKNOWN)
        self.assertEqual(len(result.sensor_truths[0].provenance_ids), 2)

    def test_unmatched_background_traffic_remains_unknown(self):
        background = self.packet(self.acquisitions[2], ordinal=1, timestamp=42,
                                 token=None, payload=digest("background packet"))
        result = self.reconcile(occurrences=self.occurrences + (background,))
        match = next(item for item in result.matches if item.sample_id == background.observation.sample_id)
        truth = next(item for item in result.truths if item.sample_id == background.observation.sample_id)
        self.assertEqual(match.status, Status.UNMATCHED)
        self.assertEqual(match.candidate_emission_ids, ())
        self.assertEqual(truth.state, Label.UNKNOWN)
        self.assertEqual(truth.provenance_ids, ())
        self.assertTrue(truth.ambiguity_reason)

    def test_inconsistent_run_identity_is_rejected(self):
        for field, value in (
            ("actors", (replace(self.actor, run_id="foreign-run"),)),
            ("emissions", (replace(self.emission, run_id="foreign-run"),)),
            ("acquisitions", (replace(self.acquisitions[0], run_id="foreign-run"),)
             + self.acquisitions[1:]),
        ):
            with self.subTest(field=field), self.assertRaises(ContractError):
                self.reconcile(**{field: value})
        origin = self.occurrences[0]
        observation = replace(
            origin.observation, run_id="foreign-run",
            sample_id=stable_sample_id("foreign-run", origin.observation.acquisition_id, 0, Unit.PACKET),
        )
        with self.assertRaises(ContractError):
            self.reconcile(occurrences=(replace(origin, observation=observation),) + self.occurrences[1:])

    def test_inconsistent_acquisition_identity_is_rejected(self):
        origin = self.occurrences[0]
        observation = replace(origin.observation, acquisition_id="undeclared-acquisition",
                              sample_id=stable_sample_id(self.run.run_id, "undeclared-acquisition", 0, Unit.PACKET))
        with self.assertRaises(ContractError):
            self.reconcile(occurrences=(replace(origin, observation=observation),) + self.occurrences[1:])
        with self.assertRaises(ContractError):
            self.reconcile(acquisitions=(replace(self.acquisitions[0], actor_id="absent-actor"),)
                           + self.acquisitions[1:])

    def foreign_clock_fixture(self):
        acquisition = replace(self.acquisitions[0], clock_id="foreign-clock")
        origin = self.packet(acquisition, timestamp=10)
        emission = replace(self.emission, clock_id="foreign-clock", attempt_ns=0)
        mapping = ClockMapping(
            self.run.run_id, "foreign-clock", self.run.clock_id, 10, 0, 1000, 0,
            ("independently-validated-clock-mapping",), True,
        )
        return acquisition, origin, emission, mapping

    def test_different_clocks_without_validated_mapping_are_rejected(self):
        acquisition, origin, emission, mapping = self.foreign_clock_fixture()
        kwargs = dict(acquisitions=(acquisition,) + self.acquisitions[1:],
                      occurrences=(origin,) + self.occurrences[1:], emissions=(emission,))
        with self.assertRaises(ContractError):
            self.reconcile(**kwargs)
        with self.assertRaises(ContractError):
            self.reconcile(mappings=(replace(mapping, validated=False),), **kwargs)

    def test_empty_acquisition_still_requires_compatible_clock(self):
        # A missing stage does not excuse unverifiable clock metadata.
        origin = replace(self.acquisitions[0], clock_id="foreign-clock")
        with self.assertRaises(ContractError):
            self.reconcile(acquisitions=(origin,) + self.acquisitions[1:],
                           occurrences=self.occurrences[1:])

    def test_validated_mapping_preserves_raw_timestamps_and_identity(self):
        acquisition, origin, emission, mapping = self.foreign_clock_fixture()
        result = self.reconcile(
            acquisitions=(acquisition,) + self.acquisitions[1:],
            occurrences=(origin,) + self.occurrences[1:], emissions=(emission,), mappings=(mapping,),
        )
        normalized = next(item for item in result.observations if item.sample_id == origin.observation.sample_id)
        self.assertEqual((normalized.timestamp_ns, normalized.clock_id), (20, self.run.clock_id))
        raw = next(item for item in result.occurrences if item.observation.sample_id == origin.observation.sample_id)
        self.assertEqual((raw.observation.timestamp_ns, raw.observation.clock_id), (10, "foreign-clock"))
        self.assertEqual(result.clock_mappings, (mapping,))
        self.assert_sensor_truth(result, Label.BENIGN)
        self.assertIn("independently-validated-clock-mapping", result.provenance[0].evidence_ids)

    def test_mapping_outside_validity_interval_is_rejected(self):
        acquisition, origin, emission, mapping = self.foreign_clock_fixture()
        with self.assertRaises(ContractError):
            self.reconcile(
                acquisitions=(acquisition,) + self.acquisitions[1:],
                occurrences=(origin,) + self.occurrences[1:], emissions=(emission,),
                mappings=(replace(mapping, valid_until_ns=5),),
            )

    def test_replay_preserves_observation_identity(self):
        first = self.reconcile()
        second = self.reconcile()
        self.assertEqual(to_json(first), to_json(second))
        self.assertEqual({item.sample_id for item in first.observations},
                         {item.observation.sample_id for item in self.occurrences})

    def test_reordering_inputs_preserves_canonical_results(self):
        background = self.packet(self.acquisitions[2], ordinal=1, timestamp=42, token=None)
        occurrences = self.occurrences + (background,)
        first = self.reconcile(occurrences=occurrences)
        second = self.reconcile(occurrences=reversed(occurrences),
                                acquisitions=reversed(self.acquisitions),
                                actors=reversed((self.actor,)), emissions=reversed((self.emission,)))
        self.assertEqual(to_json(first), to_json(second))

    def test_send_attempt_alone_does_not_establish_truth_or_emission(self):
        result = self.reconcile(occurrences=self.occurrences[1:])
        self.assertEqual(result.emissions[0].status, Status.UNCONFIRMED)
        self.assertEqual(result.emissions[0].origin_sample_ids, ())
        self.assertEqual(result.emissions[0].missing_points, (Point.ORIGIN,))
        self.assert_sensor_truth(result, Label.UNKNOWN)
        sensor = next(match for match in result.matches if match.point is Point.SENSOR)
        self.assertEqual(sensor.status, Status.UNCONFIRMED)
        self.assertEqual(sensor.candidate_emission_ids, ("emission-1",))

    def test_token_without_compatible_payload_is_not_attribution(self):
        sensor = replace(self.occurrences[2], payload_sha256=digest("different payload"))
        result = self.reconcile(occurrences=self.occurrences[:2] + (sensor,))
        match = next(match for match in result.matches if match.point is Point.SENSOR)
        self.assertEqual(match.status, Status.UNMATCHED)
        self.assert_sensor_truth(result, Label.UNKNOWN)
        self.assertEqual(result.emissions[0].missing_points, (Point.SENSOR,))

    def test_ip_and_time_without_correlation_evidence_do_not_assign_truth(self):
        sensor = self.occurrences[2]
        sensor = replace(sensor, token=None, observation=replace(
            sensor.observation, features={"SrcIP": "fixture-address", "DstPort": 9, "PacketSize": 64},
        ))
        result = self.reconcile(occurrences=self.occurrences[:2] + (sensor,))
        self.assert_sensor_truth(result, Label.UNKNOWN)

    def test_repeated_same_occurrence_is_rejected(self):
        with self.assertRaises(ContractError):
            self.reconcile(occurrences=self.occurrences + (self.occurrences[2],))

    def test_alias_cannot_double_count_same_occurrence(self):
        source = self.sources[2]
        alias = replace(source, source_id="sensor-alias", alias_of=source.source_id,
                        uri="fixture://sensor-alias")
        run = replace(self.run, sources=self.run.sources + (alias,))
        duplicate = replace(self.occurrences[2], observation=replace(
            self.occurrences[2].observation, source_id=alias.source_id,
        ))
        with self.assertRaises(ContractError):
            self.reconcile(occurrences=self.occurrences + (duplicate,),
                           experiment=replace(self.experiment, runs=(run,)))

    def test_matching_unapproved_actor_remains_unknown(self):
        actor = replace(self.actor, benign_approval_evidence_ids=())
        result = self.reconcile(actors=(actor,))
        self.assertEqual(result.emissions[0].status, Status.MATCHED)
        self.assert_sensor_truth(result, Label.UNKNOWN)
        self.assertEqual(result.provenance[0].state, Label.UNKNOWN)

    def test_unique_independent_origin_does_not_erase_duplicate_origin_uncertainty(self):
        duplicated = self.packet(self.acquisitions[0], ordinal=1, timestamp=21)
        source = replace(self.sources[0], source_id="independent-origin",
                         acquisition_id="independent-origin-acq",
                         root_acquisition_ids=("independent-origin-acq",))
        acquisition = replace(self.acquisitions[0], source=source)
        run = replace(self.run, sources=self.run.sources + (source,))
        result = self.reconcile(
            acquisitions=self.acquisitions + (acquisition,),
            occurrences=self.occurrences + (duplicated, self.packet(acquisition, timestamp=20)),
            experiment=replace(self.experiment, runs=(run,)),
        )
        self.assertEqual(result.emissions[0].status, Status.DUPLICATE)
        self.assertEqual(result.emissions[0].duplicate_acquisition_ids, ("acquisition-origin",))
        self.assert_sensor_truth(result, Label.UNKNOWN)

    def test_unconfirmed_alternative_generator_prevents_sensor_attribution(self):
        other = replace(self.actor, actor_id="unconfirmed-actor")
        alternative = replace(self.emission, emission_id="emission-2", actor_id=other.actor_id)
        result = self.reconcile(actors=(self.actor, other), emissions=(self.emission, alternative))
        sensor = next(match for match in result.matches if match.point is Point.SENSOR)
        self.assertEqual(sensor.status, Status.AMBIGUOUS)
        self.assertEqual(sensor.candidate_emission_ids, ("emission-1", "emission-2"))
        self.assertEqual(tuple(report.status for report in result.emissions),
                         (Status.MATCHED, Status.UNCONFIRMED))
        self.assert_sensor_truth(result, Label.UNKNOWN)
        self.assertEqual(len(result.sensor_truths[0].provenance_ids), 2)

    def test_origin_before_send_attempt_has_explicit_timing_failure(self):
        result = self.reconcile(emissions=(replace(self.emission, attempt_ns=50),))
        origin = next(match for match in result.matches if match.point is Point.ORIGIN)
        self.assertEqual(origin.status, Status.TIMING_INCOMPATIBLE)
        self.assert_sensor_truth(result, Label.UNKNOWN)

    def test_clock_uncertainty_cannot_be_silently_resolved(self):
        acquisition = replace(self.acquisitions[0], clock_id="foreign-clock")
        origin = self.packet(acquisition, timestamp=20)
        mapping = ClockMapping(
            self.run.run_id, "foreign-clock", self.run.clock_id, 0, 0, 1000, 15,
            ("clock-mapping-with-measured-uncertainty",), True,
        )
        result = self.reconcile(acquisitions=(acquisition,) + self.acquisitions[1:],
                                occurrences=(origin,) + self.occurrences[1:], mappings=(mapping,))
        origin_match = next(match for match in result.matches if match.point is Point.ORIGIN)
        self.assertEqual(origin_match.status, Status.AMBIGUOUS)
        self.assert_sensor_truth(result, Label.UNKNOWN)


if __name__ == "__main__":
    unittest.main()
