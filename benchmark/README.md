# Benchmark contracts v0.1.1 — Milestone M0.1

This standalone, Python 3.10+ standard-library package validates explicitly
constructed observations and evaluates independent packet labels. It imports no
DDoShield-IoT runtime, reads no bundled model, and generates no traffic. The
original 38-feature schema and pretrained model are unchanged.

## Files

- `contracts.py`: immutable, versioned records, stable sample identity, canonical
  JSON export, and source-provenance partition validation.
- `evaluator.py`: cross-record checks, packet confusion counts/metrics/coverage,
  evaluation provenance envelopes and fixed-window truth summaries.
- `tests/test_core.py`: deterministic fixture data and explicit expected outcomes.
- `tests/test_hardening.py`: acquisition/alias, uncertain-event and evaluation
  provenance regressions, including time origins and input-order invariance.
- `legacy_ids.py`: strict M1.1 offline CSV adapter; see [LEGACY_IDS.md](LEGACY_IDS.md)
  for supported formats, required external metadata and conversion blockers.
- `tests/test_legacy_ids.py`, `tests/fixtures/legacy_*.csv`: deterministic adapter
  tests and synthetic examples of verified legacy CSV layouts.
- `acquisition.py`, `tests/test_acquisition.py`: offline M1.2a evidence reconciliation;
  see [ACQUISITION.md](ACQUISITION.md) for guarantees, clock rules and capture limitations.
- `__init__.py`, `tests/__init__.py`: package markers and schema version.

## Run the deterministic validation

From the repository root:

```sh
python3 -B -m unittest discover -s benchmark/tests -v
```

Exit status 0 and `OK` mean PASS; an assertion/error and nonzero status mean FAIL.
`-B` prevents bytecode files being created. No installation or network access is
needed. Test timestamps are synthetic integer nanoseconds, not measurements.

## Contracts and semantics

`ExperimentMetadata` declares the protocol and split policy, groups run records,
and validates their experiment membership and partition independence.
`RunMetadata` identifies experiment/run/scenario, seed, partition, common clock,
run interval, source artifacts, model hash, decision threshold, and resolved network, traffic, attack,
IDS, software and hardware settings. Settings are recursively snapshotted into
immutable JSON-compatible values. Their top-level presence is validated; detailed
runtime/dependency/hardware schemas are intentionally deferred. The run interval
includes output drain. The same clock identity is required for observations,
events and predictions; clock conversion is outside M0.1.

`SourceArtifact` separates four identities:

| Identity | Meaning |
|---|---|
| `sha256` | Complete artifact bytes; integrity/content identity only |
| `acquisition_id` | Globally stable identity of an actual acquisition |
| `source_id`, `alias_of` | Run-local import name and explicit alias of a canonical source |
| `(acquisition_id, ordinal, unit)` | Canonical occurrence within that acquisition |

Each acquisition has exactly one canonical source per run. Aliases must point
directly to it and agree on acquisition, content hash and lineage; only their
import name and URI can differ. Alias chains, absent targets and contradictory
definitions are rejected. Observations identify both import and acquisition;
the evaluator validates that relationship.

`root_acquisition_ids` lists all shared underlying observation acquisitions.
Original sources list their own acquisition ID. Derived captures or datasets
declare all shared ancestry. Split validation rejects shared acquisitions or
ancestry across train/validation/test, including renamed replay copies. Reuse
within one partition is permitted, but an acquisition cannot change its declared
bytes or lineage between runs. Source IDs are run-local; reusing an import name
does not imply shared provenance. Equal content hashes alone do not establish
shared acquisition: independently acquired identical contents can cross splits
when their independently recorded acquisition IDs and ancestry are disjoint.

Acquisition identity and ancestry are declared evidence, not inferred from bytes.
A copied capture must retain its acquisition identity; inventing a new ID cannot
make it independent. The validator cannot discover fabricated IDs, omitted
ancestry or verify actual artifact bytes. Software/model/corpus configuration is
not itself shared observation acquisition ancestry.

`Observation` contains observable features, source occurrence, timestamp and unit.
Its stable SHA-256 sample ID depends on run ID, acquisition ID, canonical ordinal
and classification unit, never content hashes, aliases, labels, features or scores.
Aliases of the same occurrence get the same ID and fail as duplicate observations;
the evaluator does not silently discard duplicate/conflicting records. Independent
acquisitions or different ordinals remain distinct even with identical packet
contents. Ordinals must preserve canonical acquisition order, not alias-specific
renumbering or nondeterministic processing order. Reordered/transformed captures
require a trustworthy occurrence mapping; M0.1 does not construct that mapping.
No new feature schema is
imposed; reserved top-level truth/partition keys are rejected. Producers remain
responsible for excluding covert labels or nested metadata from features.

`AttackEvent` represents an independently evidenced emission event with a
half-open interval and actor memberships. Scheduled command intent is not an
observed event; a future controller needs separate planned/execution records.
`TrafficProvenance` records externally assigned origin state, evidence references,
actor and event memberships. `GroundTruth` explicitly assigns benign, malicious
or unknown to a sample, with provenance references and an ambiguity reason for
unknown truth. Both contracts distinguish `confirmed_event_ids` from
`candidate_event_ids`, which must be disjoint within a record. Benign records
cannot claim attack events; unknown records cannot confirm attack events.

Every confirmed/candidate provenance association is checked for event existence
and actor membership, even when its provenance record is not used for scoring.
For known truth, all origins must agree with its binary state; confirmed IDs are
their confirmed union and candidate IDs their candidate union minus confirmed IDs.
For unknown truth, referenced origins are exhaustive alternatives: all their
confirmed and candidate events become sample-level candidates, with no confirmed
events. Missing, unrelated or omitted candidates are rejected. Unknown may also
have no provenance and no candidate events, with a reason. The underlying binary
state never bypasses event/provenance validation. An event can appear in both
sets of a window when different packets independently confirm/candidate it.
No port, source IP, event-time overlap or prediction is used to infer truth.
Arrival time is not required to fall inside an emission event: transit delay can
move it outside. Evidence strings are references, not cryptographic proof that a
generator actually emitted a packet; trustworthy attribution is future work.

`Prediction` references a sample, declares a unit/model, and records malicious
score, threshold and intake/feature-ready/emission times. Positive means score
greater than or equal to threshold, preserving the current IDS's binary semantics.
Scores need not be calibrated probabilities. Stages must be ordered, intake must
not precede observation, and model/unit/clock must match the run/sample. M0.1 evaluates
one prediction per sample from one model; repeated predictions require a future
explicit policy. Each prediction's threshold must match the run manifest; a future
controller must freeze that threshold before test execution.

The evaluator rejects duplicate or foreign references, invalid actor/event links,
model mismatches and non-packet units. Unknown labels and missing truth do not
enter the confusion matrix. Missing predictions are exposed as coverage failures,
not silently converted to negative predictions or false negatives. Effectiveness
metrics are therefore conditional on known truth **and** a completed prediction.
Always report coverage alongside them; this is not end-to-end detection success.

## Metric definitions

Confusion matrix order is `[[TN, FP], [FN, TP]]`:

| Metric | Definition |
|---|---|
| Precision | TP / (TP + FP) |
| Recall | TP / (TP + FN) |
| F1 | 2TP / (2TP + FP + FN) |
| FPR | FP / (FP + TN) |
| FNR | FN / (FN + TP) |
| Evaluation coverage | evaluated packets / all declared packet observations |
| Truth coverage | known-truth packets / all observations |
| Prediction coverage | packets with predictions / all observations |
| Known prediction coverage | evaluated packets / known-truth packets |

A zero denominator produces Python `None`, exported as JSON `null`. A defined
zero remains zero: F1 is zero when there are false negatives but no positive
predictions, even though precision is undefined. Empty evaluation is not an
accuracy or operational success result. Counts distinguish unknown truth,
missing truth, missing predictions and known packets without predictions.

Fixed windows are `[run.start + k*width, run.start + (k+1)*width)`, with the last
clipped at run end. All windows, including empty ones, are emitted. Packet labels
remain intact: benign-only, malicious-only, mixed, uncertain or empty describes
the window, not a replacement packet label. Unknown or missing truth makes the
window uncertain; counts still retain any known benign/malicious composition.
Window summaries include experiment ID, run ID, clock ID, origin timestamp, and
distinct confirmed/candidate event sets. Unknown samples contribute only candidate
events. Event IDs are sets; overlapping events never multiply packet counts.

## Evaluation provenance

`evaluate()` returns pure numerical `Evaluation` results after record validation.
`evaluate_result(experiment, run_id, observations, truths, predictions, provenance,
events)` wraps them in an immutable, versioned `EvaluationResult` containing
experiment/run/protocol identity, IDS identifier, model hash, threshold and its
`>=`/malicious-class semantics, input hashes, and the numerical results. The run
must belong to the supplied validated experiment. For this wrapper,
`run.ids["implementation"]` must be a nonempty string; generic RunMetadata IDS
settings still accept arbitrary nonempty mappings.

Input iterables are snapshotted once. Collection hashes are SHA-256 over canonical
JSON of sorted canonical record JSON strings, making record iteration order
irrelevant. The envelope also hashes the run and experiment metadata and includes
declared source artifact content hashes (`source:<source_id>`). A changed feature,
truth or prediction therefore changes its input digest even if counts are equal.
These hashes identify the evaluated records; they do not read/hash external files
or authenticate the referenced evidence. Pure metric equality across two runs is
expected; their envelopes preserve different identities.

## Migration from M0 schema 0.1

Schema `0.1.1` deliberately requires new records; `0.1` records are rejected.
Source artifacts add `acquisition_id`/`alias_of` and replace `root_sha256s` with
`root_acquisition_ids`. Observations add acquisition identity, and sample IDs must
be rebuilt using it. `attack_event_ids` becomes `confirmed_event_ids`, with a
separate `candidate_event_ids` field. Unknown event alternatives must be recorded
as candidates, not confirmed memberships. Window summaries gain identity/time
fields and separate event sets. Content hashes cannot automatically recover
acquisition lineage: migration needs independently known acquisition metadata.

## Scope of verification

Tests cover port-independent truth, mixed/uncertain windows, exact boundaries,
overlapping events, independent partitions and reused source ancestry, duplicate
records, invalid contracts, immutable configuration, timing/model/unit consistency,
correct denominators, undefined metrics, coverage, source aliases, independent
identical-content acquisitions, candidate-event consistency, evaluation provenance,
nonzero origins and order invariance. They validate the declared
fixture evidence and associations, not real traffic provenance.

Still unverified: real packet capture/matching, completeness of provenance,
clock synchronization, online feature parity, actual detector effectiveness,
packet loss, latency, resource use, ns-3 behavior and live reproducibility.
Scenario-held-out partition policy, controllers, adapters, model training,
artifact loading and runtime instrumentation are outside M0.1. Window summaries
still materialize all empty windows; very long intervals with tiny widths can
produce excessive output. Measurement/warm-up/drain interval separation and
scenario-level split enforcement remain future protocol work.
