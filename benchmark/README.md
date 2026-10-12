# Benchmark contracts v0.1 — Milestone M0

This standalone, Python 3.10+ standard-library package validates explicitly
constructed observations and evaluates independent packet labels. It imports no
DDoShield-IoT runtime, reads no bundled model, and generates no traffic. The
original 38-feature schema and pretrained model are unchanged.

## Files

- `contracts.py`: immutable, versioned records, stable sample identity, canonical
  JSON export, and source-provenance partition validation.
- `evaluator.py`: cross-record checks, packet confusion counts/metrics/coverage,
  and fixed-window truth summaries.
- `tests/test_core.py`: deterministic fixture data and explicit expected outcomes.
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
events and predictions; clock conversion is outside M0.

`SourceArtifact` records content hash, URI and declared original-source ancestry.
Original sources list their own hash as a root. Derived sources must declare all
shared capture/dataset ancestors. Partition validation rejects shared source IDs,
content hashes or declared ancestry across train/validation/test, including replay
copies with renamed identifiers. Reuse within one partition is permitted. Shared
software/model/corpus configuration is not itself shared observation provenance.
The validator cannot discover omitted ancestry or verify real artifact bytes.

`Observation` contains observable features, source occurrence, timestamp and unit.
Its stable SHA-256 sample ID depends on run ID, source ID, occurrence ordinal and
classification unit, never ports, labels, features or scores. Identical packets
at different ordinals remain different samples. Ordinals must refer to stable
source order, not nondeterministic processing order. No new feature schema is
imposed; reserved top-level truth/partition keys are rejected. Producers remain
responsible for excluding covert labels or nested metadata from features.

`AttackEvent` represents an independently evidenced emission event with a
half-open interval and actor memberships. Scheduled command intent is not an
observed event; a future controller needs separate planned/execution records.
`TrafficProvenance` records externally assigned origin state, evidence references,
actor and event memberships. `GroundTruth` explicitly assigns benign, malicious
or unknown to a sample, with provenance references. Known truth must agree with
every referenced origin and its complete event set. Conflicting origins can only
be represented as unknown with a reason. Unknown may also have no provenance.
No port, source IP, event-time overlap or prediction is used to infer truth.
Arrival time is not required to fall inside an emission event: transit delay can
move it outside. Evidence strings are references, not cryptographic proof that a
generator actually emitted a packet; trustworthy attribution is future work.

`Prediction` references a sample, declares a unit/model, and records malicious
score, threshold and intake/feature-ready/emission times. Positive means score
greater than or equal to threshold, preserving the current IDS's binary semantics.
Scores need not be calibrated probabilities. Stages must be ordered, intake must
not precede observation, and model/unit/clock must match the run/sample. M0 evaluates
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
Event IDs are sets; overlapping events never multiply packet counts.

## Scope of verification

Tests cover port-independent truth, mixed/uncertain windows, exact boundaries,
overlapping events, independent partitions and reused source ancestry, duplicate
records, invalid contracts, immutable configuration, timing/model/unit consistency,
correct denominators, undefined metrics and coverage. They validate the declared
fixture evidence and associations, not real traffic provenance.

Still unverified: real packet capture/matching, completeness of provenance,
clock synchronization, online feature parity, actual detector effectiveness,
packet loss, latency, resource use, ns-3 behavior and live reproducibility.
Scenario-held-out partition policy, controllers, adapters, model training,
artifact loading and runtime instrumentation are outside M0.
