# M1.2a — Offline acquisition evidence and reconciliation

`acquisition.py` performs no I/O, capture, PCAP parsing, traffic generation or
detector execution. It is Python 3.10.12-compatible standard-library code using
the existing M0.1 schema `0.1.1`. All current evidence is independently specified
synthetic fixture data; a passing test does not verify any real emission.

## Inputs and outputs

The component reuses `ExperimentMetadata`, `RunMetadata`, `SourceArtifact`,
`Observation`, `TrafficProvenance` and `GroundTruth` without changing them.
Additional immutable evidence records are:

- `TrafficActor`: run/actor identity, generator artifact hash, identity evidence,
  and optional independent benign-profile approval references.
- `Acquisition`: canonical source artifact, run, ORIGIN/TARGET/SENSOR observation
  point, raw clock, positive timestamp resolution and capture binding evidence.
  ORIGIN additionally identifies its independently bound actor. TARGET/SENSOR
  cannot assert generator identity merely from a capture interface.
- `GeneratorEvidence`: emission/attempt identifier, actor, correlation token,
  exact payload digest, attempt timestamp/clock/resolution and ledger evidence.
  It records a send attempt, never presumed observable emission.
- `CapturedOccurrence`: an existing raw packet `Observation`, optional correlation
  token, exact payload digest and capture evidence. Correlation data stays outside
  IDS features. Stable sample identity remains run/acquisition/ordinal/unit.
- `ClockMapping`: explicit validated declaration, direct constant offset to the
  run clock, source-clock validity interval, uncertainty and calibration evidence.

Call `reconcile(experiment, run_id, actors, acquisitions, emissions, occurrences,
clock_mappings=())`. The returned `Reconciliation` preserves the experiment,
actors, acquisitions, original ledgers/captures and clock mappings, and includes
normalized M0.1 observations, ground truth, provenance and diagnostic outcomes.
Collections and evidence identifiers are sorted for deterministic export with
`to_json()`. Input generators are accepted; original records are not mutated.

## Matching semantics

This narrow probe protocol correlates an explicitly declared token **and** exact
payload SHA-256. Digests identify payload bytes, not packet occurrences. Ports,
IP addresses, timestamps alone, IDS features and predictions never assign truth.
Tokens are association evidence, not general attack/benign classification rules.
The core assumes no raw packet layout or token parser; a future capture producer
must independently establish the extraction convention.

At ORIGIN, candidates must also agree with the acquisition's actor identity.
TARGET/SENSOR candidates include every matching generator ledger entry in the
run, including unconfirmed attempts. Time is checked for compatibility, never
used to select one generator from multiple candidates. There is no first-match
or nearest-timestamp policy.

One uniquely attributable origin occurrence per acquisition, with compatible
attempt chronology, confirms observable emission for that candidate. Independent
origin acquisitions may corroborate it. Duplicate or ambiguous origin evidence
cannot be overridden by another unique acquisition. Only independently approved
benign actors with confirmed origins can produce BENIGN provenance. Unapproved
actors remain UNKNOWN; this milestone does not establish malicious provenance.

| Outcome | Meaning |
|---|---|
| MATCHED | Unique, chronologically compatible association with confirmed origin evidence |
| UNCONFIRMED | Candidate send attempt has no attributable observable origin evidence |
| AMBIGUOUS | Multiple candidates or unresolved timing uncertainty |
| DUPLICATE | Distinct occurrences within one acquisition share a declared probe correlation key |
| UNMATCHED | No supported generator association, including background and incompatible payloads |
| TIMING_INCOMPATIBLE | Declared chronology cannot support the association |

Repeated stable sample IDs, including aliases, raise `ContractError` rather than
count twice. Distinct occurrences with duplicate correlation evidence are retained
and marked UNKNOWN. Identical contents from independent acquisitions remain
distinct; payload hashes alone never deduplicate observations. Independent
acquisition identity/ancestry must be genuine declarations, not invented IDs for
copied captures.

Each `EmissionOutcome` preserves candidate origin/target/sensor sample IDs,
missing observation points and duplicate acquisition IDs. `confirmed` means
origin confirmation only, not successful arrival at every later point. Candidate
IDs in a report are not necessarily confirmed associations: inspect per-sample
`MatchOutcome.status`. Missing points mean missing matching evidence, **not**
identified packet loss, capture failure or proof that the attempt never emitted.
No missing observations or fabricated false negatives are created.

Unknown truth retains explanations and candidate provenance references. Those
references are emission evidence, not attack-event associations; M0.1 confirmed
and candidate attack-event fields remain empty. Provenance evidence preserves
actor approval, generator identity/hash, source artifact hashes, ledger references,
capture occurrence IDs and clock mapping references.

## Clocks and evaluation scope

Every acquisition and timestamp domain must match the run or have one explicit,
externally validated direct mapping. Empty foreign-clock acquisitions are checked
too. Mappings are bounded constant-offset records; chained mappings and drift
models are unsupported. The original timestamp, clock and resolution remain in
the input evidence; normalized observations retain the same sample ID.

Resolution is treated conservatively as quantization uncertainty of plus/minus
`resolution_ns - 1`; mapping uncertainty is added. The whole source quantization
interval must be within mapping validity. A causal order is accepted only when
the uncertainty intervals establish it, with exact equal timestamps allowed.
Unresolved overlaps remain AMBIGUOUS; reversed chronology remains UNKNOWN with
an explicit timing outcome. Normalized centers must lie within the run interval.
The validated flag and calibration references are declarations, not calibration
performed by this offline module.

Use `result.sensor_observations` and `result.sensor_truths` for sensor evaluation
with the existing evaluator. All-stage observations deliberately represent
different observation points of the same physical emission; their combined
count is not an emitted-packet count. The sensor properties include every declared
sensor acquisition; choose a specific acquisition for a single-detector trial.
No IDS predictions are generated, so this milestone cannot measure effectiveness.

## Connection to M1.1

Captured sensor occurrences provide acquisition IDs, canonical ordinals, measured
timestamps and evidence references. A future extraction-boundary ledger must
preserve their actual association to feature CSV rows before M1.1
`ObservationBinding` can be populated. CSV row index is not original capture
ordinal. Payload/feature equality cannot reconstruct discarded row identity.
Legacy annotations remain untrusted even if correlation evidence exists.

M1.1 deliberately creates UNKNOWN import truth. Acquisition-derived `GroundTruth`
must be joined separately by validated sample identity, with its provenance;
matching tokens must never promote the legacy port-derived annotation. Feature
extraction and per-prediction timing/model evidence are still required before
creating valid legacy prediction bindings. This milestone supplies none of those
missing fields implicitly.

## Minimum future Linux capture producer interface

An eventual producer must expose these actual measured/recorded fields:

1. Experiment/run association and immutable source artifact hash/URI, acquisition
   identity, complete observation ancestry and explicit aliases.
2. Observation point, interface identity/direction and link type, with recorded
   namespace/container/process-to-actor binding for origin attribution.
3. Canonical occurrence ordinal, stable sample ID, raw timestamp, clock domain,
   measured timestamp resolution and applicable calibration evidence.
4. Captured/original byte lengths and raw evidence sufficient to compute the
   declared payload digest and token extraction; unsupported/truncated records
   must be reported rather than assigned invented correlation values.
5. Capture start/end, readiness/termination, capture/drop counters (or explicit
   unavailability), restart events and finalization evidence.
6. Independent actor approval and generator attempt ledger, including attempt
   identity, intended token/payload, actual attempt time and execution evidence.

No capture backend is implemented or claimed available. A Linux producer must
first verify an installed backend, privileges, timestamp behavior and visibility
at origin/target/sensor. Offloads, segmentation, truncation and capture duplication
require verification before applying this exact-payload probe protocol. Raw bytes,
tokens, actor bindings and evidence references cannot be authenticated from these
synthetic records alone.

An approved benign probe validates acquisition/matching for its declared profile.
It does not validate general traffic labeling, opaque bot behavior, malicious
attack attribution, synchronization accuracy, loss rates or IDS detection quality.

## Validation

```sh
python3 -B -m unittest discover -s benchmark/tests -v
```

The new fixtures are constructed in `tests/test_acquisition.py`; none emits
traffic or parses PCAP. Existing contracts, adapter tests and runtime are preserved.
