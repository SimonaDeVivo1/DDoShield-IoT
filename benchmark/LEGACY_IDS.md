# M1.1 — Legacy IDS CSV adapter

`legacy_ids.py` is a Python 3.10+ standard-library adapter using existing M0.1
contracts (schema `0.1.1`). It reads files; it does not run a detector, load joblib,
generate traffic, extract new features or instrument capture. The original model,
38-feature schema and runtime are unchanged.

## Verified source formats

All source references are relative to the repository root. Archive references
use `archive :: member`, with line numbers from the decoded member.

| Format | Evidence | Supported mapping |
|---|---|---|
| Extractor CSV | `docker/IDS/model_train_pipeline/ids-online-save-csv.py:81–102,244–282` | Strict 38 features plus `Label`, with exact header order |
| Extractor-derived offline prediction CSV | `docker/IDS/model_train_pipeline/ids_offline_model_predict.py:28–46` | Original 39 columns, then `pred_proba,pred`; original rows must align |
| Online stdout | `docker/IDS/.conf :: ids-online-predict.py:331–338,393–404` | Blocked: cumulative metrics, no sample-level prediction artifact |
| Feature order | `docker/IDS/.conf :: ids-model-bundle/metadata.json:2–41` | Adapter constants are checked against these 38 names in tests |

The extractor's first 14 feature fields are `Protocol,TCP,UDP,TTL,ACK,SYN,FIN,
PSH,URG,RST,SequenceNumber,AcknowledgmentNumber,PacketSize,PayloadSize`. `Label`
follows them; the remaining 24 aggregate features follow `Label`. The complete
verified order is `FEATURE_NAMES`, with export layouts `EXTRACTOR_COLUMNS` and
`PREDICTION_COLUMNS`. Required fields may not be missing, extra, duplicated or
reordered. Only the extractor-derived offline CSV subset is supported: the
offline helper accepts other arbitrary inputs, but their schemas are unverified.

Rows represent IPv4 TCP/UDP packet features with shared batch context
(`ids-online-save-csv.py:40–46,237–272`). The adapter checks transport flags,
finite numeric values, integral fields, binary annotations and predictions.
It does not certify that aggregate values were computed correctly from packets.
The offline score can be a probability, transformed margin or binary fallback
(`ids_offline_model_predict.py:30–37`); calibration is not established. Its decision
is always `score >= 0.5` (`39`), and incompatible thresholds are rejected.

## Truth and metadata blockers

`Label` is `sport == 9 or dport == 9` (`ids-online-save-csv.py:78–79`, archived
predictor `102–103`). It is stored only as a separate `LegacyAnnotation` linked
to the sample, row and artifact hash. Every imported `GroundTruth` is `UNKNOWN`
with an explicit explanation, no invented provenance and no confirmed events.
The adapter does not accept legacy labels as an independent truth source.

The extractor drops packet timestamps, addresses, ports and batch identifiers
before CSV export (`270–272`). Its filename timestamp (`308–316`) is not a
per-packet timestamp. The offline output also lacks acquisition/run/model identity,
sample IDs and execution times. Therefore CSV alone cannot produce complete
M0.1 observations or predictions. Parsing is supported; conversion is blocked
unless the missing metadata has already been independently recorded.

Caller-supplied **in-memory benchmark bindings** are required. They are not a
legacy sidecar file format and do not assert that such instrumentation exists:

- Observation: declared source/acquisition in `RunMetadata`, actual CSV content
  hash, CSV row index, original acquisition ordinal, packet timestamp, clock and
  independent evidence references.
- Prediction: CSV row index, corresponding sample ID, both CSV hashes, executed
  model hash, intake/feature-ready/emission timestamps, clock and evidence references.

Empty evidence references, missing bindings, undeclared sources, wrong hashes,
duplicate occurrences, clock/interval gaps and model mismatches are rejected.
The adapter never substitutes import time, filename time, row index for original
packet ordinal, default model identity or fabricated evidence. A caller's evidence
references remain declarations: their real-world validity is not verified here.

## Import API

The following uses already-established `run`, `observation_bindings`,
`prediction_bindings` and a declared `source_id`. No defaults reconstruct them.

```python
from benchmark.legacy_ids import (
    LegacyFormat, read_legacy_csv, import_observations, import_predictions,
)

features = read_legacy_csv("features.csv", LegacyFormat.EXTRACTOR_CSV)
observed = import_observations(run, features, source_id, observation_bindings)
output = read_legacy_csv("preds.csv", LegacyFormat.OFFLINE_PREDICTION_CSV)
predicted = import_predictions(run, output, observed, prediction_bindings)

# Existing evaluator interfaces consume separate records.
from benchmark.evaluator import evaluate
result = evaluate(run, observed.observations, observed.truths,
                  predicted.predictions, provenance=())
```

With only legacy truth, prediction coverage can be complete while evaluation
coverage is zero; effectiveness metrics remain undefined. This is intentional.
Independent labels may be attached separately through the existing benchmark
contracts once trustworthy provenance exists; that work is outside this adapter.

Retain both import bundles alongside evaluation results. `to_json()` can export
them without writing files: bundles preserve annotations, both CSV hashes and
binding evidence references. The core evaluation envelope hashes its contract
inputs; it does not automatically include all adapter-only binding metadata.

## Alignment and remaining limitations

The original feature CSV is required for prediction conversion. The adapter
verifies row counts and exact numerical equality of all copied fields, including
the untrusted annotation, then checks externally bound sample references. Numeric
spellings such as `6` and `6.0` compare equal. It does not align rows by feature
hash or deduplicate equal vectors. Alias imports retain acquisition occurrence
identity; independent acquisitions with equal contents remain distinct.

The offline helper reads and rewrites numeric CSV data through pandas, rather
than copying bytes. Numerical drift during that rewrite may therefore cause a
conservative alignment rejection. No tolerance policy is silently introduced.
Swapping completely identical copied rows cannot be detected from the CSV alone;
external row-to-occurrence execution evidence must establish that association.
CSV model identity, original packet order, batch boundaries and capture timing
cannot be recovered when that evidence was never recorded. Online aggregate
stdout cannot be expanded into packet records.

The static fixtures in `tests/fixtures/legacy_*.csv` are explicitly constructed
examples of verified layouts, with synthetic external metadata in tests. They
are not real capture results or predictions produced by the pretrained model.
Real capture, independent ground truth, timing instrumentation, online adapter
integration and detector-performance claims belong to later milestones, including
M1.2, and remain out of scope.
