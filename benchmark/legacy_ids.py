"""Strict offline adapter for the two CSV formats verified in the legacy source.

CSV rows alone lack the identity and timing required by M0.1. Bindings below
are caller-supplied benchmark metadata, not a purported legacy sidecar format.
No model is executed and legacy labels never become independent truth.
"""

from __future__ import annotations

import csv
import hashlib
import io
import math
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Mapping

from . import SCHEMA_VERSION
from .contracts import (
    ContractError, GroundTruth, Label, Observation, Prediction, RunMetadata, Unit,
    _integer, _score, _settings, _sha, _strings, _text, _version, stable_sample_id,
)
from .evaluator import evaluate


# metadata.json in docker/IDS/.conf and extractor feature assignments agree.
FEATURE_NAMES = (
    "Protocol", "TCP", "UDP", "TTL", "ACK", "SYN", "FIN", "PSH", "URG", "RST",
    "SequenceNumber", "AcknowledgmentNumber", "PacketSize", "PayloadSize",
    "DstPortEntropy", "PacketCount", "MostFreqSrcPort", "MostFreqDstPort",
    "PacketSizeStd", "AvgPacketSize", "MostFreqPacketSizeFreq", "AbnormalSizeFreq",
    "SeqNumVariance", "ShortLivedConnections", "RepeatedAttempts", "ScanningActivity",
    "FlowRate", "SourceEntropy", "ConnectionErrors", "AvgPacketNumber", "SYNFrequency",
    "ACKFrequency", "TCPFrequency", "UDPFrequency", "MostFreqProtocol", "PacketSizeVar",
    "MostFreqPayloadSize", "AvgPayloadSize",
)
EXTRACTOR_COLUMNS = FEATURE_NAMES[:14] + ("Label",) + FEATURE_NAMES[14:]
PREDICTION_COLUMNS = EXTRACTOR_COLUMNS + ("pred_proba", "pred")
_INTEGER_FEATURES = frozenset(FEATURE_NAMES[:14]) | {
    "PacketCount", "MostFreqSrcPort", "MostFreqDstPort", "MostFreqPacketSizeFreq",
    "AbnormalSizeFreq", "ShortLivedConnections", "RepeatedAttempts", "ScanningActivity",
    "ConnectionErrors", "MostFreqProtocol", "MostFreqPayloadSize",
}
_BINARY_FEATURES = {"TCP", "UDP", "ACK", "SYN", "FIN", "PSH", "URG", "RST"}
_UNKNOWN_REASON = "No independent truth: legacy Label is an untrusted port-9 annotation."


class LegacyFormat(str, Enum):
    EXTRACTOR_CSV = "legacy-extractor-csv"
    OFFLINE_PREDICTION_CSV = "legacy-offline-prediction-csv"


@dataclass(frozen=True)
class LegacyRow:
    row_index: int
    features: Mapping[str, int | float]
    legacy_label: int
    copied_values: tuple[str, ...]  # exact decimal representations, including Label
    score: float | None = None
    decision: int | None = None

    def __post_init__(self) -> None:
        _integer(self.row_index, "row_index")
        if (not isinstance(self.copied_values, tuple) or len(self.copied_values) != len(EXTRACTOR_COLUMNS)
                or any(not isinstance(value, str) for value in self.copied_values)):
            raise ContractError("copied values require the complete numeric extractor row")
        numeric = {name: _decimal(value, name, self.row_index)
                   for name, value in zip(EXTRACTOR_COLUMNS, self.copied_values)}
        _settings(self, "features")
        if tuple(self.features) != FEATURE_NAMES or self.features != _features(numeric, self.row_index):
            raise ContractError("row features differ from verified copied-input schema/values")
        _integer(self.legacy_label, "legacy_label")
        if self.legacy_label != _binary(numeric["Label"], "Label", self.row_index):
            raise ContractError("legacy annotation differs from copied Label")
        if self.score is None:
            if self.decision is not None:
                raise ContractError("decision requires a score")
        else:
            _score(self.score, "score")
            _integer(self.decision, "decision")
            if self.decision != int(self.score >= 0.5):
                raise ContractError("decision disagrees with legacy threshold 0.5")


@dataclass(frozen=True)
class LegacyCSV:
    format: LegacyFormat
    sha256: str
    rows: tuple[LegacyRow, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.format, LegacyFormat):
            raise ContractError("unsupported legacy format")
        _sha(self.sha256)
        if not isinstance(self.rows, tuple) or not self.rows:
            raise ContractError("legacy CSV requires nonempty rows")
        for index, row in enumerate(self.rows):
            if not isinstance(row, LegacyRow) or row.row_index != index:
                raise ContractError("legacy CSV rows must have consecutive export indices")
            if (self.format is LegacyFormat.EXTRACTOR_CSV) != (row.score is None):
                raise ContractError("row prediction fields disagree with selected format")


def _decimal(text: str, field: str, row_index: int) -> Decimal:
    try:
        value = Decimal(text)
    except InvalidOperation as error:
        raise ContractError(f"row {row_index}: invalid numeric {field}") from error
    if not value.is_finite():
        raise ContractError(f"row {row_index}: nonfinite {field}")
    return value


def _binary(value: Decimal, field: str, row_index: int) -> int:
    if value not in (0, 1):
        raise ContractError(f"row {row_index}: {field} must be binary")
    return int(value)


def _features(numeric, row_index):
    features = {}
    for name in FEATURE_NAMES:
        value = numeric[name]
        if name in _INTEGER_FEATURES:
            if value != value.to_integral_value():
                raise ContractError(f"row {row_index}: nonintegral {name}")
            features[name] = int(value)
        else:
            floating = float(value)
            if not math.isfinite(floating):
                raise ContractError(f"row {row_index}: out-of-range {name}")
            features[name] = floating
        if name in _BINARY_FEATURES:
            _binary(value, name, row_index)
    if (features["Protocol"], features["TCP"], features["UDP"]) not in ((6, 1, 0), (17, 0, 1)):
        raise ContractError(f"row {row_index}: unsupported protocol/transport flags")
    return features


def parse_legacy_csv(data: bytes, format: LegacyFormat) -> LegacyCSV:
    """Read verified headers strictly; never reindex, pad or infer missing fields."""
    if not isinstance(data, bytes) or not isinstance(format, LegacyFormat):
        raise ContractError("expected CSV bytes and a supported LegacyFormat")
    try:
        reader = csv.reader(io.StringIO(data.decode("utf-8-sig"), newline=""), strict=True)
        header = next(reader, None)
        expected = EXTRACTOR_COLUMNS if format is LegacyFormat.EXTRACTOR_CSV else PREDICTION_COLUMNS
        if header is None or tuple(header) != expected:
            raise ContractError("incompatible CSV header: require exact verified columns and order")
        rows = []
        for row_index, cells in enumerate(reader):
            if len(cells) != len(expected):
                raise ContractError(f"row {row_index}: wrong number of fields")
            values = tuple(_decimal(cell, field, row_index) for field, cell in zip(expected, cells))
            numeric = dict(zip(expected, values))
            features = _features(numeric, row_index)
            label = _binary(numeric["Label"], "Label", row_index)
            score = decision = None
            if format is LegacyFormat.OFFLINE_PREDICTION_CSV:
                raw_score = numeric["pred_proba"]
                if not 0 <= raw_score <= 1:
                    raise ContractError(f"row {row_index}: pred_proba outside [0, 1]")
                score = float(raw_score)
                decision = _binary(numeric["pred"], "pred", row_index)
                if decision != int(score >= 0.5):
                    raise ContractError(f"row {row_index}: pred disagrees with legacy threshold 0.5")
            rows.append(LegacyRow(row_index, MappingProxyType(features), label,
                                  tuple(str(value) for value in values[:len(EXTRACTOR_COLUMNS)]), score, decision))
    except (UnicodeDecodeError, csv.Error) as error:
        raise ContractError(f"invalid UTF-8 CSV: {error}") from error
    if not rows:
        raise ContractError("legacy CSV has no observations")
    return LegacyCSV(format, hashlib.sha256(data).hexdigest(), tuple(rows))


def read_legacy_csv(path: str | Path, format: LegacyFormat) -> LegacyCSV:
    return parse_legacy_csv(Path(path).read_bytes(), format)


@dataclass(frozen=True)
class ObservationBinding:
    row_index: int
    ordinal: int  # original acquisition occurrence; not inferred from CSV row index
    timestamp_ns: int
    clock_id: str
    artifact_sha256: str
    evidence_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        for name in ("row_index", "ordinal", "timestamp_ns"):
            _integer(getattr(self, name), name)
        _text(self.clock_id, "clock_id")
        _sha(self.artifact_sha256)
        _strings(self.evidence_ids, "evidence_ids", required=True)


@dataclass(frozen=True)
class PredictionBinding:
    row_index: int
    sample_id: str
    observation_artifact_sha256: str
    prediction_artifact_sha256: str
    model_sha256: str
    intake_ns: int
    features_ready_ns: int
    emitted_ns: int
    clock_id: str
    evidence_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        for name in ("row_index", "intake_ns", "features_ready_ns", "emitted_ns"):
            _integer(getattr(self, name), name)
        _text(self.sample_id, "sample_id")
        _text(self.clock_id, "clock_id")
        for name in ("observation_artifact_sha256", "prediction_artifact_sha256", "model_sha256"):
            _sha(getattr(self, name))
        _strings(self.evidence_ids, "evidence_ids", required=True)
        if not self.intake_ns <= self.features_ready_ns <= self.emitted_ns:
            raise ContractError("prediction binding stages must be ordered")


@dataclass(frozen=True)
class LegacyAnnotation:
    run_id: str
    sample_id: str
    artifact_sha256: str
    row_index: int
    value: int
    interpretation: str = "untrusted legacy port-derived Label; not independent ground truth"
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        _version(self.schema_version)
        _text(self.run_id, "run_id")
        _text(self.sample_id, "sample_id")
        _sha(self.artifact_sha256)
        _integer(self.row_index, "row_index")
        _integer(self.value, "value")
        if self.value not in (0, 1):
            raise ContractError("legacy annotation must be binary")


@dataclass(frozen=True)
class ObservationImport:
    table: LegacyCSV
    observations: tuple[Observation, ...]
    truths: tuple[GroundTruth, ...]
    annotations: tuple[LegacyAnnotation, ...]
    bindings: tuple[ObservationBinding, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.table, LegacyCSV) or self.table.format is not LegacyFormat.EXTRACTOR_CSV:
            raise ContractError("observation import requires original extractor CSV")
        for name, record_type in (("observations", Observation), ("truths", GroundTruth),
                                  ("annotations", LegacyAnnotation), ("bindings", ObservationBinding)):
            records = getattr(self, name)
            if (not isinstance(records, tuple) or len(records) != len(self.table.rows)
                    or any(not isinstance(record, record_type) for record in records)):
                raise ContractError(f"{name} cardinality/type differs from original CSV")
        for row, observation, truth, annotation, binding in zip(
            self.table.rows, self.observations, self.truths, self.annotations, self.bindings
        ):
            if (observation.features != row.features or observation.ordinal != binding.ordinal
                    or observation.timestamp_ns != binding.timestamp_ns or observation.clock_id != binding.clock_id
                    or binding.row_index != row.row_index or binding.artifact_sha256 != self.table.sha256):
                raise ContractError("observation row/occurrence/timing binding mismatch")
            if (truth.run_id != observation.run_id or truth.sample_id != observation.sample_id
                    or truth.state is not Label.UNKNOWN or truth.provenance_ids
                    or truth.confirmed_event_ids or truth.candidate_event_ids):
                raise ContractError("legacy import truth must remain independently unassigned UNKNOWN")
            if (annotation.run_id != observation.run_id or annotation.sample_id != observation.sample_id
                    or annotation.row_index != row.row_index or annotation.artifact_sha256 != self.table.sha256
                    or annotation.value != row.legacy_label):
                raise ContractError("legacy annotation row/sample/artifact mismatch")


@dataclass(frozen=True)
class PredictionImport:
    table: LegacyCSV
    predictions: tuple[Prediction, ...]
    bindings: tuple[PredictionBinding, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.table, LegacyCSV) or self.table.format is not LegacyFormat.OFFLINE_PREDICTION_CSV:
            raise ContractError("prediction import requires offline prediction CSV")
        if (not isinstance(self.predictions, tuple) or not isinstance(self.bindings, tuple)
                or len(self.predictions) != len(self.table.rows) or len(self.bindings) != len(self.table.rows)):
            raise ContractError("prediction import cardinality differs from CSV")
        for row, prediction, binding in zip(self.table.rows, self.predictions, self.bindings):
            if not isinstance(prediction, Prediction) or not isinstance(binding, PredictionBinding):
                raise ContractError("invalid prediction import record types")
            if (prediction.sample_id != binding.sample_id or prediction.score != row.score
                    or prediction.threshold != 0.5 or binding.row_index != row.row_index
                    or binding.prediction_artifact_sha256 != self.table.sha256
                    or prediction.model_sha256 != binding.model_sha256
                    or prediction.clock_id != binding.clock_id
                    or (prediction.intake_ns, prediction.features_ready_ns, prediction.emitted_ns)
                       != (binding.intake_ns, binding.features_ready_ns, binding.emitted_ns)):
                raise ContractError("prediction import row/sample/model/timing mismatch")


def _bindings(records, expected_type, row_count):
    by_row = {}
    for record in records:
        if not isinstance(record, expected_type):
            raise ContractError(f"expected {expected_type.__name__}")
        if record.row_index in by_row:
            raise ContractError("duplicate CSV row binding")
        by_row[record.row_index] = record
    if set(by_row) != set(range(row_count)):
        raise ContractError("missing or extra row identity/timing bindings; CSV alone is insufficient")
    return tuple(by_row[index] for index in range(row_count))


def import_observations(run: RunMetadata, table: LegacyCSV, source_id: str,
                        bindings=()) -> ObservationImport:
    """Convert only with externally recorded source identity and packet timestamps."""
    if not isinstance(run, RunMetadata) or not isinstance(table, LegacyCSV):
        raise ContractError("expected RunMetadata and parsed LegacyCSV")
    if table.format is not LegacyFormat.EXTRACTOR_CSV:
        raise ContractError("observations require the original extractor CSV")
    source = next((source for source in run.sources if source.source_id == source_id), None)
    if source is None:
        raise ContractError("source identity absent from run; cannot infer it from CSV")
    if source.sha256 != table.sha256:
        raise ContractError("CSV bytes differ from declared source artifact")
    bindings = _bindings(bindings, ObservationBinding, len(table.rows))
    observations, truths, annotations = [], [], []
    for row, binding in zip(table.rows, bindings):
        if binding.artifact_sha256 != table.sha256:
            raise ContractError("observation binding references a different artifact")
        sample_id = stable_sample_id(run.run_id, source.acquisition_id, binding.ordinal, Unit.PACKET)
        observations.append(Observation(run.run_id, source.source_id, source.acquisition_id,
                            binding.ordinal, sample_id, binding.timestamp_ns, binding.clock_id,
                            Unit.PACKET, row.features))
        truths.append(GroundTruth(run.run_id, sample_id, Label.UNKNOWN, (), ambiguity_reason=_UNKNOWN_REASON))
        annotations.append(LegacyAnnotation(run.run_id, sample_id, table.sha256, row.row_index, row.legacy_label))
    result = ObservationImport(table, tuple(observations), tuple(truths), tuple(annotations), bindings)
    # Reuse M0.1 duplicate, clock, interval and identity checks, without inferring truth.
    evaluate(run, result.observations, result.truths, (), ())
    return result


def import_predictions(run: RunMetadata, table: LegacyCSV, observations: ObservationImport,
                       bindings=()) -> PredictionImport:
    """Require copied-input alignment plus hash-bound occurrence/model/timing evidence."""
    if not isinstance(run, RunMetadata) or not isinstance(table, LegacyCSV) or not isinstance(observations, ObservationImport):
        raise ContractError("expected run, parsed prediction CSV and ObservationImport")
    if table.format is not LegacyFormat.OFFLINE_PREDICTION_CSV:
        raise ContractError("predictions require verified offline prediction CSV")
    if run.decision_threshold != 0.5:
        raise ContractError("legacy offline predictor uses fixed threshold 0.5")
    sources = {source.source_id: source for source in run.sources}
    for observation in observations.observations:
        source = sources.get(observation.source_id)
        if source is None or source.sha256 != observations.table.sha256:
            raise ContractError("original observation artifact absent or changed in run")
    if len(table.rows) != len(observations.table.rows):
        raise ContractError("prediction row count differs from observation CSV")
    bindings = _bindings(bindings, PredictionBinding, len(table.rows))
    predictions = []
    for row, original, observation, binding in zip(table.rows, observations.table.rows,
                                                 observations.observations, bindings):
        if tuple(map(Decimal, row.copied_values)) != tuple(map(Decimal, original.copied_values)):
            raise ContractError(f"row {row.row_index}: prediction copied-input alignment mismatch")
        if (binding.sample_id != observation.sample_id
                or binding.observation_artifact_sha256 != observations.table.sha256
                or binding.prediction_artifact_sha256 != table.sha256):
            raise ContractError("prediction binding occurrence/artifact alignment mismatch")
        predictions.append(Prediction(run.run_id, observation.sample_id, Unit.PACKET, row.score, 0.5,
                           binding.intake_ns, binding.features_ready_ns, binding.emitted_ns,
                           binding.clock_id, binding.model_sha256))
    result = PredictionImport(table, tuple(predictions), bindings)
    evaluate(run, observations.observations, observations.truths, result.predictions, ())
    return result
