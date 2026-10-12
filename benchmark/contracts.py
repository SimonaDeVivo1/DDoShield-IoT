"""Validated immutable records and provenance checks for benchmark v0.1.1."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, fields, is_dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping

from . import SCHEMA_VERSION


class ContractError(ValueError):
    """A record or collection violates the benchmark contract."""


class Unit(str, Enum):
    PACKET = "packet"
    FLOW = "flow"
    WINDOW = "window"


class Label(str, Enum):
    BENIGN = "benign"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


class Split(str, Enum):
    TRAIN = "train"
    VALIDATION = "validation"
    TEST = "test"


def _text(value: str, name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ContractError(f"{name} must be a nonempty string")


def _integer(value: int, name: str) -> None:
    if type(value) is not int or value < 0:
        raise ContractError(f"{name} must be a nonnegative integer")


def _version(version: str) -> None:
    if version != SCHEMA_VERSION:
        raise ContractError(f"unsupported schema version: {version!r}")


def _enum(value: Enum, enum_type: type[Enum], name: str) -> None:
    if not isinstance(value, enum_type):
        raise ContractError(f"{name} must be a {enum_type.__name__}")


def _strings(values: tuple[str, ...], name: str, required: bool = False) -> None:
    if not isinstance(values, tuple):
        raise ContractError(f"{name} must be a tuple")
    for value in values:
        _text(value, name)
    if len(set(values)) != len(values) or (required and not values):
        raise ContractError(f"{name} must contain unique identifiers; required={required}")


def _sha(value: str) -> None:
    if not isinstance(value, str) or len(value) != 64 or any(
        c not in "0123456789abcdef" for c in value
    ):
        raise ContractError("artifact hash must be lowercase SHA-256 hex")


def _score(value: float, name: str) -> None:
    if type(value) not in (float, int) or not math.isfinite(value) or not 0 <= value <= 1:
        raise ContractError(f"{name} must be finite and within [0, 1]")


def _freeze(value: Any) -> Any:
    """Snapshot JSON-compatible settings so callers cannot mutate a record."""
    if isinstance(value, Mapping):
        for key in value:
            _text(key, "configuration key")
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    if value is None or type(value) in (str, bool, int):
        return value
    if type(value) is float and math.isfinite(value):
        return value
    raise ContractError("settings must contain finite JSON-compatible values")


def _settings(record: Any, name: str, required: bool = True) -> None:
    value = getattr(record, name)
    if not isinstance(value, Mapping) or (required and not value):
        raise ContractError(f"{name} must be a {'nonempty ' if required else ''}mapping")
    object.__setattr__(record, name, _freeze(value))


def to_json(record: Any) -> str:
    """Canonical JSON for hashing/export; intentionally no unsafe deserialization."""
    def plain(value: Any) -> Any:
        if isinstance(value, Enum):
            return value.value
        if is_dataclass(value) and not isinstance(value, type):
            return {field.name: plain(getattr(value, field.name)) for field in fields(value)}
        if isinstance(value, Mapping):
            return {key: plain(item) for key, item in value.items()}
        if isinstance(value, (tuple, list)):
            return [plain(item) for item in value]
        return value

    return json.dumps(plain(record), sort_keys=True, separators=(",", ":"), allow_nan=False)


def stable_sample_id(run_id: str, acquisition_id: str, ordinal: int, unit: Unit) -> str:
    """Identity is a canonical acquisition occurrence, never content or an alias."""
    _text(run_id, "run_id")
    _text(acquisition_id, "acquisition_id")
    _integer(ordinal, "ordinal")
    _enum(unit, Unit, "unit")
    encoded = json.dumps([run_id, acquisition_id, ordinal, unit.value], separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class SourceArtifact:
    source_id: str  # run-local import name; aliases explicitly point to a canonical source
    acquisition_id: str  # globally stable acquisition identity, independent of bytes
    sha256: str  # complete artifact content identity; not packet occurrence identity
    uri: str
    root_acquisition_ids: tuple[str, ...]  # all shared underlying observation ancestry
    alias_of: str | None = None
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        _version(self.schema_version)
        _text(self.source_id, "source_id")
        _text(self.acquisition_id, "acquisition_id")
        _text(self.uri, "uri")
        _sha(self.sha256)
        _strings(self.root_acquisition_ids, "root_acquisition_ids", required=True)
        if self.alias_of is not None:
            _text(self.alias_of, "alias_of")
            if self.alias_of == self.source_id:
                raise ContractError("source alias cannot refer to itself")


def _validate_sources(sources: tuple[SourceArtifact, ...]) -> None:
    if not isinstance(sources, tuple) or not sources or any(
        not isinstance(source, SourceArtifact) for source in sources
    ):
        raise ContractError("sources must be a nonempty tuple of SourceArtifact records")
    by_id = {source.source_id: source for source in sources}
    if len(by_id) != len(sources):
        raise ContractError("duplicate source_id in run")
    canonical = [source for source in sources if source.alias_of is None]
    if len({source.acquisition_id for source in canonical}) != len(canonical):
        raise ContractError("an acquisition must have exactly one canonical source")
    for source in sources:
        if source.alias_of is None:
            continue
        target = by_id.get(source.alias_of)
        if target is None or target.alias_of is not None:
            raise ContractError("alias must refer directly to an existing canonical source")
        if (source.acquisition_id != target.acquisition_id or source.sha256 != target.sha256
                or set(source.root_acquisition_ids) != set(target.root_acquisition_ids)):
            raise ContractError("alias acquisition, content or lineage differs from canonical source")


@dataclass(frozen=True)
class RunMetadata:
    experiment_id: str
    run_id: str
    scenario_id: str
    random_seed: int
    split: Split
    start_ns: int
    end_ns: int
    clock_id: str
    sources: tuple[SourceArtifact, ...]
    model_sha256: str
    decision_threshold: float
    network: Mapping[str, Any]
    traffic: Mapping[str, Any]
    attack_scenario: Mapping[str, Any]
    ids: Mapping[str, Any]
    software: Mapping[str, Any]
    hardware: Mapping[str, Any]
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        _version(self.schema_version)
        for name in ("experiment_id", "run_id", "scenario_id", "clock_id"):
            _text(getattr(self, name), name)
        for name in ("random_seed", "start_ns", "end_ns"):
            _integer(getattr(self, name), name)
        if self.end_ns <= self.start_ns:
            raise ContractError("run end must follow start")
        _enum(self.split, Split, "split")
        _sha(self.model_sha256)
        _score(self.decision_threshold, "decision_threshold")
        _validate_sources(self.sources)
        for name in ("network", "traffic", "attack_scenario", "ids", "software", "hardware"):
            _settings(self, name)


@dataclass(frozen=True)
class Observation:
    run_id: str
    source_id: str
    acquisition_id: str
    ordinal: int
    sample_id: str
    timestamp_ns: int
    clock_id: str
    unit: Unit
    features: Mapping[str, Any]
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        _version(self.schema_version)
        _integer(self.timestamp_ns, "timestamp_ns")
        _text(self.source_id, "source_id")
        _text(self.clock_id, "clock_id")
        expected = stable_sample_id(self.run_id, self.acquisition_id, self.ordinal, self.unit)
        if self.sample_id != expected:
            raise ContractError("sample_id does not match its stable source occurrence")
        _settings(self, "features", required=False)
        # Dedicated fields belong in separate truth/provenance records, not observations.
        forbidden = {"label", "ground_truth", "attack_event_ids", "confirmed_event_ids",
                     "candidate_event_ids", "provenance_ids", "split"}
        if forbidden.intersection(key.lower() for key in self.features):
            raise ContractError("ground truth or partition metadata in observable features")


@dataclass(frozen=True)
class AttackEvent:
    run_id: str
    event_id: str
    actor_ids: tuple[str, ...]
    attack_family: str
    start_ns: int
    end_ns: int
    clock_id: str
    evidence_ids: tuple[str, ...]  # independent execution evidence, not IDS output
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        _version(self.schema_version)
        for name in ("run_id", "event_id", "attack_family", "clock_id"):
            _text(getattr(self, name), name)
        _strings(self.actor_ids, "actor_ids", required=True)
        _strings(self.evidence_ids, "evidence_ids", required=True)
        _integer(self.start_ns, "start_ns")
        _integer(self.end_ns, "end_ns")
        if self.end_ns <= self.start_ns:
            raise ContractError("event end must follow start")


@dataclass(frozen=True)
class TrafficProvenance:
    run_id: str
    provenance_id: str
    actor_id: str
    state: Label
    evidence_ids: tuple[str, ...]
    confirmed_event_ids: tuple[str, ...] = ()
    candidate_event_ids: tuple[str, ...] = ()
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        _version(self.schema_version)
        for name in ("run_id", "provenance_id", "actor_id"):
            _text(getattr(self, name), name)
        _enum(self.state, Label, "state")
        _strings(self.evidence_ids, "evidence_ids", required=True)
        _event_associations(self.confirmed_event_ids, self.candidate_event_ids)
        if self.state is Label.MALICIOUS and not self.confirmed_event_ids:
            raise ContractError("malicious provenance requires attack event membership")
        if self.state is Label.UNKNOWN and self.confirmed_event_ids:
            raise ContractError("unknown provenance cannot confirm attack membership")
        if self.state is Label.BENIGN and (self.confirmed_event_ids or self.candidate_event_ids):
            raise ContractError("benign provenance cannot claim confirmed or candidate attacks")


def _event_associations(confirmed: tuple[str, ...], candidates: tuple[str, ...]) -> None:
    _strings(confirmed, "confirmed_event_ids")
    _strings(candidates, "candidate_event_ids")
    if set(confirmed).intersection(candidates):
        raise ContractError("confirmed and candidate event associations must be disjoint")


@dataclass(frozen=True)
class GroundTruth:
    run_id: str
    sample_id: str
    state: Label
    provenance_ids: tuple[str, ...]
    confirmed_event_ids: tuple[str, ...] = ()
    candidate_event_ids: tuple[str, ...] = ()
    ambiguity_reason: str | None = None
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        _version(self.schema_version)
        _text(self.run_id, "run_id")
        _text(self.sample_id, "sample_id")
        _enum(self.state, Label, "state")
        _strings(self.provenance_ids, "provenance_ids", required=self.state is not Label.UNKNOWN)
        _event_associations(self.confirmed_event_ids, self.candidate_event_ids)
        if self.state is Label.UNKNOWN:
            _text(self.ambiguity_reason, "ambiguity_reason")
            if self.confirmed_event_ids:
                raise ContractError("unknown truth cannot confirm attack membership")
        elif self.ambiguity_reason is not None:
            raise ContractError("known truth cannot carry an ambiguity reason")
        if self.state is Label.MALICIOUS and not self.confirmed_event_ids:
            raise ContractError("malicious truth requires event membership")
        if self.state is Label.BENIGN and (self.confirmed_event_ids or self.candidate_event_ids):
            raise ContractError("benign truth cannot claim confirmed or candidate attacks")


@dataclass(frozen=True)
class Prediction:
    run_id: str
    sample_id: str
    unit: Unit
    score: float                  # malicious-class score in [0, 1], not necessarily calibrated
    threshold: float
    intake_ns: int
    features_ready_ns: int
    emitted_ns: int
    clock_id: str
    model_sha256: str
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        _version(self.schema_version)
        for name in ("run_id", "sample_id", "clock_id"):
            _text(getattr(self, name), name)
        _enum(self.unit, Unit, "unit")
        _sha(self.model_sha256)
        for name in ("score", "threshold"):
            _score(getattr(self, name), name)
        for name in ("intake_ns", "features_ready_ns", "emitted_ns"):
            _integer(getattr(self, name), name)
        if not self.intake_ns <= self.features_ready_ns <= self.emitted_ns:
            raise ContractError("prediction stages must be time ordered")

    @property
    def decision(self) -> Label:
        return Label.MALICIOUS if self.score >= self.threshold else Label.BENIGN


def validate_partitions(runs: tuple[RunMetadata, ...]) -> None:
    """Reject shared acquisitions/ancestry across splits, not equal packet contents."""
    seen_runs: set[str] = set()
    owners: dict[str, Split] = {}
    definitions: dict[str, tuple[str, frozenset[str]]] = {}
    for run in runs:
        if not isinstance(run, RunMetadata):
            raise ContractError("partitions require RunMetadata records")
        if run.run_id in seen_runs:
            raise ContractError(f"duplicate run_id: {run.run_id}")
        seen_runs.add(run.run_id)
        for source in run.sources:
            definition = (source.sha256, frozenset(source.root_acquisition_ids))
            if source.acquisition_id in definitions and definitions[source.acquisition_id] != definition:
                raise ContractError("acquisition has inconsistent content or lineage across runs")
            definitions[source.acquisition_id] = definition
            keys = (source.acquisition_id, *source.root_acquisition_ids)
            for key in keys:
                if key in owners and owners[key] is not run.split:
                    raise ContractError(f"source provenance crosses partitions: {key}")
                owners[key] = run.split


@dataclass(frozen=True)
class ExperimentMetadata:
    experiment_id: str
    protocol_version: str
    split_policy: str
    runs: tuple[RunMetadata, ...]
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        _version(self.schema_version)
        for name in ("experiment_id", "protocol_version", "split_policy"):
            _text(getattr(self, name), name)
        if not isinstance(self.runs, tuple) or not self.runs:
            raise ContractError("experiment requires a nonempty tuple of runs")
        validate_partitions(self.runs)
        if any(run.experiment_id != self.experiment_id for run in self.runs):
            raise ContractError("run belongs to a different experiment")
