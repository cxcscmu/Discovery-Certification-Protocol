"""Trusted task boundary for a generic DCP audit."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from enum import Enum
import importlib
import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any

from dcp.registration import Registration
from dcp.types import Gate1Evidence, Gate2Evidence, Gate3Evidence, IntegrityEvidence

from dcp_harness.config import HarnessConfig
from dcp_harness.util import HarnessError, hash_file, hash_json


class Phase(str, Enum):
    MAIN = "main"
    CHALLENGE = "challenge"
    FEEDBACK_TRUTHFUL = "feedback_truthful"
    FEEDBACK_NEUTRAL = "feedback_neutral"
    SHAM_REFERENCE = "sham_reference"
    SHAM_PROPOSED = "sham_proposed"
    POSITIVE_CONTROL = "positive_control"


@dataclass(frozen=True)
class EpisodeContext:
    claim_id: str
    episode_id: str
    phase: Phase
    workspace: Path
    record_dir: Path
    run_root: Path
    ordinal: int
    pair_id: str = ""
    replacement_of: str = ""
    task_options: dict[str, Any] = field(default_factory=dict)

    @property
    def is_feedback_branch(self) -> bool:
        return self.phase in {
            Phase.FEEDBACK_TRUTHFUL,
            Phase.FEEDBACK_NEUTRAL,
        }

    @property
    def is_sham_branch(self) -> bool:
        return self.phase in {Phase.SHAM_REFERENCE, Phase.SHAM_PROPOSED}


@dataclass(frozen=True)
class EpisodeEvaluation:
    """Private-verifier output committed after the agent session is closed."""

    outcome: str
    validity: str = "unresolved"
    artifact_path: str = ""
    per_unit: tuple[float, ...] = ()
    unit_ids: tuple[str, ...] = ()
    utility: float | None = None
    reason: str = ""

    def __post_init__(self) -> None:
        if self.outcome not in {
            "artifact",
            "model_failure",
            "execution_contract_violation",
            "infrastructure_invalid",
            "unresolved",
        }:
            raise ValueError(f"unknown episode outcome: {self.outcome!r}")
        if self.validity not in {"valid", "invalid", "unresolved"}:
            raise ValueError(f"unknown validity value: {self.validity!r}")
        if len(self.per_unit) != len(self.unit_ids):
            raise ValueError("per_unit and unit_ids must have equal lengths")
        if self.outcome == "artifact" and not self.artifact_path:
            raise ValueError("an artifact outcome must identify artifact_path")
        if self.outcome != "artifact" and (
            self.artifact_path
            or self.per_unit
            or self.unit_ids
            or self.utility is not None
        ):
            raise ValueError("a non-artifact outcome cannot carry artifact data")
        if not isinstance(self.reason, str):
            raise ValueError("evaluation reason must be a string")


@dataclass(frozen=True)
class RunView:
    """Read-only audit record exposed to the trusted evidence assembler."""

    root: Path
    config: HarnessConfig
    registration: Registration
    state: dict[str, Any]
    contracts: dict[str, Any]
    source_manifest: dict[str, Any]
    web_manifest: dict[str, Any]
    episodes: tuple[dict[str, Any], ...]
    event_head: str

    def by_phase(self, phase: Phase) -> tuple[dict[str, Any], ...]:
        return tuple(item for item in self.episodes if item.get("phase") == phase.value)

    def episode(self, episode_id: str) -> dict[str, Any]:
        matches = [item for item in self.episodes if item.get("episode_id") == episode_id]
        if len(matches) != 1:
            raise HarnessError(f"expected exactly one episode named {episode_id!r}")
        return matches[0]


@dataclass(frozen=True)
class EvidencePackage:
    registration: Registration
    integrity: IntegrityEvidence
    gate1: Gate1Evidence
    gate2: Gate2Evidence
    gate3: Gate3Evidence | None = None


@dataclass(frozen=True)
class AuditMaterials:
    """Prospective digests for task code, private data, and feedback policies."""

    private_verifier_hash: str
    private_unit_manifest_hash: str
    baseline_policy_hash: str
    truthful_feedback_policy_hash: str
    neutral_feedback_policy_hash: str
    sham_reference_policy_hash: str

    def __post_init__(self) -> None:
        for name, value in asdict(self).items():
            digest = (
                value.removeprefix("sha256:")
                if isinstance(value, str)
                else ""
            )
            if (
                not isinstance(value, str)
                or len(digest) != 64
                or value != value.lower()
            ):
                raise ValueError(f"audit material {name} must be a sha256 digest")
            try:
                int(digest, 16)
            except ValueError as exc:
                raise ValueError(
                    f"audit material {name} must be a sha256 digest"
                ) from exc


@dataclass(frozen=True)
class RegistrationContext:
    """Prospective inputs available before any research outcome exists."""

    config: HarnessConfig
    contracts: dict[str, Any]
    source_manifest: dict[str, Any]
    interface_hash: str
    adapter_identity_hash: str
    audit_materials: AuditMaterials


class BaseTaskAdapter(ABC):
    """The small trusted surface that makes a research task auditable.

    The harness owns model execution, actions, snapshots, randomization, and
    ledgers. The adapter owns task semantics. In particular it prepares each
    workspace, executes a registered experiment, applies truthful or neutral
    feedback according to ``context.phase``, evaluates a committed artifact on
    private units, and converts the recorded run into kernel evidence.
    """

    def __init__(self, options: dict[str, Any] | None = None) -> None:
        self.options = dict(options or {})

    @abstractmethod
    def audit_materials(self) -> AuditMaterials:
        """Hash the private verifier, held-out units, and branch policies."""

    @abstractmethod
    def registration(self, context: RegistrationContext) -> Registration:
        """Return every scientific/statistical choice before the main run."""

    @abstractmethod
    def prepare_episode(self, context: EpisodeContext) -> None:
        """Populate task files before the first model action."""

    @abstractmethod
    def prompt(self, context: EpisodeContext) -> str:
        """Return the phase-specific task prompt."""

    @abstractmethod
    def handle_experiment(
        self, context: EpisodeContext, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Return the observation allowed by this registered branch policy."""

    @abstractmethod
    def evaluate(self, context: EpisodeContext) -> EpisodeEvaluation:
        """Run the private verifier after the model session has ended."""

    @abstractmethod
    def baseline(self, main_context: EpisodeContext) -> EpisodeEvaluation:
        """Evaluate the frozen public baseline on the same private units."""

    @abstractmethod
    def select_checkpoint(self, main_episode: dict[str, Any]) -> int:
        """Select a preregistered checkpoint ordinal from the captured main run."""

    @abstractmethod
    def build_evidence(self, run: RunView) -> EvidencePackage:
        """Map immutable run records to the strict DCP kernel evidence objects."""

    def validate_action(
        self, context: EpisodeContext, payload: dict[str, Any]
    ) -> None:
        """Optionally reject an experiment before it is executed."""

    def adapter_identity(self) -> dict[str, Any]:
        return {
            "class": f"{type(self).__module__}.{type(self).__qualname__}",
            "options_hash": hash_json(self.options),
        }


@dataclass(frozen=True)
class LoadedAdapter:
    adapter: BaseTaskAdapter
    locator: str
    source_path: str
    source_hash: str
    identity_hash: str
    audit_materials: AuditMaterials
    audit_materials_hash: str


def _load_module(config: HarnessConfig, module_text: str) -> tuple[ModuleType, str, str]:
    looks_like_path = module_text.endswith(".py") or "/" in module_text or "\\" in module_text
    if looks_like_path:
        source = config.resolve(module_text)
        if not source.is_file() or source.is_symlink():
            raise HarnessError(f"task adapter must be a regular Python file: {source}")
        module_name = "dcp_task_adapter_" + hash_file(source).split(":", 1)[1][:16]
        spec = importlib.util.spec_from_file_location(module_name, source)
        if spec is None or spec.loader is None:
            raise HarnessError(f"cannot load task adapter: {source}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module, str(source), hash_file(source)
    module = importlib.import_module(module_text)
    source_text = getattr(module, "__file__", None)
    if not source_text:
        raise HarnessError("task adapter module has no auditable source file")
    source = Path(source_text).resolve()
    if not source.is_file() or source.is_symlink():
        raise HarnessError("task adapter module source is not a regular file")
    return module, str(source), hash_file(source)


def load_adapter(config: HarnessConfig) -> LoadedAdapter:
    if ":" not in config.task_adapter:
        raise HarnessError("task_adapter must use 'module:object' or 'file.py:object'")
    module_text, object_name = config.task_adapter.rsplit(":", 1)
    if not module_text or not object_name or "." in object_name:
        raise HarnessError("task_adapter object name must be a direct module attribute")
    module, source_path, source_hash = _load_module(config, module_text)
    if not hasattr(module, object_name):
        raise HarnessError(f"task adapter object {object_name!r} was not found")
    candidate = getattr(module, object_name)
    if isinstance(candidate, type) and issubclass(candidate, BaseTaskAdapter):
        adapter = candidate(config.task_options)
    elif isinstance(candidate, BaseTaskAdapter):
        if config.task_options:
            raise HarnessError(
                "task_options require an adapter class; an existing instance was supplied"
            )
        adapter = candidate
    else:
        raise HarnessError("task_adapter must name a BaseTaskAdapter instance or class")
    try:
        materials = adapter.audit_materials()
    except Exception as exc:
        raise HarnessError(
            f"task adapter could not seal its audit materials: {type(exc).__name__}: {exc}"
        ) from exc
    if not isinstance(materials, AuditMaterials):
        raise HarnessError("task adapter audit_materials() must return AuditMaterials")
    materials_document = asdict(materials)
    identity = {
        "schema": "dcp_task_adapter_identity_v1",
        "locator": config.task_adapter,
        "source_hash": source_hash,
        "audit_materials": materials_document,
        "audit_materials_hash": hash_json(materials_document),
        **adapter.adapter_identity(),
    }
    return LoadedAdapter(
        adapter=adapter,
        locator=config.task_adapter,
        source_path=source_path,
        source_hash=source_hash,
        identity_hash=hash_json(identity),
        audit_materials=materials,
        audit_materials_hash=hash_json(materials_document),
    )
