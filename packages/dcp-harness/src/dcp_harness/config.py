"""Strict, language-neutral configuration for one prospective audit."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from dcp_harness.util import (
    HarnessError,
    explicit_text,
    finite_float,
    hash_json,
    load_json_object,
    positive_int,
    require_keys,
)


CONFIG_SCHEMA = "dcp_harness_config_v1"


@dataclass(frozen=True)
class AgentConfig:
    backend: str = "claude-code"
    execution: str = "docker"
    model: str = "claude-sonnet-4-5"
    accepted_model_ids: tuple[str, ...] = ()
    claude_binary: str = "claude"
    container_image: str = ""
    dotenv: str = ".env"
    effort: str = "high"
    max_budget_usd: float = 10.0
    timeout_seconds: int = 1800
    max_turns: int = 8
    memory_mb: int = 3072
    cpus: float = 2.0


@dataclass(frozen=True)
class WebConfig:
    enabled: bool = False
    allowed_hosts: tuple[str, ...] = ()
    allow_subdomains: bool = False
    max_requests: int = 20
    max_redirects: int = 3
    max_raw_bytes: int = 2_000_000
    max_delivered_bytes: int = 300_000
    timeout_seconds: int = 30


@dataclass(frozen=True)
class AuditConfig:
    grade: str = "core"
    challenger_episodes: int = 1
    positive_control_episodes: int = 1
    feedback_pairs: int = 2
    sham_pairs: int = 2
    max_feedback_pair_replacements: int = 0
    max_sham_pair_replacements: int = 0
    checkpoint_scope: str = "lineage_prefix"


@dataclass(frozen=True)
class HarnessConfig:
    schema: str
    claim_id: str
    source_workspace: str
    task_adapter: str
    task_options: dict[str, Any] = field(default_factory=dict)
    agent: AgentConfig = field(default_factory=AgentConfig)
    web: WebConfig = field(default_factory=WebConfig)
    audit: AuditConfig = field(default_factory=AuditConfig)
    config_path: str = field(default="", compare=False, repr=False)

    @property
    def path(self) -> Path:
        return Path(self.config_path)

    @property
    def base_dir(self) -> Path:
        return self.path.parent

    def resolve(self, value: str) -> Path:
        path = Path(value).expanduser()
        if not path.is_absolute():
            path = self.base_dir / path
        return path.resolve()

    def public_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value.pop("config_path", None)
        return value

    @property
    def config_hash(self) -> str:
        return hash_json(self.public_dict())


_ROOT_KEYS = {
    "schema",
    "claim_id",
    "source_workspace",
    "task_adapter",
    "task_options",
    "agent",
    "web",
    "audit",
}
_AGENT_KEYS = {
    "backend",
    "execution",
    "model",
    "accepted_model_ids",
    "claude_binary",
    "container_image",
    "dotenv",
    "effort",
    "max_budget_usd",
    "timeout_seconds",
    "max_turns",
    "memory_mb",
    "cpus",
}
_WEB_KEYS = {
    "enabled",
    "allowed_hosts",
    "allow_subdomains",
    "max_requests",
    "max_redirects",
    "max_raw_bytes",
    "max_delivered_bytes",
    "timeout_seconds",
}
_AUDIT_KEYS = {
    "grade",
    "challenger_episodes",
    "positive_control_episodes",
    "feedback_pairs",
    "sham_pairs",
    "max_feedback_pair_replacements",
    "max_sham_pair_replacements",
    "checkpoint_scope",
}


def _tuple_of_text(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise HarnessError(f"{label} must be a JSON array")
    items = tuple(explicit_text(item, f"{label}[]") for item in value)
    if len(set(items)) != len(items):
        raise HarnessError(f"{label} contains duplicates")
    return items


def _bool(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise HarnessError(f"{label} must be a boolean")
    return value


def load_config(path: str | Path) -> HarnessConfig:
    config_path = Path(path).expanduser().resolve()
    document = load_json_object(config_path)
    require_keys(
        document,
        allowed=_ROOT_KEYS,
        required={"schema", "claim_id", "source_workspace", "task_adapter"},
        label="config",
    )
    if document["schema"] != CONFIG_SCHEMA:
        raise HarnessError(f"config.schema must be {CONFIG_SCHEMA!r}")

    agent_doc = document.get("agent", {})
    web_doc = document.get("web", {})
    audit_doc = document.get("audit", {})
    for value, label, allowed in (
        (agent_doc, "agent", _AGENT_KEYS),
        (web_doc, "web", _WEB_KEYS),
        (audit_doc, "audit", _AUDIT_KEYS),
    ):
        if not isinstance(value, dict):
            raise HarnessError(f"config.{label} must be an object")
        require_keys(value, allowed=allowed, label=f"config.{label}")

    agent_defaults = AgentConfig()
    backend = explicit_text(agent_doc.get("backend", agent_defaults.backend), "agent.backend")
    if backend != "claude-code":
        raise HarnessError("agent.backend currently supports only 'claude-code'")
    execution = explicit_text(
        agent_doc.get("execution", agent_defaults.execution), "agent.execution"
    )
    if execution not in {"docker", "host"}:
        raise HarnessError("agent.execution must be docker|host")
    accepted = _tuple_of_text(
        agent_doc.get("accepted_model_ids", []), "agent.accepted_model_ids"
    )
    model = explicit_text(agent_doc.get("model", agent_defaults.model), "agent.model")
    if not accepted:
        accepted = (model,)
    container_image = str(agent_doc.get("container_image", ""))
    if execution == "docker" and not container_image.strip():
        raise HarnessError("agent.container_image is required in docker mode")
    agent = AgentConfig(
        backend=backend,
        execution=execution,
        model=model,
        accepted_model_ids=accepted,
        claude_binary=explicit_text(
            agent_doc.get("claude_binary", agent_defaults.claude_binary),
            "agent.claude_binary",
        ),
        container_image=container_image.strip(),
        dotenv=str(agent_doc.get("dotenv", agent_defaults.dotenv)),
        effort=explicit_text(
            agent_doc.get("effort", agent_defaults.effort), "agent.effort"
        ),
        max_budget_usd=finite_float(
            agent_doc.get("max_budget_usd", agent_defaults.max_budget_usd),
            "agent.max_budget_usd",
            minimum=0.000001,
        ),
        timeout_seconds=positive_int(
            agent_doc.get("timeout_seconds", agent_defaults.timeout_seconds),
            "agent.timeout_seconds",
        ),
        max_turns=positive_int(
            agent_doc.get("max_turns", agent_defaults.max_turns),
            "agent.max_turns",
        ),
        memory_mb=positive_int(
            agent_doc.get("memory_mb", agent_defaults.memory_mb), "agent.memory_mb", minimum=512
        ),
        cpus=finite_float(
            agent_doc.get("cpus", agent_defaults.cpus), "agent.cpus", minimum=0.1
        ),
    )

    web_defaults = WebConfig()
    enabled = _bool(web_doc.get("enabled", web_defaults.enabled), "web.enabled")
    allowed_hosts = _tuple_of_text(web_doc.get("allowed_hosts", []), "web.allowed_hosts")
    if enabled and not allowed_hosts:
        raise HarnessError("web.allowed_hosts cannot be empty when Web is enabled")
    web = WebConfig(
        enabled=enabled,
        allowed_hosts=allowed_hosts,
        allow_subdomains=_bool(
            web_doc.get("allow_subdomains", web_defaults.allow_subdomains),
            "web.allow_subdomains",
        ),
        max_requests=positive_int(
            web_doc.get("max_requests", web_defaults.max_requests), "web.max_requests"
        ),
        max_redirects=positive_int(
            web_doc.get("max_redirects", web_defaults.max_redirects),
            "web.max_redirects",
            minimum=0,
        ),
        max_raw_bytes=positive_int(
            web_doc.get("max_raw_bytes", web_defaults.max_raw_bytes), "web.max_raw_bytes"
        ),
        max_delivered_bytes=positive_int(
            web_doc.get("max_delivered_bytes", web_defaults.max_delivered_bytes),
            "web.max_delivered_bytes",
        ),
        timeout_seconds=positive_int(
            web_doc.get("timeout_seconds", web_defaults.timeout_seconds),
            "web.timeout_seconds",
        ),
    )
    if web.max_delivered_bytes > web.max_raw_bytes:
        raise HarnessError("web.max_delivered_bytes cannot exceed web.max_raw_bytes")

    audit_defaults = AuditConfig()
    grade = explicit_text(audit_doc.get("grade", audit_defaults.grade), "audit.grade")
    if grade not in {"core", "evidence"}:
        raise HarnessError("audit.grade must be core|evidence")
    checkpoint_scope = explicit_text(
        audit_doc.get("checkpoint_scope", audit_defaults.checkpoint_scope),
        "audit.checkpoint_scope",
    )
    if checkpoint_scope not in {"lineage_empty", "lineage_prefix"}:
        raise HarnessError("audit.checkpoint_scope must be lineage_empty|lineage_prefix")
    audit = AuditConfig(
        grade=grade,
        challenger_episodes=positive_int(
            audit_doc.get("challenger_episodes", audit_defaults.challenger_episodes),
            "audit.challenger_episodes",
        ),
        positive_control_episodes=positive_int(
            audit_doc.get(
                "positive_control_episodes", audit_defaults.positive_control_episodes
            ),
            "audit.positive_control_episodes",
        ),
        feedback_pairs=positive_int(
            audit_doc.get("feedback_pairs", audit_defaults.feedback_pairs),
            "audit.feedback_pairs",
            minimum=2,
        ),
        sham_pairs=positive_int(
            audit_doc.get("sham_pairs", audit_defaults.sham_pairs),
            "audit.sham_pairs",
            minimum=2,
        ),
        max_feedback_pair_replacements=positive_int(
            audit_doc.get(
                "max_feedback_pair_replacements",
                audit_defaults.max_feedback_pair_replacements,
            ),
            "audit.max_feedback_pair_replacements",
            minimum=0,
        ),
        max_sham_pair_replacements=positive_int(
            audit_doc.get(
                "max_sham_pair_replacements",
                audit_defaults.max_sham_pair_replacements,
            ),
            "audit.max_sham_pair_replacements",
            minimum=0,
        ),
        checkpoint_scope=checkpoint_scope,
    )

    options = document.get("task_options", {})
    if not isinstance(options, dict):
        raise HarnessError("config.task_options must be an object")
    config = HarnessConfig(
        schema=CONFIG_SCHEMA,
        claim_id=explicit_text(document["claim_id"], "claim_id"),
        source_workspace=explicit_text(
            document["source_workspace"], "source_workspace"
        ),
        task_adapter=explicit_text(document["task_adapter"], "task_adapter"),
        task_options=dict(options),
        agent=agent,
        web=web,
        audit=audit,
        config_path=str(config_path),
    )
    source = config.resolve(config.source_workspace)
    if not source.is_dir():
        raise HarnessError(f"source_workspace does not exist: {source}")
    return config


def template() -> dict[str, Any]:
    return {
        "schema": CONFIG_SCHEMA,
        "claim_id": "example-claim-v1",
        "source_workspace": "workspace",
        "task_adapter": "task_adapter.py:adapter",
        "task_options": {},
        "agent": {
            "backend": "claude-code",
            "execution": "docker",
            "model": "claude-sonnet-4-5",
            "accepted_model_ids": ["claude-sonnet-4-5"],
            "claude_binary": "claude",
            "container_image": "your-claude-code-image@sha256:...",
            "dotenv": ".env",
            "effort": "high",
            "max_budget_usd": 10.0,
            "timeout_seconds": 1800,
            "max_turns": 8,
            "memory_mb": 3072,
            "cpus": 2.0,
        },
        "web": {
            "enabled": True,
            "allowed_hosts": ["example.org"],
            "allow_subdomains": False,
            "max_requests": 20,
            "max_redirects": 3,
            "max_raw_bytes": 2_000_000,
            "max_delivered_bytes": 300_000,
            "timeout_seconds": 30,
        },
        "audit": {
            "grade": "evidence",
            "challenger_episodes": 96,
            "positive_control_episodes": 45,
            "feedback_pairs": 30,
            "sham_pairs": 60,
            "max_feedback_pair_replacements": 2,
            "max_sham_pair_replacements": 2,
            "checkpoint_scope": "lineage_prefix",
        },
    }

