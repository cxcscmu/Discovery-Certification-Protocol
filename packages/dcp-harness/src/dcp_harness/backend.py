"""Claude Code CLI backend with a file-only, audit-visible interface."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time
from types import MappingProxyType
from typing import Any, Protocol
import uuid

from dcp_harness.config import HarnessConfig
from dcp_harness.util import (
    HarnessError,
    hash_file,
    hash_json,
    redact_environment_value,
    utc_now,
    write_json,
)


ALLOWED_FILE_TOOLS = ("Read", "Write", "Edit", "Glob", "Grep")
FORBIDDEN_TOOLS = frozenset({"Bash", "WebSearch", "WebFetch", "Task"})
SECRET_NAMES = (
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "ANTHROPIC_BASE_URL",
)


@dataclass(frozen=True)
class AgentRunResult:
    run_id: str
    returncode: int
    timed_out: bool
    started_at: str
    finished_at: str
    elapsed_seconds: float
    requested_model: str
    init_models: tuple[str, ...]
    assistant_models: tuple[str, ...]
    usage_models: tuple[str, ...]
    declared_tools: tuple[str, ...]
    used_tools: tuple[str, ...]
    event_count: int
    assistant_event_count: int
    result_event_count: int
    result_text: str
    reported_cost_usd: float | None
    provider_session_id: str
    assistant_message_ids: tuple[str, ...]
    result_event_uuid: str
    stdout_hash: str
    stderr_hash: str
    provider_receipt_hash: str
    identity_complete: bool
    identity_ok: bool
    interface_ok: bool
    model_action_started: bool
    infrastructure_invalid_preaction: bool
    stdout_path: str
    stderr_path: str

    @property
    def execution_ok(self) -> bool:
        return bool(
            self.returncode == 0
            and not self.timed_out
            and self.identity_ok
            and self.interface_ok
        )


class AgentBackend(Protocol):
    @property
    def interface_identity(self) -> dict[str, Any]: ...

    @property
    def interface_hash(self) -> str: ...

    def run(
        self,
        *,
        workspace: Path,
        prompt: str,
        record_dir: Path,
        episode_id: str,
    ) -> AgentRunResult: ...

    def doctor(self) -> dict[str, Any]: ...


class RecordedBackend:
    """Offline identity view used by status and finalization only."""

    def __init__(self, interface_identity: dict[str, Any]) -> None:
        self._identity = dict(interface_identity)

    @property
    def interface_identity(self) -> dict[str, Any]:
        return dict(self._identity)

    @property
    def interface_hash(self) -> str:
        return hash_json(self._identity)

    def doctor(self) -> dict[str, Any]:
        return {
            "ok": True,
            "offline_recorded_identity": True,
            "interface_hash": self.interface_hash,
        }

    def run(self, **kwargs: Any) -> AgentRunResult:
        del kwargs
        raise HarnessError("the recorded backend cannot start model sessions")


def _load_dotenv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip().rstrip("\r")
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[7:]
        name, value = line.split("=", 1)
        name = name.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        if name:
            values[name] = value
    return values


class ClaudeCodeBackend:
    def __init__(self, config: HarnessConfig, *, run_root: Path) -> None:
        self.config = config
        self.agent = config.agent
        self.run_root = run_root.resolve()
        frozen_dir = self.run_root / "registration" / "agent"
        frozen_dir.mkdir(parents=True, exist_ok=True)
        if frozen_dir.is_symlink():
            raise HarnessError("frozen agent directory cannot be a symbolic link")
        self.cli_binary = frozen_dir / "claude"
        if self.cli_binary.is_symlink():
            raise HarnessError("frozen Claude CLI cannot be a symbolic link")
        if self.cli_binary.exists():
            if not self.cli_binary.is_file():
                raise HarnessError("frozen Claude CLI is not a regular file")
        else:
            resolved_binary = shutil.which(self.agent.claude_binary)
            if resolved_binary is None:
                candidate = config.resolve(self.agent.claude_binary)
                if candidate.is_file():
                    resolved_binary = str(candidate)
            if resolved_binary is None:
                raise HarnessError(
                    f"Claude CLI was not found: {self.agent.claude_binary}"
                )
            source_binary = Path(resolved_binary).resolve()
            if not source_binary.is_file() or source_binary.is_symlink():
                raise HarnessError("Claude CLI must resolve to a regular file")
            shutil.copyfile(source_binary, self.cli_binary)
            self.cli_binary.chmod(0o500)
            if hash_file(self.cli_binary) != hash_file(source_binary):
                raise HarnessError("Claude CLI snapshot copy failed verification")
        self.cli_hash = hash_file(self.cli_binary)

        self.image_id = "host-process-developmental"
        if self.agent.execution == "docker":
            if shutil.which("docker") is None:
                raise HarnessError("Docker is required for agent.execution=docker")
            completed = subprocess.run(
                [
                    "docker",
                    "image",
                    "inspect",
                    self.agent.container_image,
                    "--format",
                    "{{.Id}}",
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if completed.returncode != 0 or not completed.stdout.strip().startswith("sha256:"):
                raise HarnessError(
                    f"Docker image cannot be resolved: {self.agent.container_image}"
                )
            self.image_id = completed.stdout.strip()

        process_env = dict(os.environ)
        dotenv = _load_dotenv(config.resolve(self.agent.dotenv))
        child_env: dict[str, str] = {
            "PATH": process_env.get("PATH", ""),
            "HOME": process_env.get("HOME", str(Path.home())),
            "LANG": process_env.get("LANG", "C.UTF-8"),
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        }
        for name in SECRET_NAMES:
            value = process_env.get(name) or dotenv.get(name)
            if value:
                child_env[name] = value
        self._child_env = MappingProxyType(child_env)
        self.version = self._version()
        self._interface_identity = {
            "schema": "dcp_claude_code_interface_v1",
            "backend": "claude-code",
            "execution": self.agent.execution,
            "requested_model": self.agent.model,
            "accepted_model_ids": list(self.agent.accepted_model_ids),
            "claude_cli_version": self.version,
            "claude_cli_hash": self.cli_hash,
            "container_image_id": self.image_id,
            "private_isolation_pass": self.agent.execution == "docker",
            "allowed_tools": list(ALLOWED_FILE_TOOLS),
            "forbidden_tools": sorted(FORBIDDEN_TOOLS),
            "shell_available_to_agent": False,
            "live_web_tool_available_to_agent": False,
            "api_environment": [
                (
                    redact_environment_value(name, child_env.get(name))
                    if name == "ANTHROPIC_BASE_URL"
                    else {"name": name, "present": bool(child_env.get(name))}
                )
                for name in SECRET_NAMES
            ],
        }

    @property
    def interface_identity(self) -> dict[str, Any]:
        return dict(self._interface_identity)

    @property
    def interface_hash(self) -> str:
        return hash_json(self._interface_identity)

    def _version(self) -> str:
        completed = subprocess.run(
            [str(self.cli_binary), "--version"],
            capture_output=True,
            text=True,
            timeout=30,
            env=dict(self._child_env),
            check=False,
        )
        if completed.returncode != 0 or not completed.stdout.strip():
            raise HarnessError("Claude CLI version check failed")
        return completed.stdout.strip()

    def doctor(self) -> dict[str, Any]:
        return {
            "backend": "claude-code",
            "execution": self.agent.execution,
            "claude_cli_version": self.version,
            "claude_cli_hash": self.cli_hash,
            "container_image_id": self.image_id,
            "interface_hash": self.interface_hash,
            "credentials": {
                name: bool(self._child_env.get(name)) for name in SECRET_NAMES
            },
            "certifying_isolation_available": self.agent.execution == "docker",
            "ok": bool(
                self._child_env.get("ANTHROPIC_API_KEY")
                or self._child_env.get("ANTHROPIC_AUTH_TOKEN")
            ),
        }

    def _command(self, workspace: Path, container_name: str) -> list[str]:
        tools = ",".join(ALLOWED_FILE_TOOLS)
        cli_args = [
            "-p",
            "--model",
            self.agent.model,
            "--effort",
            self.agent.effort,
            "--output-format",
            "stream-json",
            "--verbose",
            "--no-session-persistence",
            "--bare",
            "--strict-mcp-config",
            "--mcp-config",
            '{"mcpServers":{}}',
            "--tools",
            tools,
            "--allowedTools",
            tools,
            "--disallowedTools",
            ",".join(sorted(FORBIDDEN_TOOLS)),
            "--permission-mode",
            "bypassPermissions",
            "--max-budget-usd",
            f"{self.agent.max_budget_usd:.6f}",
        ]
        if self.agent.execution == "host":
            return [str(self.cli_binary), *cli_args]
        command = [
            "docker",
            "run",
            "--rm",
            "-i",
            "--name",
            container_name,
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "--workdir",
            "/workspace",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--pids-limit",
            "256",
            "--memory",
            f"{self.agent.memory_mb}m",
            "--cpus",
            f"{self.agent.cpus:.2f}",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,size=512m",
            "--tmpfs",
            f"/home/agent:rw,nosuid,nodev,size=256m,uid={os.getuid()},gid={os.getgid()}",
            "-e",
            "HOME=/home/agent",
            "-v",
            f"{workspace.resolve()}:/workspace:rw",
            "-v",
            f"{self.cli_binary}:/usr/local/bin/dcp-claude:ro",
        ]
        for name in (*SECRET_NAMES, "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"):
            if self._child_env.get(name):
                command.extend(["-e", name])
        return [*command, self.image_id, "/usr/local/bin/dcp-claude", *cli_args]

    def run(
        self,
        *,
        workspace: Path,
        prompt: str,
        record_dir: Path,
        episode_id: str,
    ) -> AgentRunResult:
        if hash_file(self.cli_binary) != self.cli_hash:
            raise HarnessError("Claude CLI changed after registration")
        workspace = workspace.resolve()
        record_dir.mkdir(parents=True, exist_ok=True)
        stdout_path = record_dir / "claude_stream.jsonl"
        stderr_path = record_dir / "claude_stderr.log"
        container_name = "dcp-harness-" + uuid.uuid4().hex[:18]
        command = self._command(workspace, container_name)
        started_at = utc_now()
        start = time.monotonic()
        timed_out = False
        cwd = workspace if self.agent.execution == "host" else None
        with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=stdout,
                stderr=stderr,
                cwd=cwd,
                env=dict(self._child_env),
                start_new_session=True,
            )
            try:
                process.communicate(
                    prompt.encode("utf-8"), timeout=self.agent.timeout_seconds
                )
            except subprocess.TimeoutExpired:
                timed_out = True
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                if self.agent.execution == "docker":
                    subprocess.run(
                        ["docker", "rm", "-f", container_name],
                        capture_output=True,
                        timeout=30,
                        check=False,
                        env=dict(self._child_env),
                    )
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=10)
        finished_at = utc_now()
        parsed = _parse_stream(stdout_path)
        observed_models = set(parsed["init_models"]) | set(parsed["assistant_models"]) | set(
            parsed["usage_models"]
        )
        accepted = set(self.agent.accepted_model_ids)
        identity_complete = bool(
            parsed["init_event_count"] > 0
            and parsed["assistant_event_count"] > 0
            and parsed["result_event_count"] > 0
            and observed_models
        )
        identity_ok = bool(identity_complete and observed_models <= accepted)
        declared_tools = set(parsed["declared_tools"])
        used_tools = set(parsed["used_tools"])
        interface_ok = bool(
            declared_tools <= set(ALLOWED_FILE_TOOLS)
            and used_tools <= set(ALLOWED_FILE_TOOLS)
            and not (used_tools & FORBIDDEN_TOOLS)
        )
        model_action_started = bool(parsed["assistant_event_count"] or used_tools)
        infrastructure_invalid_preaction = bool(
            process.returncode != 0 and not model_action_started and not identity_complete
        )
        receipt = {
            "schema": "dcp_provider_execution_receipt_v1",
            "episode_id": episode_id,
            "provider_session_id": parsed["provider_session_id"],
            "assistant_message_ids": parsed["assistant_message_ids"],
            "result_event_uuid": parsed["result_event_uuid"],
            "stdout_hash": hash_file(stdout_path),
            "stderr_hash": hash_file(stderr_path),
            "identity_complete": identity_complete,
            "identity_ok": identity_ok,
            "interface_ok": interface_ok,
        }
        result = AgentRunResult(
            run_id="claude-" + uuid.uuid4().hex[:16],
            returncode=int(process.returncode),
            timed_out=timed_out,
            started_at=started_at,
            finished_at=finished_at,
            elapsed_seconds=time.monotonic() - start,
            requested_model=self.agent.model,
            init_models=tuple(parsed["init_models"]),
            assistant_models=tuple(parsed["assistant_models"]),
            usage_models=tuple(parsed["usage_models"]),
            declared_tools=tuple(parsed["declared_tools"]),
            used_tools=tuple(parsed["used_tools"]),
            event_count=int(parsed["event_count"]),
            assistant_event_count=int(parsed["assistant_event_count"]),
            result_event_count=int(parsed["result_event_count"]),
            result_text=str(parsed["result_text"]),
            reported_cost_usd=parsed["reported_cost_usd"],
            provider_session_id=str(parsed["provider_session_id"]),
            assistant_message_ids=tuple(parsed["assistant_message_ids"]),
            result_event_uuid=str(parsed["result_event_uuid"]),
            stdout_hash=receipt["stdout_hash"],
            stderr_hash=receipt["stderr_hash"],
            provider_receipt_hash=hash_json(receipt),
            identity_complete=identity_complete,
            identity_ok=identity_ok,
            interface_ok=interface_ok,
            model_action_started=model_action_started,
            infrastructure_invalid_preaction=infrastructure_invalid_preaction,
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
        )
        write_json(record_dir / "agent_result.json", asdict(result))
        return result


def _parse_stream(path: Path) -> dict[str, Any]:
    values: dict[str, Any] = {
        "event_count": 0,
        "init_event_count": 0,
        "assistant_event_count": 0,
        "result_event_count": 0,
        "init_models": set(),
        "assistant_models": set(),
        "usage_models": set(),
        "declared_tools": set(),
        "used_tools": set(),
        "result_text": "",
        "reported_cost_usd": None,
        "provider_session_ids": set(),
        "assistant_message_ids": set(),
        "result_event_uuids": set(),
    }
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(item, dict):
            continue
        values["event_count"] += 1
        session_id = item.get("session_id")
        if isinstance(session_id, str) and session_id:
            values["provider_session_ids"].add(session_id)
        if item.get("type") == "system" and item.get("subtype") == "init":
            values["init_event_count"] += 1
            if isinstance(item.get("model"), str):
                values["init_models"].add(item["model"])
            tools = item.get("tools")
            if isinstance(tools, list):
                values["declared_tools"].update(
                    tool for tool in tools if isinstance(tool, str)
                )
        if item.get("type") == "assistant":
            values["assistant_event_count"] += 1
            message = item.get("message")
            if not isinstance(message, dict):
                message = {}
            if isinstance(message.get("model"), str) and message["model"] != "<synthetic>":
                values["assistant_models"].add(message["model"])
            if isinstance(message.get("id"), str):
                values["assistant_message_ids"].add(message["id"])
            content = message.get("content")
            if isinstance(content, list):
                for block in content:
                    if (
                        isinstance(block, dict)
                        and block.get("type") == "tool_use"
                        and isinstance(block.get("name"), str)
                    ):
                        values["used_tools"].add(block["name"])
        if item.get("type") == "result":
            values["result_event_count"] += 1
            if isinstance(item.get("result"), str):
                values["result_text"] = item["result"]
            if isinstance(item.get("total_cost_usd"), (int, float)):
                values["reported_cost_usd"] = float(item["total_cost_usd"])
            if isinstance(item.get("uuid"), str):
                values["result_event_uuids"].add(item["uuid"])
            usage = item.get("modelUsage")
            if isinstance(usage, dict):
                values["usage_models"].update(str(name) for name in usage)
    for key in (
        "init_models",
        "assistant_models",
        "usage_models",
        "declared_tools",
        "used_tools",
        "assistant_message_ids",
    ):
        values[key] = sorted(values[key])
    session_ids = sorted(values.pop("provider_session_ids"))
    result_uuids = sorted(values.pop("result_event_uuids"))
    values["provider_session_id"] = session_ids[0] if len(session_ids) == 1 else ""
    values["result_event_uuid"] = result_uuids[0] if len(result_uuids) == 1 else ""
    return values
