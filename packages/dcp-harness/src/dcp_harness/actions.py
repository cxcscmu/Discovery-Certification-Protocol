"""The only audited action channel exposed to the research agent."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dcp_harness.util import HarnessError, load_json_object, require_keys


ACTION_SCHEMA = "dcp_action_v1"
ACTION_PATH = Path(".dcp/action.json")
OBSERVATION_PATH = Path(".dcp/observation.json")
MAX_ACTION_BYTES = 128 * 1024


@dataclass(frozen=True)
class Action:
    kind: str
    payload: dict[str, Any]
    raw: dict[str, Any]


def instructions(*, live_web: bool, replay_web: bool) -> str:
    web_text = (
        "Web requests are available through the audited action channel."
        if live_web
        else "Only exact replay of URLs in WEB_PRIVILEGED.json is available."
        if replay_web
        else "No Web requests are available in this episode."
    )
    return f"""# DCP audited action channel

Work only inside this workspace. Bash, direct Web tools, and subagents are not
part of the registered interface. {web_text}

When you need one external action, write `.dcp/action.json` with exactly one of
these strict JSON objects and end the session.

```json
{{"schema":"{ACTION_SCHEMA}","action":"web_fetch","payload":{{"schema":"dcp_web_request_v1","requests":[{{"request_id":"doc-1","query":"what you seek","url":"https://allowed.example/page"}}]}}}}
```

```json
{{"schema":"{ACTION_SCHEMA}","action":"experiment","payload":{{"task-defined":"request"}}}}
```

When the final artifact has been committed to the path required by the task,
write the following object and end the session.

```json
{{"schema":"{ACTION_SCHEMA}","action":"finish","payload":{{}}}}
```

The next isolated session will receive `.dcp/observation.json`. One session may
commit only one action. Private evaluation results are never returned here.
"""


def read_action(workspace: Path) -> Action:
    path = workspace / ACTION_PATH
    if not path.is_file() or path.is_symlink():
        raise HarnessError("agent did not commit a regular .dcp/action.json")
    if path.stat().st_size > MAX_ACTION_BYTES:
        raise HarnessError("agent action exceeds the 128 KiB limit")
    document = load_json_object(path)
    require_keys(
        document,
        allowed={"schema", "action", "payload"},
        required={"schema", "action", "payload"},
        label="agent action",
    )
    if document["schema"] != ACTION_SCHEMA:
        raise HarnessError(f"agent action schema must be {ACTION_SCHEMA!r}")
    kind = document["action"]
    if kind not in {"web_fetch", "experiment", "finish"}:
        raise HarnessError("agent action must be web_fetch|experiment|finish")
    payload = document["payload"]
    if not isinstance(payload, dict):
        raise HarnessError("agent action payload must be a JSON object")
    if kind == "finish" and payload:
        raise HarnessError("finish action payload must be empty")
    return Action(kind=kind, payload=dict(payload), raw=document)

