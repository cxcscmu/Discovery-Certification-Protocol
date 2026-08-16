from __future__ import annotations

import json
from pathlib import Path

import pytest

from dcp_harness.actions import read_action
from dcp_harness.backend import _parse_stream
from dcp_harness.util import HarnessError, write_json
from dcp_harness.web import WebPolicy, canonicalize_url
from dcp_harness.workspace import manifest


def test_claude_stream_parser_binds_identity_tools_and_receipts(tmp_path: Path):
    path = tmp_path / "stream.jsonl"
    events = [
        {
            "type": "system",
            "subtype": "init",
            "session_id": "session-1",
            "model": "model-1",
            "tools": ["Read", "Write"],
        },
        {
            "type": "assistant",
            "session_id": "session-1",
            "message": {
                "id": "message-1",
                "model": "model-1",
                "content": [
                    {"type": "tool_use", "name": "Write", "input": {}}
                ],
            },
        },
        {
            "type": "result",
            "session_id": "session-1",
            "uuid": "result-1",
            "result": "done",
            "total_cost_usd": 0.25,
            "modelUsage": {"model-1": {}},
        },
    ]
    path.write_text(
        "\n".join(json.dumps(event) for event in events) + "\n",
        encoding="utf-8",
    )
    parsed = _parse_stream(path)
    assert parsed["provider_session_id"] == "session-1"
    assert parsed["assistant_message_ids"] == ["message-1"]
    assert parsed["result_event_uuid"] == "result-1"
    assert parsed["init_models"] == ["model-1"]
    assert parsed["assistant_models"] == ["model-1"]
    assert parsed["usage_models"] == ["model-1"]
    assert parsed["declared_tools"] == ["Read", "Write"]
    assert parsed["used_tools"] == ["Write"]


def test_multiple_provider_sessions_are_not_collapsed(tmp_path: Path):
    path = tmp_path / "stream.jsonl"
    path.write_text(
        json.dumps({"type": "system", "subtype": "init", "session_id": "a"})
        + "\n"
        + json.dumps({"type": "result", "session_id": "b", "uuid": "r"})
        + "\n",
        encoding="utf-8",
    )
    assert _parse_stream(path)["provider_session_id"] == ""


def test_workspace_symbolic_links_are_rejected(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = tmp_path / "private.txt"
    target.write_text("private\n", encoding="utf-8")
    (workspace / "escape").symlink_to(target)
    with pytest.raises(HarnessError, match="symlink"):
        manifest(workspace)


def test_web_policy_rejects_unregistered_or_unsafe_urls():
    policy = WebPolicy(
        enabled=True,
        allowed_hosts=("docs.example",),
        allow_subdomains=False,
        max_requests=2,
        max_redirects=1,
        max_raw_bytes=1000,
        max_delivered_bytes=500,
        timeout_seconds=5,
    )
    assert canonicalize_url("https://docs.example/a", policy) == (
        "https://docs.example/a"
    )
    for value in (
        "http://docs.example/a",
        "https://user:pass@docs.example/a",
        "https://docs.example:444/a",
        "https://other.example/a",
    ):
        with pytest.raises(HarnessError):
            canonicalize_url(value, policy)


def test_action_schema_rejects_extra_fields(tmp_path: Path):
    channel = tmp_path / ".dcp"
    channel.mkdir()
    write_json(
        channel / "action.json",
        {
            "schema": "dcp_action_v1",
            "action": "finish",
            "payload": {},
            "unregistered": True,
        },
    )
    with pytest.raises(HarnessError, match="unknown keys"):
        read_action(tmp_path)

