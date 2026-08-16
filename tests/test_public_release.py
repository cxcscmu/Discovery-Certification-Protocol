from __future__ import annotations

import json
import hashlib
from pathlib import Path

import pytest

import dcp
from dcp import cli
from dcp.api import verify_bundle


REPO_ROOT = Path(__file__).resolve().parents[1]
PUBLIC_EXAMPLES = {
    "sqlite-web": {
        "bundle_id": (
            "sha256:"
            "eff6cf27afa58da58fc2591fff3be9116c0ee0fe896dc9f60a8c51376e504846"
        ),
        "certificate_digest": (
            "sha256:"
            "c64e0d650b69fdafd9f504fe650a271695b81a2a1ac366a9f4696ea5d3f59e4b"
        ),
        "core": "certified",
        "evidence": "certified",
    },
    "virtual-catalyst": {
        "bundle_id": (
            "sha256:"
            "fa17603f2184bb7b6a9a2432baa48766847fe27a4edcebd887697ccacfcaf1c2"
        ),
        "certificate_digest": (
            "sha256:"
            "cdab48b505c3685dd42d8c4a5a5fae14b853deccedb71359f72fa30c6b613fe9"
        ),
        "core": "certified",
        "evidence": "certified",
    },
    "sqlite-core": {
        "bundle_id": (
            "sha256:"
            "3690bebc8b3ac882ab17ad0f8a61b05ea630443dbc85e36965eabf27e1f1bbca"
        ),
        "certificate_digest": (
            "sha256:"
            "8b014c7a2a1f486461585fd5c87c33c5b698d194a98ff7389e80636eb69f79d8"
        ),
        "core": "certified",
        "evidence": "not_tested",
    },
    "device-calibration-core": {
        "bundle_id": (
            "sha256:"
            "dff7b57b062362e036fb26e7da94959e7d4900e5007b839e43e5fa107a507945"
        ),
        "certificate_digest": (
            "sha256:"
            "06b407d740d9b974d6a0b4637ff3f7ea12a394d49bf3535bcfb1e99bcd3a253b"
        ),
        "core": "certified",
        "evidence": "not_tested",
    },
}


@pytest.mark.parametrize(("name", "expected"), PUBLIC_EXAMPLES.items())
def test_public_examples_replay_exactly(
    name: str,
    expected: dict[str, str],
) -> None:
    bundle = REPO_ROOT / "examples" / "audits" / name
    report = verify_bundle(bundle)
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))

    assert report["ok"] is True
    assert report["manifest_valid"] is True
    assert report["payload_hashes_valid"] is True
    assert report["kernel_replay_matches"] is True
    assert report["saved_verdict"] == report["replayed_verdict"]
    assert report["replayed_verdict"]["core"] == expected["core"]
    assert report["replayed_verdict"]["evidence"] == expected["evidence"]
    assert report["formal_certificate_issued"] is False
    assert report["bundle_id"] == expected["bundle_id"]
    assert (
        manifest["payloads"]["certificate"]["content_digest"]
        == expected["certificate_digest"]
    )


def test_public_python_api_is_the_bundle_verifier() -> None:
    from dcp.bundle import verify_bundle as kernel_verify_bundle

    assert verify_bundle is kernel_verify_bundle


def test_public_example_index_links_paper_records_to_bundles() -> None:
    index = json.loads(
        (REPO_ROOT / "examples" / "audit-index.json").read_text(
            encoding="utf-8"
        )
    )
    assert index["schema"] == "dcp-public-audit-index-v1"
    records = {record["name"]: record for record in index["examples"]}
    assert set(records) == set(PUBLIC_EXAMPLES)

    for name, expected in PUBLIC_EXAMPLES.items():
        record = records[name]
        bundle = REPO_ROOT / record["bundle_path"]
        certificate = json.loads(
            (bundle / "payload" / "certificate.json").read_text(
                encoding="utf-8"
            )
        )
        encoded = json.dumps(
            certificate,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        object_digest = "sha256:" + hashlib.sha256(encoded).hexdigest()

        assert record["publication_bundle_id"] == expected["bundle_id"]
        assert (
            record["certificate_payload_digest"]
            == expected["certificate_digest"]
        )
        assert record["certificate_object_digest"] == object_digest
        assert record["expected_core"] == expected["core"]
        assert record["expected_evidence"] == expected["evidence"]

    assert records["sqlite-web"]["canonical_record"] == {
        "type": "dcp_reference_certificate_v1",
        "id": (
            "sha256:"
            "b3f0af47968ba2cb82afa0506deb14f32b58449ff6887039c8e015c1cfde6a3d"
        ),
    }


def test_public_cli_json_is_the_complete_verifier_report(capsys: pytest.CaptureFixture[str]) -> None:
    bundle = REPO_ROOT / "examples" / "audits" / "sqlite-web"

    return_code = cli.main(["verify", str(bundle), "--json"])
    output = capsys.readouterr()

    assert return_code == 0
    assert output.err == ""
    assert json.loads(output.out) == verify_bundle(bundle)


def test_public_cli_default_is_a_short_verified_summary(
    capsys: pytest.CaptureFixture[str],
) -> None:
    bundle = REPO_ROOT / "examples" / "audits" / "virtual-catalyst"

    return_code = cli.main(["verify", str(bundle)])
    output = capsys.readouterr()

    assert return_code == 0
    assert output.err == ""
    assert "Replay: VERIFIED" in output.out
    assert "Core: certified" in output.out
    assert "Evidence: certified" in output.out
    assert PUBLIC_EXAMPLES["virtual-catalyst"]["bundle_id"] in output.out
    assert "Formal issuance: no" in output.out


def test_public_cli_hides_untrusted_decisions_on_failure(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    report = {
        "ok": False,
        "bundle_id": "sha256:untrusted",
        "saved_verdict": {"core": "certified", "evidence": "certified"},
        "replayed_verdict": {"core": "certified", "evidence": "certified"},
        "errors": ["saved certificate does not match a fresh kernel replay"],
    }
    monkeypatch.setattr(cli, "verify_bundle", lambda _path: report)

    return_code = cli.main(["verify", "untrusted-bundle"])
    output = capsys.readouterr()

    assert return_code == 1
    assert "Replay: FAILED" in output.out
    assert "Decision: unavailable" in output.out
    assert "certified" not in output.out


def test_public_cli_exit_zero_means_replay_not_certification(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    report = {
        "ok": True,
        "bundle_id": "sha256:valid-replay",
        "bundle_profile": "full_audit_v1",
        "replayed_verdict": {
            "core": "refuted",
            "evidence": "inconclusive",
        },
        "provenance_scope": "local_content_addressed_only",
        "formal_certificate_issued": False,
        "errors": [],
    }
    monkeypatch.setattr(cli, "verify_bundle", lambda _path: report)

    return_code = cli.main(["verify", "valid-refutation"])
    output = capsys.readouterr()

    assert return_code == 0
    assert "Core: refuted" in output.out
    assert "Evidence: inconclusive" in output.out


def test_public_cli_version_and_usage_exit_codes(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as version_exit:
        cli.main(["--version"])
    assert version_exit.value.code == 0
    assert capsys.readouterr().out.strip() == f"dcp {dcp.__version__}"

    with pytest.raises(SystemExit) as usage_exit:
        cli.main(["verify"])
    assert usage_exit.value.code == 2
