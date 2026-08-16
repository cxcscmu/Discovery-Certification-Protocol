from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

from dcp import (
    IntegrityEvidence,
    Registration,
    adequacy_evidence_hash,
    artifact_results_hash,
    branch_result_hash,
    evaluate,
    feedback_pairs_manifest_hash,
    gate3_neutral_recovery_ledger_manifest_hash,
    gate3_neutral_scope_manifest_hash,
    private_results_manifest_hash,
    recovery_ledger_manifest_hash,
    sham_pairs_manifest_hash,
    unit_manifest_hash,
)
from dcp.bundle import (
    BundleError,
    FULL_AUDIT_PROFILE,
    verify_bundle,
    verify_core_bundle,
    verify_full_audit_bundle,
    write_core_bundle,
    write_full_audit_bundle,
)
from dcp.types import (
    AdequacyEvidence,
    ArtifactScores,
    BranchOutcome,
    ControlAttempt,
    FeedbackPair,
    Gate1Evidence,
    Gate2Evidence,
    Gate3Evidence,
    RawAttemptOutcome,
    ShamCalibration,
    ShamPair,
    Validity,
)


UNIT_IDS = tuple(f"private-{index}" for index in range(20))


def _bundle_inputs():
    reg = Registration(
        claim_id="bundle-roundtrip",
        audit_family_id="bundle-family-v1",
        model_id="model:test-v1",
        interface_hash="sha256:interface",
        task_family_profile="synthetic-optimizer-v1",
        inference_scope="exhaustive_finite_set",
        ci_method="finite_set_exact",
        delta_min=0.10,
        kappa=0.5,
        m_max=1,
        min_n_ind=1,
        gate2_control_contract_hash="sha256:gate2-control-contract",
        challenge_distribution_hash="sha256:challenge-QB",
        audit_slot_id="audit-slot-001",
        audit_slot_reservation_receipt_hash="sha256:alpha-ledger-receipt",
        notes={"bundle_test": True, "language_neutral": "json"},
    )
    astar = ArtifactScores(
        name="A*",
        per_unit=[0.90] * len(UNIT_IDS),
        validity=Validity.VALID,
        artifact_hash="sha256:astar",
        unit_ids=UNIT_IDS,
    )
    baseline = ArtifactScores(
        name="baseline",
        per_unit=[0.60] * len(UNIT_IDS),
        validity=Validity.VALID,
        artifact_hash="sha256:baseline",
        unit_ids=UNIT_IDS,
    )
    gate1 = Gate1Evidence(astar=astar, baseline=baseline)
    control = ControlAttempt(
        attempt_id="challenge-001",
        outcome=RawAttemptOutcome.ARTIFACT,
        per_unit=[0.90] * len(UNIT_IDS),
        validity=Validity.VALID,
        artifact_hash="sha256:control-001",
        unit_ids=UNIT_IDS,
        stratum="matched",
        scope_contract_hash=reg.gate2_control_contract_hash,
        prestart_contract_receipt_hash="sha256:prestart-001",
        challenge_distribution_hash=reg.challenge_distribution_hash,
        independent_draw_receipt_hash="sha256:draw-001",
        independent_unit_id="draw-001",
        independence_ok=True,
        infrastructure_outcome_independent=True,
    )
    adequacy = AdequacyEvidence(
        matched_model_present=True,
        materials_readable=True,
        opportunity_floor_met=True,
        health_audit_pass=True,
        positive_control_successes=99,
        positive_control_trials=100,
        calibration_id="positive-controls-v1",
    )
    adequacy.checks_manifest_hash = adequacy_evidence_hash(adequacy)
    gate2 = Gate2Evidence(controls=(control,), adequacy=adequacy)
    verifier_hash = "sha256:verifier-v1"
    integrity = IntegrityEvidence(
        registration_frozen=True,
        claim_frozen=True,
        provenance_pass=True,
        iterative_lineage_eligible=True,
        lineage_dataflow_audit_pass=True,
        challenger_contract_pass=True,
        private_isolation_pass=True,
        symmetric_verifier_pass=True,
        inference_assumptions_pass=True,
        feedback_inference_assumptions_pass=True,
        sham_inference_assumptions_pass=True,
        familywise_budget_audit_pass=True,
        astar_hash=astar.artifact_hash,
        baseline_hash=baseline.artifact_hash,
        verifier_hash=verifier_hash,
        astar_results_hash=artifact_results_hash(astar),
        baseline_results_hash=artifact_results_hash(baseline),
        private_unit_manifest_hash=unit_manifest_hash(UNIT_IDS),
        private_results_manifest_hash=private_results_manifest_hash(
            astar, baseline, verifier_hash
        ),
        p_hash="sha256:P",
        resource_contract_hash="sha256:resource-contract",
        selection_rule_hash="sha256:selection-rule",
        k_manifest_hash="sha256:K",
        e0_manifest_hash="sha256:E0",
        lineage_manifest_hash="sha256:L-star",
        observed_web_manifest_hash="sha256:W-obs-none",
        challenger_policy_hash="sha256:challenger-policy",
        opportunity_contract_hash="sha256:opportunity-contract",
        recovery_ledger_complete=True,
        recovery_ledger_manifest_hash=recovery_ledger_manifest_hash(gate2.controls),
        gate2_recovery_ledger_manifest_hash=recovery_ledger_manifest_hash(
            gate2.controls
        ),
        claim_family_manifest_hash="sha256:claim-family",
        alpha_ledger_receipt_hash="sha256:alpha-ledger-receipt",
        audit_slot_registry_entry_hash="sha256:audit-slot-registry-entry",
        human_assistance="none",
        attribution_subject="autonomous_agent",
        web_access_used=False,
        web_replay_scope="not_used",
    )
    certificate = evaluate(reg, gate1, gate2, integrity=integrity)
    return reg, integrity, gate1, gate2, certificate


def _full_bundle_inputs():
    base_reg, base_integrity, gate1, gate2, _certificate = _bundle_inputs()
    reg = replace(
        base_reg,
        grade_requested="evidence",
        m_max=5,
        feedback_estimand="binary",
        feedback_utility_mapping="canonical_p_wrapper_v1",
        feedback_ci_method="paired_binary_exact",
        sham_ci_method="paired_binary_exact",
        registered_n_feedback_pairs=2,
        registered_n_sham_pairs=2,
        scaffold_hash="sha256:scaffold",
        feedback_schema_hash="sha256:feedback-schema",
        sham_operator_hash="sha256:sham-operator",
        utility_scale_id="utility:binary:v1",
        sham_calibration_id="sham-calibration-v1",
        gate3_checkpoint_scope="lineage_prefix",
        gate3_paired_arm_contract_hash="sha256:gate3-paired-contract",
        gate3_truthful_arm_contract_hash="sha256:gate3-truthful-contract",
        gate3_neutral_arm_contract_hash="sha256:gate3-neutral-contract",
        gate3_neutral_recovery_contract_hash="sha256:gate3-recovery-contract",
        gate3_checkpoint_selection_rule_hash=base_integrity.selection_rule_hash,
        gate3_resource_contract_hash="sha256:gate3-resource-contract",
        gate3_opportunity_contract_hash="sha256:gate3-opportunity-contract",
        gate3_branch_policy_hash="sha256:gate3-branch-policy",
        truthful_feedback_generator_hash="sha256:truthful-generator",
        neutral_sham_generator_hash="sha256:sham-operator",
        gate3_pair_randomization_distribution_hash="sha256:feedback-pair-Q",
        sham_randomization_distribution_hash="sha256:sham-pair-Q",
        sham_paired_arm_contract_hash="sha256:sham-paired-contract",
        sham_reference_arm_contract_hash="sha256:sham-reference-contract",
        sham_proposed_arm_contract_hash="sha256:sham-proposed-contract",
        reference_null_generator_hash="sha256:reference-null-generator",
    )

    feedback_pairs = []
    for index in range(reg.registered_n_feedback_pairs):
        truthful = BranchOutcome(
            outcome=RawAttemptOutcome.ARTIFACT,
            validity=Validity.VALID,
            branch_id=f"truthful-{index}",
            artifact_hash=f"sha256:truthful-artifact-{index}",
            execution_contract_hash=reg.gate3_truthful_arm_contract_hash,
            prestart_contract_receipt_hash=f"sha256:truthful-prestart-{index}",
            per_unit=[0.90] * len(UNIT_IDS),
            unit_ids=UNIT_IDS,
        )
        truthful.verifier_result_hash = branch_result_hash(truthful)
        neutral = BranchOutcome(
            outcome=RawAttemptOutcome.ARTIFACT,
            validity=Validity.VALID,
            branch_id=f"neutral-{index}",
            artifact_hash=f"sha256:neutral-artifact-{index}",
            execution_contract_hash=reg.gate3_neutral_arm_contract_hash,
            prestart_contract_receipt_hash=f"sha256:neutral-prestart-{index}",
            per_unit=[0.60] * len(UNIT_IDS),
            unit_ids=UNIT_IDS,
        )
        neutral.verifier_result_hash = branch_result_hash(neutral)
        feedback_pairs.append(
            FeedbackPair(
                pair_id=f"feedback-pair-{index}",
                truthful=truthful,
                neutral=neutral,
                block_id=f"feedback-block-{index}",
                randomization_distribution_hash=(
                    reg.gate3_pair_randomization_distribution_hash
                ),
                randomization_draw_receipt_hash=f"sha256:feedback-draw-{index}",
                assignment_frozen=True,
                independence_ok=True,
            )
        )

    sham_pairs = []
    for index in range(reg.registered_n_sham_pairs):
        reference = BranchOutcome(
            outcome=RawAttemptOutcome.ARTIFACT,
            utility=1.0,
            validity=Validity.VALID,
            branch_id=f"reference-null-{index}",
            artifact_hash=f"sha256:reference-artifact-{index}",
            execution_contract_hash=reg.sham_reference_arm_contract_hash,
            prestart_contract_receipt_hash=f"sha256:reference-prestart-{index}",
        )
        reference.verifier_result_hash = branch_result_hash(reference)
        proposed = BranchOutcome(
            outcome=RawAttemptOutcome.ARTIFACT,
            utility=1.0,
            validity=Validity.VALID,
            branch_id=f"proposed-sham-{index}",
            artifact_hash=f"sha256:proposed-artifact-{index}",
            execution_contract_hash=reg.sham_proposed_arm_contract_hash,
            prestart_contract_receipt_hash=f"sha256:proposed-prestart-{index}",
        )
        proposed.verifier_result_hash = branch_result_hash(proposed)
        sham_pairs.append(
            ShamPair(
                pair_id=f"sham-pair-{index}",
                reference_null=reference,
                proposed_sham=proposed,
                block_id=f"sham-block-{index}",
                randomization_distribution_hash=reg.sham_randomization_distribution_hash,
                randomization_draw_receipt_hash=f"sha256:sham-draw-{index}",
                assignment_frozen=True,
                independence_ok=True,
            )
        )

    sham = ShamCalibration(
        pairs=tuple(sham_pairs),
        calibration_id=reg.sham_calibration_id,
        development_manifest_hash="sha256:sham-development-cases",
        confirmatory_manifest_hash=sham_pairs_manifest_hash(sham_pairs),
        task_family_profile=reg.task_family_profile,
        model_id=reg.model_id,
        interface_hash=reg.interface_hash,
        scaffold_hash=reg.scaffold_hash,
        feedback_schema_hash=reg.feedback_schema_hash,
        operator_hash=reg.sham_operator_hash,
        reference_null_generator_hash=reg.reference_null_generator_hash,
        utility_scale_id=reg.utility_scale_id,
        paired_arm_contract_hash=reg.sham_paired_arm_contract_hash,
        reference_arm_contract_hash=reg.sham_reference_arm_contract_hash,
        proposed_arm_contract_hash=reg.sham_proposed_arm_contract_hash,
        contract_preseal_receipt_hash="sha256:sham-contract-preseal",
        contract_sealed_before_branches_pass=True,
        contract_sealed_event_index=10,
        first_branch_started_event_index=11,
        channel_checks_pass=True,
        freshness_pass=True,
        operator_frozen_before_confirmatory=True,
        development_confirmatory_disjoint=True,
        all_started_pairs_disclosed=True,
        no_pair_replacements=True,
        started_pair_count=len(sham_pairs),
    )
    gate3 = Gate3Evidence(
        pairs=tuple(feedback_pairs),
        sham=sham,
        neutral_adequacy=gate2.adequacy,
        design_checks_pass=True,
        stopping_rule_pass=True,
        registered_pairs_complete=True,
        all_started_pairs_disclosed=True,
        no_pair_replacements=True,
        paired_contract_audit_pass=True,
        truthful_channel_audit_pass=True,
        neutral_channel_audit_pass=True,
        started_pair_count=len(feedback_pairs),
        checkpoint_scope=reg.gate3_checkpoint_scope,
        checkpoint_hash="sha256:checkpoint",
        window_hash="sha256:window",
        feedback_pairs_manifest_hash=feedback_pairs_manifest_hash(feedback_pairs),
        paired_arm_contract_hash=reg.gate3_paired_arm_contract_hash,
        truthful_arm_contract_hash=reg.gate3_truthful_arm_contract_hash,
        neutral_arm_contract_hash=reg.gate3_neutral_arm_contract_hash,
        neutral_recovery_contract_hash=reg.gate3_neutral_recovery_contract_hash,
        truthful_feedback_generator_hash=reg.truthful_feedback_generator_hash,
        neutral_sham_generator_hash=reg.neutral_sham_generator_hash,
        contract_preseal_receipt_hash="sha256:gate3-contract-preseal",
        contract_sealed_before_branches_pass=True,
        contract_sealed_event_index=20,
        first_branch_started_event_index=21,
        neutral_model_id=reg.model_id,
        neutral_interface_hash=reg.interface_hash,
        neutral_resource_contract_hash=reg.gate3_resource_contract_hash,
        neutral_k_manifest_hash=base_integrity.k_manifest_hash,
        neutral_e0_manifest_hash=base_integrity.e0_manifest_hash,
        neutral_web_manifest_hash=base_integrity.observed_web_manifest_hash,
        neutral_opportunity_contract_hash=reg.gate3_opportunity_contract_hash,
        neutral_challenger_policy_hash=reg.gate3_branch_policy_hash,
        neutral_scope_audit_manifest_hash="pending",
    )
    gate3.neutral_scope_audit_manifest_hash = gate3_neutral_scope_manifest_hash(
        gate3, base_integrity.selection_rule_hash
    )
    integrity = replace(
        base_integrity,
        recovery_ledger_manifest_hash=recovery_ledger_manifest_hash(
            gate2.controls, gate3
        ),
        gate3_neutral_scope_manifest_hash=gate3.neutral_scope_audit_manifest_hash,
        gate3_neutral_recovery_ledger_manifest_hash=(
            gate3_neutral_recovery_ledger_manifest_hash(gate3)
        ),
        gate3_contract_preseal_receipt_hash=gate3.contract_preseal_receipt_hash,
        sham_contract_preseal_receipt_hash=sham.contract_preseal_receipt_hash,
    )
    certificate = evaluate(reg, gate1, gate2, gate3, integrity=integrity)
    return reg, integrity, gate1, gate2, gate3, certificate


def _canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _rehash_full_payload(root: Path, name: str) -> None:
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload_path = root / manifest["payloads"][name]["path"]
    raw = payload_path.read_bytes()
    manifest["payloads"][name]["content_digest"] = _digest(raw)
    manifest["payloads"][name]["size_bytes"] = len(raw)
    identity = {key: value for key, value in manifest.items() if key != "bundle_id"}
    manifest["bundle_id"] = _digest(_canonical_bytes(identity))
    manifest_path.write_bytes(_canonical_bytes(manifest))


def test_core_bundle_round_trip_and_replay(tmp_path: Path) -> None:
    reg, integrity, gate1, gate2, certificate = _bundle_inputs()
    manifest = write_core_bundle(
        tmp_path, reg, integrity, gate1, gate2, certificate
    )

    assert manifest["bundle_id"].startswith("sha256:")
    assert manifest["formal_certificate_issued"] is False
    assert set(manifest["payloads"]) == {
        "registration",
        "integrity",
        "gate1",
        "gate2",
        "certificate",
    }

    report = verify_core_bundle(tmp_path)
    assert report["ok"] is True
    assert report["manifest_valid"] is True
    assert report["payload_hashes_valid"] is True
    assert report["kernel_replay_matches"] is True
    assert report["provenance_scope"] == "local_content_addressed_only"
    assert report["formal_certificate_issued"] is False
    assert report["saved_verdict"] == certificate.to_dict()["verdict"]


def test_core_bundle_detects_payload_tampering(tmp_path: Path) -> None:
    write_core_bundle(tmp_path, *_bundle_inputs())
    registration_path = tmp_path / "payload" / "registration.json"
    payload = json.loads(registration_path.read_text(encoding="utf-8"))
    payload["claim_id"] = "tampered-claim"
    registration_path.write_text(json.dumps(payload), encoding="utf-8")

    report = verify_core_bundle(tmp_path)
    assert report["ok"] is False
    assert report["manifest_valid"] is True
    assert report["payload_hashes_valid"] is False
    assert report["kernel_replay_matches"] is False
    assert any("mismatch" in error for error in report["errors"])


def test_core_bundle_detects_a_content_addressed_but_wrong_certificate(
    tmp_path: Path,
) -> None:
    reg, integrity, gate1, gate2, certificate = _bundle_inputs()
    wrong_certificate = certificate.to_dict()
    wrong_certificate["verdict"]["core"] = "certified"
    write_core_bundle(
        tmp_path, reg, integrity, gate1, gate2, wrong_certificate
    )

    report = verify_core_bundle(tmp_path)
    assert report["manifest_valid"] is True
    assert report["payload_hashes_valid"] is True
    assert report["kernel_replay_matches"] is False
    assert report["ok"] is False
    assert any("kernel replay" in error for error in report["errors"])


def test_python_module_cli_verifies_bundle(tmp_path: Path) -> None:
    write_core_bundle(tmp_path, *_bundle_inputs())
    completed = subprocess.run(
        [sys.executable, "-m", "dcp", "verify", str(tmp_path)],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    report = json.loads(completed.stdout)
    assert report["ok"] is True
    assert report["formal_certificate_issued"] is False


def test_full_audit_bundle_round_trip_replays_gate3(tmp_path: Path) -> None:
    reg, integrity, gate1, gate2, gate3, certificate = _full_bundle_inputs()
    manifest = write_full_audit_bundle(
        tmp_path, reg, integrity, gate1, gate2, gate3, certificate
    )

    assert manifest["profile"] == FULL_AUDIT_PROFILE
    assert set(manifest["payloads"]) == {
        "registration",
        "integrity",
        "gate1",
        "gate2",
        "gate3",
        "certificate",
    }
    report = verify_full_audit_bundle(tmp_path)
    assert report["ok"] is True
    assert report["manifest_valid"] is True
    assert report["payload_hashes_valid"] is True
    assert report["kernel_replay_matches"] is True
    assert report["bundle_profile"] == FULL_AUDIT_PROFILE
    assert report["saved_verdict"] == certificate.to_dict()["verdict"]
    assert "feedback_test" in certificate.to_dict()
    gate3_payload = json.loads(
        (tmp_path / "payload" / "gate3.json").read_text(encoding="utf-8")
    )
    assert "neutral_contract_audit_pass" not in gate3_payload
    assert (
        "neutral_contract_audit_pass"
        not in certificate.to_dict()["feedback_test"]
    )

    auto_report = verify_bundle(tmp_path)
    assert auto_report == report


def test_full_audit_bundle_round_trips_explicit_neutral_audit(tmp_path: Path) -> None:
    reg, integrity, gate1, gate2, gate3, _certificate = _full_bundle_inputs()
    gate3.neutral_contract_audit_pass = True
    gate3.neutral_scope_audit_manifest_hash = gate3_neutral_scope_manifest_hash(
        gate3, integrity.selection_rule_hash
    )
    integrity = replace(
        integrity,
        recovery_ledger_manifest_hash=recovery_ledger_manifest_hash(
            gate2.controls, gate3
        ),
        gate3_neutral_scope_manifest_hash=gate3.neutral_scope_audit_manifest_hash,
    )
    certificate = evaluate(reg, gate1, gate2, gate3, integrity=integrity)
    write_full_audit_bundle(
        tmp_path, reg, integrity, gate1, gate2, gate3, certificate
    )

    gate3_payload = json.loads(
        (tmp_path / "payload" / "gate3.json").read_text(encoding="utf-8")
    )
    assert gate3_payload["neutral_contract_audit_pass"] is True
    assert certificate.to_dict()["feedback_test"]["neutral_contract_audit_pass"] is True
    report = verify_full_audit_bundle(tmp_path)
    assert report["ok"] is True
    assert report["kernel_replay_matches"] is True


def test_full_audit_bundle_detects_gate3_byte_tampering(tmp_path: Path) -> None:
    write_full_audit_bundle(tmp_path, *_full_bundle_inputs())
    gate3_path = tmp_path / "payload" / "gate3.json"
    payload = json.loads(gate3_path.read_text(encoding="utf-8"))
    payload["pairs"][0]["neutral"]["artifact_hash"] = "sha256:tampered"
    gate3_path.write_bytes(_canonical_bytes(payload))

    report = verify_full_audit_bundle(tmp_path)
    assert report["ok"] is False
    assert report["manifest_valid"] is True
    assert report["payload_hashes_valid"] is False
    assert report["kernel_replay_matches"] is False


def test_full_audit_rejects_content_addressed_unknown_nested_field(
    tmp_path: Path,
) -> None:
    write_full_audit_bundle(tmp_path, *_full_bundle_inputs())
    gate3_path = tmp_path / "payload" / "gate3.json"
    payload = json.loads(gate3_path.read_text(encoding="utf-8"))
    payload["pairs"][0]["truthful"]["unregistered_field"] = True
    gate3_path.write_bytes(_canonical_bytes(payload))
    _rehash_full_payload(tmp_path, "gate3")

    report = verify_full_audit_bundle(tmp_path)
    assert report["manifest_valid"] is True
    assert report["payload_hashes_valid"] is True
    assert report["kernel_replay_matches"] is False
    assert report["ok"] is False
    assert any("unknown fields" in error for error in report["errors"])


def test_full_audit_detects_content_addressed_wrong_certificate(
    tmp_path: Path,
) -> None:
    reg, integrity, gate1, gate2, gate3, certificate = _full_bundle_inputs()
    wrong_certificate = certificate.to_dict()
    wrong_certificate["fields"]["feedback_effect"] = "supported"
    write_full_audit_bundle(
        tmp_path,
        reg,
        integrity,
        gate1,
        gate2,
        gate3,
        wrong_certificate,
    )

    report = verify_full_audit_bundle(tmp_path)
    assert report["manifest_valid"] is True
    assert report["payload_hashes_valid"] is True
    assert report["kernel_replay_matches"] is False
    assert report["ok"] is False


def test_full_audit_rejects_unregistered_file_and_cross_profile_overwrite(
    tmp_path: Path,
) -> None:
    inputs = _full_bundle_inputs()
    write_full_audit_bundle(tmp_path, *inputs)
    (tmp_path / "payload" / "unregistered.json").write_text(
        "{}", encoding="utf-8"
    )

    report = verify_full_audit_bundle(tmp_path)
    assert report["manifest_valid"] is False
    assert report["ok"] is False
    assert any("file set mismatch" in error for error in report["errors"])

    other = tmp_path / "core"
    write_core_bundle(other, *_bundle_inputs())
    with pytest.raises(BundleError, match="different format/profile"):
        write_full_audit_bundle(other, *inputs)


def test_python_module_cli_auto_detects_full_audit_bundle(tmp_path: Path) -> None:
    write_full_audit_bundle(tmp_path, *_full_bundle_inputs())
    completed = subprocess.run(
        [sys.executable, "-m", "dcp", "verify", str(tmp_path)],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    report = json.loads(completed.stdout)
    assert report["ok"] is True
    assert report["bundle_profile"] == FULL_AUDIT_PROFILE


def test_auto_verify_rejects_unknown_bundle_format(tmp_path: Path) -> None:
    (tmp_path / "manifest.json").write_text(
        json.dumps({"format": "unknown", "format_version": "1.0"}),
        encoding="utf-8",
    )
    report = verify_bundle(tmp_path)
    assert report["ok"] is False
    assert report["manifest_valid"] is False
    assert any("unsupported bundle format" in error for error in report["errors"])
