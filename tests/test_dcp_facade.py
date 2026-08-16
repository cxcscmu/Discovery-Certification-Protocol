from __future__ import annotations

from dataclasses import asdict

import pytest

from dcp import (
    STRICT_CORE_PROFILE_V1,
    audit,
    evaluate,
    strict_core_registration,
)
from dcp.bundle import verify_bundle
from dcp.types import CoreVerdict
from tests.test_dcp_bundle import _bundle_inputs, _full_bundle_inputs


def test_facade_certificate_is_identical_to_direct_kernel() -> None:
    reg, integrity, gate1, gate2, _certificate = _bundle_inputs()
    direct = evaluate(reg, gate1, gate2, integrity=integrity)
    wrapped = audit(
        registration=reg,
        outcome=gate1,
        challenge=gate2,
        integrity=integrity,
    )

    assert wrapped.certificate.to_dict() == direct.to_dict()
    assert wrapped.formal_certificate_issued is False
    assert "formal_certificate_issued=False" in repr(wrapped)


def test_facade_does_not_fill_missing_integrity() -> None:
    reg, _integrity, gate1, gate2, _certificate = _bundle_inputs()
    direct = evaluate(reg, gate1, gate2, integrity=None)
    wrapped = audit(
        registration=reg,
        outcome=gate1,
        challenge=gate2,
        integrity=None,
    )

    assert wrapped.certificate.to_dict() == direct.to_dict()
    assert wrapped.certificate.verdict.core == CoreVerdict.INCONCLUSIVE
    assert wrapped.certificate.integrity_errors


def test_facade_writes_replayable_core_bundle(tmp_path) -> None:
    reg, integrity, gate1, gate2, _certificate = _bundle_inputs()
    wrapped = audit(
        registration=reg,
        outcome=gate1,
        challenge=gate2,
        integrity=integrity,
        bundle_dir=tmp_path,
    )

    report = verify_bundle(tmp_path)
    summary = wrapped.summary()
    assert report["ok"] is True
    assert wrapped.bundle_id == report["bundle_id"]
    assert summary["record_scope"]["formal_certificate_issued"] is False
    assert (
        summary["record_scope"]["provenance"]
        == "local_content_addressed_only"
    )
    assert (
        summary["outcome_attribution_within_registered_scope"]["kernel_verdict"]
        == wrapped.certificate.verdict.core.value
    )
    assert summary["complete_reason"] == wrapped.certificate.verdict.reason


def test_facade_writes_full_bundle_when_feedback_is_present(tmp_path) -> None:
    reg, integrity, gate1, gate2, gate3, _certificate = _full_bundle_inputs()
    direct = evaluate(reg, gate1, gate2, gate3, integrity=integrity)
    wrapped = audit(
        registration=reg,
        outcome=gate1,
        challenge=gate2,
        feedback=gate3,
        integrity=integrity,
        bundle_dir=tmp_path,
    )

    assert wrapped.certificate.to_dict() == direct.to_dict()
    assert verify_bundle(tmp_path)["ok"] is True
    assert wrapped.bundle_manifest["profile"] == "full_audit_v1"


def test_bundle_request_does_not_synthesize_integrity(tmp_path) -> None:
    reg, _integrity, gate1, gate2, _certificate = _bundle_inputs()
    with pytest.raises(ValueError, match="will not synthesize"):
        audit(
            registration=reg,
            outcome=gate1,
            challenge=gate2,
            integrity=None,
            bundle_dir=tmp_path,
        )


def test_strict_core_registration_is_an_explicit_fixed_profile() -> None:
    reg = strict_core_registration(
        profile=STRICT_CORE_PROFILE_V1,
        claim_id="facade-claim",
        audit_family_id="facade-family",
        model_id="provider/model-version",
        interface_hash="sha256:interface",
        task_family_profile="plain-demo-v1",
        inference_scope="exhaustive_finite_set",
        minimum_gain=0.10,
        recovery_tolerance_fraction=0.5,
        max_candidate_slots=77,
        minimum_independent_units=77,
        challenger_contract_hash="sha256:challenger-contract",
        challenge_distribution_hash="sha256:challenge-distribution",
        audit_slot_id="slot-001",
        audit_slot_reservation_receipt_hash="sha256:slot-receipt",
        notes={"purpose": "test"},
    )

    assert reg.grade_requested == "core"
    assert reg.ci_method == "finite_set_exact"
    assert reg.rho == 0.05
    assert reg.active_alphas() == {
        "alpha_main": 0.005,
        "alpha_score": 0.005,
        "alpha_recovery": 0.020,
        "alpha_adequacy": 0.005,
    }
    assert reg.family_max_audits == 1
    assert asdict(reg)["notes"] == {"purpose": "test"}


def test_strict_core_registration_rejects_unknown_or_invalid_profile() -> None:
    kwargs = dict(
        claim_id="facade-claim",
        audit_family_id="facade-family",
        model_id="provider/model-version",
        interface_hash="sha256:interface",
        task_family_profile="plain-demo-v1",
        inference_scope="sampled_population",
        minimum_gain=0.10,
        recovery_tolerance_fraction=0.5,
        max_candidate_slots=77,
        minimum_independent_units=77,
        challenger_contract_hash="sha256:challenger-contract",
        challenge_distribution_hash="sha256:challenge-distribution",
        audit_slot_id="slot-001",
        audit_slot_reservation_receipt_hash="sha256:slot-receipt",
    )
    with pytest.raises(ValueError, match="profile must be"):
        strict_core_registration(profile="loose", **kwargs)
    with pytest.raises(ValueError, match="invalid strict Core registration"):
        strict_core_registration(
            profile=STRICT_CORE_PROFILE_V1,
            **{**kwargs, "recovery_tolerance_fraction": 1.0},
        )
    with pytest.raises(ValueError, match="at least 77 independent units"):
        strict_core_registration(
            profile=STRICT_CORE_PROFILE_V1,
            **{**kwargs, "minimum_independent_units": 76},
        )
    with pytest.raises(ValueError, match="max_candidate_slots must be at least"):
        strict_core_registration(
            profile=STRICT_CORE_PROFILE_V1,
            **{**kwargs, "max_candidate_slots": 76},
        )


def test_record_snapshots_inputs_and_bundle_manifest(tmp_path) -> None:
    reg, integrity, gate1, gate2, _certificate = _bundle_inputs()
    wrapped = audit(
        registration=reg,
        outcome=gate1,
        challenge=gate2,
        integrity=integrity,
        bundle_dir=tmp_path,
    )
    sealed = wrapped.certificate.to_dict()
    reg.model_id = "mutated-after-audit"
    gate1.astar.per_unit[0] = 0.0

    assert wrapped.certificate.to_dict() == sealed
    with pytest.raises(TypeError):
        wrapped.bundle_manifest["provenance_scope"] = "forged"
    assert wrapped.provenance_scope == "local_content_addressed_only"
