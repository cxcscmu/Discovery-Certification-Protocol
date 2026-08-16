"""Small public façade over the unchanged DCP evaluation kernel.

The façade removes orchestration boilerplate only.  It does not infer
integrity, mint receipts, generate content hashes, or change a kernel verdict.
The complete sealed kernel record remains the source of truth.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping, Optional

from dcp.bundle import (
    PROVENANCE_SCOPE,
    write_core_bundle,
    write_full_audit_bundle,
)
from dcp.evaluate import Certificate, evaluate
from dcp.registration import Registration, validate_registration
from dcp.types import (
    Gate1Evidence,
    Gate2Evidence,
    Gate3Evidence,
    IntegrityEvidence,
)


STRICT_CORE_PROFILE_V1 = "dcp_v2_strict_core_single_audit_v1"
_STRICT_CORE_MIN_ZERO_HIT_UNITS = 77


def _freeze_json(value: Any) -> Any:
    """Take an immutable snapshot of a strict-JSON-like value."""

    if isinstance(value, Mapping):
        return MappingProxyType(
            {str(key): _freeze_json(item) for key, item in value.items()}
        )
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)
    return value


@dataclass(frozen=True)
class AuditRecord:
    """One sealed kernel decision and its optional local bundle manifest."""

    certificate: Certificate
    bundle_manifest: Optional[Mapping[str, Any]] = None

    def __post_init__(self) -> None:
        if self.bundle_manifest is not None:
            object.__setattr__(
                self,
                "bundle_manifest",
                _freeze_json(deepcopy(dict(self.bundle_manifest))),
            )
        protocol = self.certificate.to_dict().get("protocol", {})
        if protocol.get("formal_certificate_issued") is not False:
            raise ValueError(
                "the local DCP façade accepts only non-formal kernel records"
            )

    @property
    def formal_certificate_issued(self) -> bool:
        """Whether an external registry has formally issued this record."""

        return False

    @property
    def provenance_scope(self) -> str:
        """The strongest provenance scope represented by this local object."""

        if self.bundle_manifest is None:
            return "kernel_decision_record_only"
        return str(self.bundle_manifest.get("provenance_scope", PROVENANCE_SCOPE))

    @property
    def bundle_id(self) -> Optional[str]:
        if self.bundle_manifest is None:
            return None
        value = self.bundle_manifest.get("bundle_id")
        return value if isinstance(value, str) else None

    def summary(self) -> dict[str, Any]:
        """Return a scoped projection of the sealed kernel payload.

        This is a display convenience, not a second verdict implementation.
        Every value below is copied from the already sealed certificate or the
        content-addressed bundle manifest.
        """

        payload = self.certificate.to_dict()
        protocol = payload["protocol"]
        verdict = payload["verdict"]
        scope = payload["scope"]
        recovery = payload["no_feedback_recovery"]
        fields = payload["fields"]
        return {
            "record_scope": {
                "provenance": self.provenance_scope,
                "formal_certificate_issued": False,
                "registry_status": protocol["registry_status"],
                "bundle_id": self.bundle_id,
            },
            "registered_scope": {
                "claim_id": payload["claim"]["claim_id"],
                "model": scope["model"],
                "interface_hash": scope["interface_hash"],
                "task_family_profile": scope["task_family_profile"],
                "audit_family_id": scope["audit_family_id"],
                "audit_slot_id": scope["audit_slot_id"],
                "delta_min": scope["delta_min"],
                "epsilon": scope["epsilon"],
                "rho": scope["rho"],
                "m_max": scope["m_max"],
                "alpha_total": scope["alpha_total"],
                "alpha_allocation": scope["alpha_allocation"],
            },
            "outcome_attribution_within_registered_scope": {
                "kernel_verdict": verdict["core"],
                "inconclusive_class": verdict["core_inconclusive_class"],
                "recovery_status": fields["no_feedback_recovery"],
                "independent_units": recovery["n_ind"],
                "recovery_probability_upper_bound": recovery["p_upper"],
                "registered_probability_limit": recovery["rho"],
            },
            "feedback_attribution_within_registered_scope": {
                "kernel_verdict": verdict["evidence"],
                "inconclusive_class": verdict["evidence_inconclusive_class"],
                "feedback_effect": fields["feedback_effect"],
                "neutral_recovery": fields["neutral_recovery"],
            },
            "statement": verdict["statement"],
            "complete_reason": verdict["reason"],
        }

    def __repr__(self) -> str:
        summary = self.summary()
        outcome = summary["outcome_attribution_within_registered_scope"]
        feedback = summary["feedback_attribution_within_registered_scope"]
        return (
            "AuditRecord("
            "formal_certificate_issued=False, "
            f"provenance_scope={self.provenance_scope!r}, "
            f"outcome_within_registered_scope={outcome['kernel_verdict']!r}, "
            f"feedback_within_registered_scope={feedback['kernel_verdict']!r}"
            ")"
        )


def strict_core_registration(
    *,
    profile: str,
    claim_id: str,
    audit_family_id: str,
    model_id: str,
    interface_hash: str,
    task_family_profile: str,
    inference_scope: str,
    minimum_gain: float,
    recovery_tolerance_fraction: float,
    max_candidate_slots: int,
    minimum_independent_units: int,
    challenger_contract_hash: str,
    challenge_distribution_hash: str,
    audit_slot_id: str,
    audit_slot_reservation_receipt_hash: str,
    notes: Optional[dict[str, Any]] = None,
) -> Registration:
    """Build the fixed strict Core profile for one audit in one family.

    ``profile`` must be :data:`STRICT_CORE_PROFILE_V1`, making the statistical
    policy explicit at the call site.  The profile uses the existing kernel
    values ``rho=0.05``, ``alpha_total=0.05``, ``alpha_main=0.005``,
    ``alpha_score=0.005``, ``alpha_recovery=0.020``, and
    ``alpha_adequacy=0.005``.  It also retains the kernel's non-relaxable
    adequacy floors and failure caps.

    This helper is intentionally Core-only and single-audit-only.  Full
    feedback registration has more causal scope bindings and continues to use
    :class:`Registration` directly.
    """

    if profile != STRICT_CORE_PROFILE_V1:
        raise ValueError(
            f"profile must be {STRICT_CORE_PROFILE_V1!r}; got {profile!r}"
        )
    if inference_scope == "sampled_population":
        ci_method = "bounded_empirical_bernstein"
    elif inference_scope == "exhaustive_finite_set":
        ci_method = "finite_set_exact"
    else:
        raise ValueError(
            "inference_scope must be sampled_population or exhaustive_finite_set"
        )
    if minimum_independent_units < _STRICT_CORE_MIN_ZERO_HIT_UNITS:
        raise ValueError(
            "the strict Core profile requires at least "
            f"{_STRICT_CORE_MIN_ZERO_HIT_UNITS} independent units so that "
            "zero hits can satisfy rho=0.05 at alpha_recovery=0.020"
        )
    if max_candidate_slots < minimum_independent_units:
        raise ValueError(
            "max_candidate_slots must be at least minimum_independent_units"
        )

    registration = Registration(
        claim_id=claim_id,
        audit_family_id=audit_family_id,
        model_id=model_id,
        interface_hash=interface_hash,
        task_family_profile=task_family_profile,
        grade_requested="core",
        inference_scope=inference_scope,
        ci_method=ci_method,
        score_range_id="normalized_unit_interval_v1",
        delta_min=minimum_gain,
        kappa=recovery_tolerance_fraction,
        m_max=max_candidate_slots,
        recovery_stratum="matched",
        gate2_control_contract_hash=challenger_contract_hash,
        challenge_distribution_hash=challenge_distribution_hash,
        min_n_ind=minimum_independent_units,
        audit_slot_id=audit_slot_id,
        audit_slot_reservation_receipt_hash=(
            audit_slot_reservation_receipt_hash
        ),
        notes={} if notes is None else deepcopy(notes),
    )
    errors = validate_registration(registration)
    if errors:
        raise ValueError("invalid strict Core registration: " + "; ".join(errors))
    return registration


def audit(
    *,
    registration: Registration,
    outcome: Gate1Evidence,
    challenge: Gate2Evidence,
    integrity: Optional[IntegrityEvidence],
    feedback: Optional[Gate3Evidence] = None,
    verifier_flaw: bool = False,
    bundle_dir: Optional[str | Path] = None,
) -> AuditRecord:
    """Evaluate recorded evidence and optionally write a replayable bundle.

    The friendly argument names are exact aliases for Gate 1, Gate 2, and
    Gate 3 evidence.  All inputs are snapshotted before calling the unchanged
    :func:`dcp.evaluate.evaluate` kernel.  No integrity flag is synthesized.
    """

    frozen_registration = deepcopy(registration)
    frozen_outcome = deepcopy(outcome)
    frozen_challenge = deepcopy(challenge)
    frozen_integrity = deepcopy(integrity)
    frozen_feedback = deepcopy(feedback)

    certificate = evaluate(
        frozen_registration,
        frozen_outcome,
        frozen_challenge,
        frozen_feedback,
        verifier_flaw=verifier_flaw,
        integrity=frozen_integrity,
    )
    # Materialize the kernel's sealed payload before creating any convenience
    # projection or writing a bundle.
    certificate.to_dict()

    manifest: Optional[dict[str, Any]] = None
    if bundle_dir is not None:
        if not isinstance(frozen_integrity, IntegrityEvidence):
            raise ValueError(
                "a replayable bundle requires explicit IntegrityEvidence; "
                "the façade will not synthesize it"
            )
        if frozen_feedback is None:
            manifest = write_core_bundle(
                bundle_dir,
                frozen_registration,
                frozen_integrity,
                frozen_outcome,
                frozen_challenge,
                certificate,
            )
        else:
            manifest = write_full_audit_bundle(
                bundle_dir,
                frozen_registration,
                frozen_integrity,
                frozen_outcome,
                frozen_challenge,
                frozen_feedback,
                certificate,
            )
    return AuditRecord(certificate=certificate, bundle_manifest=manifest)


__all__ = [
    "AuditRecord",
    "STRICT_CORE_PROFILE_V1",
    "audit",
    "strict_core_registration",
]
