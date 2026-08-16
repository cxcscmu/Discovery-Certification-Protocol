"""Fail-closed verdict ordering (proposal §8.4) and grade logic (§8.2-8.3).

The Core verdict is produced by walking the §8.4 ladder in order; the first
matching rule wins.  DCP-Evidence is only reachable from a certified Core plus a
passing sham calibration and a supported feedback effect (§8.3).
"""

from __future__ import annotations

from typing import Optional

from dcp.registration import Registration
from dcp.types import (
    AttemptStatus,
    CoreVerdict,
    EffectStatus,
    EvidenceVerdict,
    Gate1Result,
    Gate2Result,
    Gate3Result,
    InconclusiveClass,
    Recovery,
    TriState,
    Validity,
    Verdict,
)


_NULL = InconclusiveClass.NULL
_AUDIT = InconclusiveClass.AUDIT_INCOMPLETE
_STATISTICAL = InconclusiveClass.STATISTICAL_UNCERTAINTY


def _unresolved_class(classifications) -> InconclusiveClass:
    unresolved = [
        item for item in classifications if item.status == AttemptStatus.UNRESOLVED
    ]
    if unresolved and all(item.d_mean is not None for item in unresolved):
        return _STATISTICAL
    return _AUDIT


def _gate2_inconclusive_class(reg: Registration, g2: Gate2Result) -> InconclusiveClass:
    if not g2.hit_admissibility_pass or not g2.adequacy_pass:
        return _AUDIT
    if g2.unresolved > 0:
        return _unresolved_class(g2.classifications)
    if g2.n_ind < reg.min_n_ind:
        return _AUDIT
    if g2.p_upper is not None and g2.p_upper > reg.rho:
        return _STATISTICAL
    return _AUDIT


def _neutral_inconclusive_class(
    reg: Registration, g3: Gate3Result
) -> InconclusiveClass:
    if not g3.neutral_adequacy_pass:
        return _AUDIT
    if g3.neutral_unresolved > 0:
        return _unresolved_class(g3.neutral_classifications)
    if g3.neutral_n_ind < reg.min_n_ind:
        return _AUDIT
    if g3.neutral_p_upper is not None and g3.neutral_p_upper > reg.rho_placebo:
        return _STATISTICAL
    return _AUDIT


def _core_verdict(
    reg: Registration,
    reg_errors: list[str],
    integrity_errors: list[str],
    gate3_core_errors: list[str],
    g1: Gate1Result,
    g2: Gate2Result,
    g3: Optional[Gate3Result],
    verifier_flaw: bool,
) -> tuple[CoreVerdict, str, InconclusiveClass]:
    """Walk the §8.4 ladder; return (verdict, reason for the first rule that fires)."""
    if reg_errors:
        return (
            CoreVerdict.INCONCLUSIVE,
            "registration incomplete: " + "; ".join(reg_errors),
            _AUDIT,
        )
    # A separately integrity-validated recovery hit is a positive
    # counterexample.  Unrelated ledger defects still block certification, but
    # cannot erase that witness.  ``evaluate`` only emits RECOVERED on this
    # path after the target and candidate-local envelopes have been checked.
    if (
        integrity_errors
        and g2.no_feedback_recovery != Recovery.RECOVERED
    ):
        return (
            CoreVerdict.INCONCLUSIVE,
            "integrity incomplete: " + "; ".join(integrity_errors),
            _AUDIT,
        )

    if g1.baseline_validity != Validity.VALID:
        return (
            CoreVerdict.INCONCLUSIVE,
            "Valid(baseline) is false or unresolved",
            _AUDIT,
        )
    if g1.astar_validity == Validity.INVALID:
        return CoreVerdict.REFUTED, "Valid(A*) = false", _NULL
    if g1.astar_validity == Validity.UNRESOLVED:
        return CoreVerdict.INCONCLUSIVE, "Valid(A*) unresolved", _AUDIT
    if g1.baseline_satisfies_p:
        return CoreVerdict.REFUTED, "baseline satisfies P", _NULL
    if g1.baseline_fails_p == TriState.INCONCLUSIVE:
        return (
            CoreVerdict.INCONCLUSIVE,
            "baseline position vs recovery line uncertain",
            _STATISTICAL,
        )
    if g1.utility_confirmed_below:
        return (
            CoreVerdict.REFUTED,
            "main utility confirmed below delta_min",
            _NULL,
        )
    if not g1.utility_pass:
        return (
            CoreVerdict.INCONCLUSIVE,
            "main utility uncertain around delta_min",
            _STATISTICAL,
        )

    if verifier_flaw:
        return (
            CoreVerdict.INCONCLUSIVE,
            "new verifier flaw compromises P",
            _AUDIT,
        )

    if g2.no_feedback_recovery == Recovery.RECOVERED:
        return CoreVerdict.REFUTED, f"no-feedback recovery: {g2.reason}", _NULL
    if g3 is not None and g3.lineage_empty_hit_refutes_core:
        return (
            CoreVerdict.REFUTED,
            "lineage-empty neutral recovery reached P",
            _NULL,
        )
    if g3 is not None and g3.neutral_in_gate2_scope and g3.neutral_unresolved > 0:
        return (
            CoreVerdict.INCONCLUSIVE,
            "lineage-empty recovery ledger contains an unresolved P classification",
            _neutral_inconclusive_class(reg, g3),
        )
    if gate3_core_errors:
        return (
            CoreVerdict.INCONCLUSIVE,
            "lineage-empty recovery ledger is malformed: "
            + "; ".join(gate3_core_errors),
            _AUDIT,
        )
    if g2.no_feedback_recovery == Recovery.INCONCLUSIVE:
        return (
            CoreVerdict.INCONCLUSIVE,
            f"no-feedback recovery inconclusive: {g2.reason}",
            _gate2_inconclusive_class(reg, g2),
        )

    return CoreVerdict.CERTIFIED, f"scoped non-recovery: {g2.reason}", _NULL


def _evidence_verdict(
    reg: Registration,
    core: CoreVerdict,
    g3: Optional[Gate3Result],
    gate3_integrity_errors: list[str],
) -> tuple[EvidenceVerdict, str, InconclusiveClass]:
    if not reg.requests_evidence:
        return EvidenceVerdict.NOT_TESTED, "evidence grade not requested", _NULL
    if core != CoreVerdict.CERTIFIED:
        return (
            EvidenceVerdict.NOT_TESTED,
            "Core not certified; evidence grade unreachable",
            _NULL,
        )
    if g3 is None:
        return (
            EvidenceVerdict.INCONCLUSIVE,
            "requested feedback intervention was not supplied",
            _AUDIT,
        )

    if reg.necessity_claim_requested and g3.neutral_recovery == Recovery.RECOVERED:
        return (
            EvidenceVerdict.REFUTED,
            "neutral branch recovered the registered outcome",
            _NULL,
        )

    if gate3_integrity_errors:
        return (
            EvidenceVerdict.INCONCLUSIVE,
            "feedback audit integrity is incomplete",
            _AUDIT,
        )

    if g3.sham_adequacy != TriState.PASS:
        sham_class = (
            _STATISTICAL
            if g3.sham_adequacy == TriState.INCONCLUSIVE
            and g3.sham_n == reg.registered_n_sham_pairs
            and g3.sham_delta_null_lcb is not None
            and g3.sham_delta_null_ucb is not None
            else _AUDIT
        )
        return (
            EvidenceVerdict.INCONCLUSIVE,
            f"sham_adequacy={g3.sham_adequacy.value}",
            sham_class,
        )
    if g3.feedback_effect == EffectStatus.SUPPORTED:
        if reg.necessity_claim_requested:
            if g3.neutral_recovery != Recovery.NOT_RECOVERED_WITHIN_SCOPE:
                return (
                    EvidenceVerdict.INCONCLUSIVE,
                    "neutral recovery is unresolved",
                    _neutral_inconclusive_class(reg, g3),
                )
        return (
            EvidenceVerdict.CERTIFIED,
            "feedback_effect supported with passing sham calibration",
            _NULL,
        )
    if g3.feedback_effect == EffectStatus.NOT_SUPPORTED:
        return (
            EvidenceVerdict.REFUTED,
            "feedback_effect confirmed below the registered minimum",
            _NULL,
        )
    effect_class = (
        _STATISTICAL
        if g3.branch_health_pass
        and g3.pairs_unresolved == 0
        and g3.effect_lcb is not None
        and g3.effect_ucb is not None
        else _AUDIT
    )
    return (
        EvidenceVerdict.INCONCLUSIVE,
        f"feedback_effect inconclusive: {g3.reason}",
        effect_class,
    )


def final_verdict(
    reg: Registration,
    reg_errors: list[str],
    integrity_errors: list[str],
    gate3_core_errors: list[str],
    g1: Gate1Result,
    g2: Gate2Result,
    g3: Optional[Gate3Result] = None,
    verifier_flaw: bool = False,
    gate3_integrity_errors: Optional[list[str]] = None,
) -> Verdict:
    core, core_reason, core_inconclusive_class = _core_verdict(
        reg,
        reg_errors,
        integrity_errors,
        gate3_core_errors,
        g1,
        g2,
        g3,
        verifier_flaw,
    )
    evidence, ev_reason, evidence_inconclusive_class = _evidence_verdict(
        reg, core, g3, gate3_integrity_errors or []
    )

    statement = _statement(reg, core, evidence)
    return Verdict(
        core=core,
        evidence=evidence,
        core_inconclusive_class=core_inconclusive_class,
        evidence_inconclusive_class=evidence_inconclusive_class,
        statement=statement,
        reason=f"core: {core_reason} | evidence: {ev_reason}",
    )


def _statement(reg: Registration, core: CoreVerdict, evidence: EvidenceVerdict) -> str:
    if core == CoreVerdict.CERTIFIED:
        base = (
            "Within the certificate's frozen scope, the result passed sealed validation and "
            "registered privileged no-feedback challengers did not recover it within the stated "
            f"probability/budget bound (rho={reg.rho})."
        )
        if evidence == EvidenceVerdict.CERTIFIED:
            base += " Truthful feedback content showed a certified causal effect over a calibrated neutral sham."
            if reg.necessity_claim_requested:
                base += " Neutral branches also failed to recover the outcome within the registered bound."
        return base
    if core == CoreVerdict.REFUTED:
        return "Within the frozen scope, the outcome-attribution claim is refuted."
    return "Within the frozen scope, the claim is inconclusive under the registered budget."
