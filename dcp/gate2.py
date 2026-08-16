"""Gate 2 — privileged no-feedback recovery (proposal §5)."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Optional, Sequence

from dcp.integrity import control_result_hash
from dcp.registration import Registration
from dcp.stats import (
    binomial_lower_bound,
    bonferroni_share,
    mean_diff_ci,
    zero_hit_upper_bound,
)
from dcp.types import (
    AdequacyEvidence,
    ArtifactScores,
    AttemptStatus,
    ControlAttempt,
    ControlClassification,
    Gate2Evidence,
    Gate2Result,
    RawAttemptOutcome,
    Recovery,
    Validity,
)


def _classification(
    control: ControlAttempt,
    status: AttemptStatus,
    *,
    reason: str,
    d_mean: Optional[float] = None,
    d_lcb: Optional[float] = None,
    d_ucb: Optional[float] = None,
    denominator: bool = False,
    n_ind: bool = False,
) -> ControlClassification:
    return ControlClassification(
        attempt_id=control.attempt_id,
        artifact_hash=control.artifact_hash,
        verifier_result_hash=control_result_hash(control),
        status=status,
        d_mean=d_mean,
        d_lcb=d_lcb,
        d_ucb=d_ucb,
        counts_in_denominator=denominator,
        counts_in_n_ind=n_ind,
        stratum=control.stratum,
        scope_contract_hash=control.scope_contract_hash,
        prestart_contract_receipt_hash=control.prestart_contract_receipt_hash,
        challenge_distribution_hash=control.challenge_distribution_hash,
        independent_draw_receipt_hash=control.independent_draw_receipt_hash,
        independent_unit_id=control.independent_unit_id,
        reason=reason,
    )


def classify_control(
    reg: Registration,
    control: ControlAttempt,
    astar: ArtifactScores,
    a_i: float,
    *,
    expected_scope_contract_hash: Optional[str] = None,
    expected_distribution_hash: Optional[str] = None,
) -> ControlClassification:
    """Classify one explicit raw attempt; contradictions become unresolved."""
    independent = control.independence_ok and bool(control.independent_unit_id)

    if control.stratum != reg.recovery_stratum:
        return _classification(
            control,
            AttemptStatus.UNRESOLVED,
            reason=f"attempt stratum is outside registered scope {reg.recovery_stratum!r}",
        )

    if (
        expected_scope_contract_hash is not None
        and control.scope_contract_hash != expected_scope_contract_hash
    ):
        return _classification(
            control,
            AttemptStatus.EXECUTION_CONTRACT_VIOLATION,
            reason="attempt violated the frozen model/resource/opportunity contract",
        )
    if (
        expected_distribution_hash is not None
        and control.challenge_distribution_hash != expected_distribution_hash
    ):
        return _classification(
            control,
            AttemptStatus.EXECUTION_CONTRACT_VIOLATION,
            reason="attempt was not drawn from the frozen challenger episode distribution",
        )

    if control.outcome == RawAttemptOutcome.INFRASTRUCTURE_INVALID:
        if (
            control.per_unit is not None
            or not control.infrastructure_outcome_independent
        ):
            return _classification(
                control,
                AttemptStatus.UNRESOLVED,
                reason="infrastructure exclusion is outcome-dependent or conflicts with an artifact",
            )
        return _classification(
            control,
            AttemptStatus.INFRASTRUCTURE_INVALID,
            reason="outcome-independent infrastructure failure",
        )

    if control.outcome == RawAttemptOutcome.MODEL_FAILURE:
        if control.per_unit is not None or control.validity == Validity.VALID:
            return _classification(
                control,
                AttemptStatus.UNRESOLVED,
                reason="declared failure conflicts with a scored or validity-confirmed artifact",
            )
        return _classification(
            control,
            AttemptStatus.MODEL_FAILURE,
            reason="explicit model failure under the registered contract",
            denominator=True,
            n_ind=independent,
        )

    if control.outcome == RawAttemptOutcome.EXECUTION_CONTRACT_VIOLATION:
        return _classification(
            control,
            AttemptStatus.EXECUTION_CONTRACT_VIOLATION,
            reason="explicit execution-contract violation",
        )

    if control.outcome == RawAttemptOutcome.UNRESOLVED:
        return _classification(
            control, AttemptStatus.UNRESOLVED, reason="raw attempt unresolved"
        )

    # ARTIFACT outcome.
    if control.validity == Validity.INVALID:
        return _classification(
            control,
            AttemptStatus.MODEL_FAILURE,
            reason="artifact violates the registered outcome contract",
            denominator=True,
            n_ind=independent,
        )
    if control.validity != Validity.VALID:
        return _classification(
            control, AttemptStatus.UNRESOLVED, reason="artifact validity unresolved"
        )
    if control.per_unit is None:
        return _classification(
            control, AttemptStatus.UNRESOLVED, reason="valid artifact has no scores"
        )
    if not control.artifact_hash:
        return _classification(
            control, AttemptStatus.UNRESOLVED, reason="artifact hash missing"
        )
    if tuple(control.unit_ids) != tuple(astar.unit_ids):
        return _classification(
            control, AttemptStatus.UNRESOLVED, reason="private-unit manifest mismatch"
        )
    if len(control.per_unit) != len(astar.per_unit) or not all(
        math.isfinite(float(x)) for x in control.per_unit
    ):
        return _classification(
            control, AttemptStatus.UNRESOLVED, reason="scores malformed or non-finite"
        )

    d = mean_diff_ci(
        control.per_unit,
        astar.per_unit,
        1.0 - a_i,
        method=reg.ci_method,
    )
    neg_eps = -reg.epsilon
    if d.lcb >= neg_eps:
        status = AttemptStatus.CONFIRMED_HIT
        reason = "multiplicity-adjusted LCB reaches recovery line"
    elif d.ucb < neg_eps:
        status = AttemptStatus.CONFIRMED_MISS
        reason = "multiplicity-adjusted UCB is below recovery line"
    else:
        status = AttemptStatus.UNRESOLVED
        reason = "score interval crosses recovery line"

    return _classification(
        control,
        status,
        reason=reason,
        d_mean=d.mean,
        d_lcb=d.lcb,
        d_ucb=d.ucb,
        denominator=status != AttemptStatus.UNRESOLVED,
        n_ind=status != AttemptStatus.UNRESOLVED and independent,
    )


@dataclass
class RecoverySummary:
    recovery: Recovery
    classifications: list[ControlClassification]
    n_started: int
    n_evaluable: int
    n_ind: int
    hits: int
    admissible_hits: int
    unresolved: int
    p_upper: Optional[float]
    best_control_margin: Optional[float]
    adequacy_pass: bool
    adequacy_reasons: list[str]
    hit_admissibility_pass: bool
    hit_admissibility_reasons: list[str]
    positive_control_recall_lcb: Optional[float]
    positive_control_successes: int
    positive_control_trials: int
    adequacy_calibration_id: str
    adequacy_manifest_hash: str
    a_i: float
    reason: str


def _check_adequacy(
    reg: Registration,
    ad: AdequacyEvidence,
    controls: Sequence[ControlAttempt],
    classifications: Sequence[ControlClassification],
) -> tuple[bool, list[str], Optional[float]]:
    reasons: list[str] = []
    if ad.matched_model_present is not True:
        reasons.append("no matched model/interface stratum attested")
    if not any(c.stratum == reg.recovery_stratum for c in controls):
        reasons.append(
            f"no actual control in registered stratum {reg.recovery_stratum!r}"
        )
    if ad.materials_readable is not True:
        reasons.append("privileged materials not readable/retrievable")
    if ad.opportunity_floor_met is not True:
        reasons.append("opportunity floor not met")
    if ad.health_audit_pass is not True:
        reasons.append("independence/parser/provider/verifier health audit failed")
    if not ad.checks_manifest_hash:
        reasons.append("adequacy checks manifest hash missing")
    positive_lcb: Optional[float]
    try:
        positive_lcb = binomial_lower_bound(
            ad.positive_control_successes,
            ad.positive_control_trials,
            reg.alpha_adequacy,
        )
    except (TypeError, ValueError, ArithmeticError):
        positive_lcb = None
        reasons.append("positive-control h/n evidence is malformed")
    if positive_lcb is not None and positive_lcb < reg.positive_control_recall_min:
        reasons.append(
            f"positive-control recall LCB {positive_lcb:.3f} "
            f"< registered minimum {reg.positive_control_recall_min:.3f}"
        )

    if len(controls) > reg.m_max:
        reasons.append(
            f"candidate slots {len(controls)} exceed registered M_max={reg.m_max}"
        )

    strata = {c.stratum for c in controls if c.stratum}
    if any(not c.stratum for c in controls):
        reasons.append("one or more controls have no registered stratum")
    if len(strata) > 1:
        reasons.append(
            "heterogeneous strata require a registered mixture/per-stratum bound"
        )

    non_infra = [
        c for c in classifications if c.status != AttemptStatus.INFRASTRUCTURE_INVALID
    ]
    structurally_valid = [c for c in classifications if c.d_mean is not None]
    valid_rate = len(structurally_valid) / len(non_infra) if non_infra else 0.0
    if valid_rate < reg.min_valid_candidate_rate:
        reasons.append(
            f"valid-candidate rate {valid_rate:.3f} < registered minimum "
            f"{reg.min_valid_candidate_rate:.3f}"
        )

    infra_rate = (
        sum(c.status == AttemptStatus.INFRASTRUCTURE_INVALID for c in classifications)
        / len(classifications)
        if classifications
        else 0.0
    )
    if infra_rate > reg.max_infrastructure_failure_rate:
        reasons.append(
            f"infrastructure-failure rate {infra_rate:.3f} > registered maximum "
            f"{reg.max_infrastructure_failure_rate:.3f}"
        )
    model_failure_rate = (
        sum(c.status == AttemptStatus.MODEL_FAILURE for c in classifications)
        / len(non_infra)
        if non_infra
        else 0.0
    )
    if model_failure_rate > reg.max_model_failure_rate:
        reasons.append(
            f"model-failure rate {model_failure_rate:.3f} > registered maximum "
            f"{reg.max_model_failure_rate:.3f}"
        )
    contract_violation_rate = (
        sum(
            c.status == AttemptStatus.EXECUTION_CONTRACT_VIOLATION
            for c in classifications
        )
        / len(classifications)
        if classifications
        else 0.0
    )
    if contract_violation_rate > reg.max_execution_contract_violation_rate:
        reasons.append(
            f"execution-contract-violation rate {contract_violation_rate:.3f} "
            f"> registered maximum {reg.max_execution_contract_violation_rate:.3f}"
        )
    return not reasons, reasons, positive_lcb


def recovery_from_controls(
    reg: Registration,
    controls: Sequence[ControlAttempt],
    astar: ArtifactScores,
    adequacy: AdequacyEvidence,
    *,
    alpha_bound: float,
    rho_threshold: float,
    expected_scope_contract_hash: Optional[str] = None,
    expected_distribution_hash: Optional[str] = None,
    hit_admissibility_override: Optional[tuple[bool, list[str]]] = None,
) -> RecoverySummary:
    a_i = bonferroni_share(reg.alpha_score, reg.m_max)
    classifications = [
        classify_control(
            reg,
            c,
            astar,
            a_i,
            expected_scope_contract_hash=expected_scope_contract_hash,
            expected_distribution_hash=expected_distribution_hash,
        )
        for c in controls
    ]

    # Correlated candidates may all be inspected for a recovery witness, but a
    # cluster contributes at most one Bernoulli unit to the zero-hit bound.
    seen_units: set[str] = set()
    for c in classifications:
        if c.counts_in_n_ind:
            if c.independent_unit_id in seen_units:
                c.counts_in_n_ind = False
                c.reason += "; duplicate independent-unit cluster"
            else:
                seen_units.add(c.independent_unit_id)

    hits = sum(c.status == AttemptStatus.CONFIRMED_HIT for c in classifications)
    unresolved = sum(c.status == AttemptStatus.UNRESOLVED for c in classifications)
    n_evaluable = sum(c.counts_in_denominator for c in classifications)
    n_ind = sum(c.counts_in_n_ind for c in classifications)
    margins = [c.d_mean for c in classifications if c.d_mean is not None]
    best_control_margin = max(margins) if margins else None
    adequacy_pass, adequacy_reasons, positive_lcb = _check_adequacy(
        reg, adequacy, controls, classifications
    )
    if hit_admissibility_override is None:
        hit_admissibility_pass, hit_admissibility_reasons = True, []
    else:
        hit_admissibility_pass, hit_admissibility_reasons = hit_admissibility_override
    admissible_hits = hits if hit_admissibility_pass else 0
    p_upper = (
        zero_hit_upper_bound(n_ind, alpha_bound)
        if hits == 0 and adequacy_pass and unresolved == 0
        else None
    )
    if admissible_hits > 0:
        recovery, reason = (
            Recovery.RECOVERED,
            f"{admissible_hits} admissible adjusted confirmed hit(s)",
        )
    elif hits > 0:
        recovery, reason = (
            Recovery.INCONCLUSIVE,
            "score hit observed but its candidate-level execution scope is not admissible",
        )
    elif not adequacy_pass:
        recovery, reason = Recovery.INCONCLUSIVE, "control adequacy failed"
    elif unresolved > 0:
        recovery, reason = Recovery.INCONCLUSIVE, f"{unresolved} unresolved attempt(s)"
    elif n_ind < reg.min_n_ind:
        recovery, reason = (
            Recovery.INCONCLUSIVE,
            f"n_ind={n_ind} < required {reg.min_n_ind}",
        )
    elif p_upper is None:
        recovery, reason = Recovery.INCONCLUSIVE, "zero-hit bound is not applicable"
    elif p_upper > rho_threshold:
        recovery, reason = (
            Recovery.INCONCLUSIVE,
            f"p_upper={p_upper:.4f} > rho={rho_threshold}",
        )
    else:
        recovery, reason = (
            Recovery.NOT_RECOVERED_WITHIN_SCOPE,
            f"0/{n_ind} hits, p_upper={p_upper:.4f} <= rho={rho_threshold}",
        )

    return RecoverySummary(
        recovery=recovery,
        classifications=classifications,
        n_started=len(controls),
        n_evaluable=n_evaluable,
        n_ind=n_ind,
        hits=hits,
        admissible_hits=admissible_hits,
        unresolved=unresolved,
        p_upper=p_upper,
        best_control_margin=best_control_margin,
        adequacy_pass=adequacy_pass,
        adequacy_reasons=adequacy_reasons,
        hit_admissibility_pass=hit_admissibility_pass,
        hit_admissibility_reasons=hit_admissibility_reasons,
        positive_control_recall_lcb=positive_lcb,
        positive_control_successes=adequacy.positive_control_successes,
        positive_control_trials=adequacy.positive_control_trials,
        adequacy_calibration_id=adequacy.calibration_id,
        adequacy_manifest_hash=adequacy.checks_manifest_hash,
        a_i=a_i,
        reason=reason,
    )


def evaluate_gate2(
    reg: Registration, ev: Gate2Evidence, astar: ArtifactScores
) -> Gate2Result:
    summary = recovery_from_controls(
        reg,
        ev.controls,
        astar,
        ev.adequacy,
        alpha_bound=reg.alpha_recovery,
        rho_threshold=reg.rho,
        expected_scope_contract_hash=reg.gate2_control_contract_hash,
        expected_distribution_hash=reg.challenge_distribution_hash,
    )
    return Gate2Result(
        no_feedback_recovery=summary.recovery,
        classifications=summary.classifications,
        n_started=summary.n_started,
        n_evaluable=summary.n_evaluable,
        n_ind=summary.n_ind,
        hits=summary.hits,
        admissible_hits=summary.admissible_hits,
        unresolved=summary.unresolved,
        p_upper=summary.p_upper,
        best_control_margin=summary.best_control_margin,
        adequacy_pass=summary.adequacy_pass,
        adequacy_reasons=summary.adequacy_reasons,
        hit_admissibility_pass=summary.hit_admissibility_pass,
        hit_admissibility_reasons=summary.hit_admissibility_reasons,
        positive_control_recall_lcb=summary.positive_control_recall_lcb,
        positive_control_successes=summary.positive_control_successes,
        positive_control_trials=summary.positive_control_trials,
        adequacy_calibration_id=summary.adequacy_calibration_id,
        adequacy_manifest_hash=summary.adequacy_manifest_hash,
        a_i=summary.a_i,
        reason=summary.reason,
    )
