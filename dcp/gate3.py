"""Gate 3 — randomized feedback effect and bound neutral recovery.

The neutral branch of every randomized pair is the recovery record.  There is
no second, freely selectable ``neutral_controls`` cohort to splice into a
necessity claim.
"""

from __future__ import annotations

import math
from typing import Optional

from dcp.gate2 import classify_control, recovery_from_controls
from dcp.integrity import (
    neutral_contract_matches,
    neutral_scope_matches,
)
from dcp.registration import Registration
from dcp.replacements import (
    feedback_replacement_ledger,
    sham_replacement_ledger,
)
from dcp.stats import (
    Interval,
    bounded_empirical_bernstein_interval,
    bonferroni_share,
    paired_binary_interval,
)
from dcp.types import (
    AdequacyEvidence,
    ArtifactScores,
    AttemptStatus,
    BranchOutcome,
    ControlAttempt,
    ControlClassification,
    EffectStatus,
    FeedbackPair,
    Gate3Evidence,
    Gate3Result,
    IntegrityEvidence,
    RawAttemptOutcome,
    Recovery,
    ShamPair,
    TriState,
    Validity,
)


def _inconclusive_interval(n: int = 0) -> Interval:
    return Interval(
        mean=float("nan"),
        lcb=float("-inf"),
        ucb=float("inf"),
        se=float("inf"),
        half_width=float("inf"),
        n=n,
        coverage=0.0,
    )


def _effect_unit(pair: FeedbackPair | ShamPair) -> str:
    return pair.block_id or pair.pair_id


def _control_from_branch(
    reg: Registration, pair: FeedbackPair, branch: BranchOutcome
) -> ControlAttempt:
    return ControlAttempt(
        attempt_id=branch.branch_id,
        outcome=branch.outcome,
        per_unit=branch.per_unit,
        validity=branch.validity,
        artifact_hash=branch.artifact_hash,
        unit_ids=branch.unit_ids,
        stratum=reg.recovery_stratum,
        # The branch execution contract is validated separately.  Recovery is
        # classified under its registered projection contract.
        scope_contract_hash=reg.gate3_neutral_recovery_contract_hash,
        prestart_contract_receipt_hash=branch.prestart_contract_receipt_hash,
        challenge_distribution_hash=pair.randomization_distribution_hash,
        independent_draw_receipt_hash=pair.randomization_draw_receipt_hash,
        independent_unit_id=_effect_unit(pair),
        independence_ok=pair.independence_ok,
        infrastructure_outcome_independent=branch.infrastructure_outcome_independent,
    )


def neutral_controls_from_pairs(
    reg: Registration, pairs: list[FeedbackPair] | tuple[FeedbackPair, ...]
) -> list[ControlAttempt]:
    return [_control_from_branch(reg, pair, pair.neutral) for pair in pairs]


def evaluate_neutral_hit_witness(
    reg: Registration,
    ev: Gate3Evidence,
    astar: ArtifactScores,
    integrity: IntegrityEvidence,
    eligible_pair_indices: list[int],
) -> tuple[list[ControlClassification], bool, bool]:
    """Classify only integrity-admissible neutral branches for a monotone hit.

    This path never makes a zero-hit claim.  It exists so a malformed truthful
    arm or sham calibration cannot erase a valid neutral artifact that reaches
    the registered outcome.
    """
    classifications: list[ControlClassification] = []
    alpha_each = bonferroni_share(reg.alpha_score, reg.m_max)
    for index in eligible_pair_indices:
        pair = ev.pairs[index]
        control = _control_from_branch(reg, pair, pair.neutral)
        classifications.append(
            classify_control(
                reg,
                control,
                astar,
                alpha_each,
                expected_scope_contract_hash=reg.gate3_neutral_recovery_contract_hash,
                expected_distribution_hash=reg.gate3_pair_randomization_distribution_hash,
            )
        )
    recovered = any(
        item.status == AttemptStatus.CONFIRMED_HIT for item in classifications
    )
    neutral_scope_ok = neutral_contract_matches(reg, integrity, ev)
    return (
        classifications,
        recovered and neutral_scope_ok,
        (recovered and neutral_scope_ok and neutral_scope_matches(reg, integrity, ev)),
    )


def _continuous_utility(
    reg: Registration,
    branch: BranchOutcome,
    *,
    derive_from_private_scores: bool = False,
) -> tuple[Optional[float], str]:
    if branch.outcome == RawAttemptOutcome.UNRESOLVED:
        return None, "branch outcome unresolved"
    if branch.outcome == RawAttemptOutcome.INFRASTRUCTURE_INVALID:
        return None, "infrastructure branch must be handled at pair level"
    if branch.outcome == RawAttemptOutcome.MODEL_FAILURE:
        if branch.utility is not None or branch.validity == Validity.VALID:
            return None, "declared branch failure conflicts with utility/validity"
        return reg.worst_utility, "ITT model failure"
    if branch.outcome == RawAttemptOutcome.EXECUTION_CONTRACT_VIOLATION:
        return None, "execution-contract violation is not an ITT model outcome"

    if branch.validity == Validity.INVALID:
        return reg.worst_utility, "ITT contract-invalid artifact"
    if branch.validity != Validity.VALID:
        return None, "branch artifact validity or utility unresolved"
    if derive_from_private_scores:
        if branch.per_unit is None or len(branch.per_unit) == 0:
            return None, "branch private verifier scores missing"
        utility = float(sum(branch.per_unit) / len(branch.per_unit))
        if branch.utility is not None and not math.isclose(
            float(branch.utility), utility, rel_tol=0.0, abs_tol=1e-12
        ):
            return None, "reported utility does not match frozen per-unit mapping"
    else:
        if branch.utility is None:
            return None, "branch artifact validity or utility unresolved"
        utility = float(branch.utility)
    if not math.isfinite(utility) or not (0.0 <= utility <= 1.0):
        return None, "branch utility must be finite in [0,1]"
    return utility, "valid branch"


def _binary_utility(
    reg: Registration,
    pair: FeedbackPair,
    branch: BranchOutcome,
    astar: ArtifactScores,
) -> tuple[Optional[float], str, Optional[dict]]:
    control = _control_from_branch(reg, pair, branch)
    classification = classify_control(
        reg,
        control,
        astar,
        bonferroni_share(reg.alpha_score, reg.m_max),
        expected_scope_contract_hash=reg.gate3_neutral_recovery_contract_hash,
        expected_distribution_hash=reg.gate3_pair_randomization_distribution_hash,
    )
    record = {
        "status": classification.status.value,
        "d_mean": classification.d_mean,
        "d_lcb": classification.d_lcb,
        "d_ucb": classification.d_ucb,
        "reason": classification.reason,
    }
    if classification.status == AttemptStatus.CONFIRMED_HIT:
        return 1.0, "P confirmed", record
    if classification.status in {
        AttemptStatus.CONFIRMED_MISS,
        AttemptStatus.MODEL_FAILURE,
    }:
        return 0.0, "P not reached", record
    return None, "P classification unresolved", record


def _feedback_differences(
    reg: Registration, ev: Gate3Evidence, astar: ArtifactScores
) -> tuple[list[float], list[str], int, int, list[str], list[dict]]:
    diffs: list[float] = []
    analyzed_ids: list[str] = []
    unresolved = 0
    infra_excluded = 0
    reasons: list[str] = []
    records: list[dict] = []

    if not (
        ev.design_checks_pass is True
        and ev.stopping_rule_pass is True
        and ev.registered_pairs_complete is True
    ):
        return (
            [],
            [],
            len(ev.pairs),
            0,
            ["paired design/stopping/completeness audit failed"],
            [],
        )

    ledger = feedback_replacement_ledger(
        ev.pairs,
        registered_n=reg.registered_n_feedback_pairs,
        max_replacements=reg.max_feedback_pair_replacements,
        policy=reg.gate3_pair_replacement_policy,
    )
    if not ledger.valid:
        return (
            [],
            [],
            len(ev.pairs),
            ledger.infrastructure_pair_count,
            list(ledger.errors),
            [],
        )
    active_indices = set(ledger.active_indices)
    infra_excluded = len(ledger.replaced_indices)

    for index, pair in enumerate(ev.pairs):
        record = {
            "pair_id": pair.pair_id,
            "replacement_of": pair.replacement_of,
            "block_id": pair.block_id,
            "randomization_distribution_hash": pair.randomization_distribution_hash,
            "randomization_draw_receipt_hash": pair.randomization_draw_receipt_hash,
            "truthful_branch_id": pair.truthful.branch_id,
            "neutral_branch_id": pair.neutral.branch_id,
            "truthful_artifact_hash": pair.truthful.artifact_hash,
            "neutral_artifact_hash": pair.neutral.artifact_hash,
            "truthful_result_hash": pair.truthful.verifier_result_hash,
            "neutral_result_hash": pair.neutral.verifier_result_hash,
            "truthful_raw_utility": pair.truthful.utility,
            "neutral_raw_utility": pair.neutral.utility,
            "status": "unresolved",
            "reason": "",
        }
        if index not in active_indices:
            record.update(
                status="replaced_infrastructure",
                reason="retained in the started ledger; terminal replacement analyzed",
            )
            records.append(record)
            continue
        if pair.assignment_frozen is not True or pair.independence_ok is not True:
            unresolved += 1
            record["reason"] = "assignment or independent-unit audit failed"
            reasons.append(f"pair {pair.pair_id}: {record['reason']}")
            records.append(record)
            continue
        branches = (pair.truthful, pair.neutral)
        infra = [
            branch
            for branch in branches
            if branch.outcome == RawAttemptOutcome.INFRASTRUCTURE_INVALID
        ]
        if infra:
            if all(
                branch.infrastructure_outcome_independent
                and branch.utility is None
                and branch.per_unit is None
                for branch in infra
            ):
                infra_excluded += 1
                record.update(
                    status="infrastructure_excluded",
                    reason="whole randomized pair excluded",
                )
            else:
                unresolved += 1
                record["reason"] = "informative/ambiguous infrastructure attrition"
                reasons.append(f"pair {pair.pair_id}: {record['reason']}")
            records.append(record)
            continue

        if reg.feedback_estimand == "binary":
            truthful, tr_reason, tr_p = _binary_utility(reg, pair, pair.truthful, astar)
            neutral, ne_reason, ne_p = _binary_utility(reg, pair, pair.neutral, astar)
            record["truthful_p_classification"] = tr_p
            record["neutral_p_classification"] = ne_p
        else:
            truthful, tr_reason = _continuous_utility(
                reg, pair.truthful, derive_from_private_scores=True
            )
            neutral, ne_reason = _continuous_utility(
                reg, pair.neutral, derive_from_private_scores=True
            )

        if truthful is None or neutral is None:
            unresolved += 1
            record["reason"] = f"{tr_reason}; {ne_reason}"
            reasons.append(f"pair {pair.pair_id}: {record['reason']}")
            records.append(record)
            continue
        difference = truthful - neutral
        diffs.append(difference)
        analyzed_ids.append(pair.pair_id)
        record.update(
            status="analyzed",
            reason="ITT pair included",
            truthful_analysis_utility=truthful,
            neutral_analysis_utility=neutral,
            difference=difference,
        )
        records.append(record)

    if len(diffs) != reg.registered_n_feedback_pairs:
        reasons.append(
            f"analyzed pairs {len(diffs)} != registered fixed N="
            f"{reg.registered_n_feedback_pairs}"
        )
        unresolved += 1
    return diffs, analyzed_ids, unresolved, infra_excluded, reasons, records


def _feedback_arm_health(
    reg: Registration, ev: Gate3Evidence
) -> tuple[bool, list[str], float, float, float, float, float]:
    """Detect arm-specific collapse that could manufacture an ITT contrast."""
    ledger = feedback_replacement_ledger(
        ev.pairs,
        registered_n=reg.registered_n_feedback_pairs,
        max_replacements=reg.max_feedback_pair_replacements,
        policy=reg.gate3_pair_replacement_policy,
    )
    active_pairs = (
        [ev.pairs[index] for index in ledger.active_indices]
        if ledger.valid
        else []
    )
    complete_pairs = [
        pair
        for pair in active_pairs
        if all(
            branch.outcome != RawAttemptOutcome.INFRASTRUCTURE_INVALID
            for branch in (pair.truthful, pair.neutral)
        )
    ]

    def rates(which: str) -> tuple[float, float]:
        branches = [getattr(pair, which) for pair in complete_pairs]
        if not branches:
            return 0.0, 1.0
        valid_rate = sum(
            branch.outcome == RawAttemptOutcome.ARTIFACT
            and branch.validity == Validity.VALID
            for branch in branches
        ) / len(branches)
        failure_rate = sum(
            branch.outcome == RawAttemptOutcome.MODEL_FAILURE
            or (
                branch.outcome == RawAttemptOutcome.ARTIFACT
                and branch.validity == Validity.INVALID
            )
            for branch in branches
        ) / len(branches)
        return valid_rate, failure_rate

    truthful_valid, truthful_failures = rates("truthful")
    neutral_valid, neutral_failures = rates("neutral")
    infra_rate = (
        ledger.infrastructure_pair_count / len(ev.pairs) if ev.pairs else 1.0
    )
    reasons: list[str] = list(ledger.errors)
    if min(truthful_valid, neutral_valid) < reg.min_feedback_arm_valid_rate:
        reasons.append(
            "one feedback arm has a valid-artifact rate below the registered floor"
        )
    if (
        max(truthful_failures, neutral_failures)
        > reg.max_feedback_arm_model_failure_rate
    ):
        reasons.append(
            "one feedback arm has a model-failure rate above the registered cap"
        )
    if infra_rate > reg.max_feedback_pair_infrastructure_rate:
        reasons.append("paired infrastructure-failure rate exceeds the registered cap")
    return (
        not reasons,
        reasons,
        truthful_valid,
        neutral_valid,
        truthful_failures,
        neutral_failures,
        infra_rate,
    )


def _calibration_utility(
    reg: Registration, branch: BranchOutcome
) -> tuple[Optional[float], str]:
    # Calibration uses the same [0,1] scale and ITT failure mapping, but its
    # null-task artifacts do not share the target task's private-unit manifest.
    utility, reason = _continuous_utility(reg, branch)
    if (
        utility is not None
        and reg.feedback_estimand == "binary"
        and utility not in (0.0, 1.0)
    ):
        return None, "binary sham calibration requires 0/1 utility"
    return utility, reason


def evaluate_sham_adequacy(
    reg: Registration, ev: Gate3Evidence
) -> tuple[TriState, Interval, str, list[dict]]:
    sham = ev.sham
    metadata_matches = all(
        (
            sham.calibration_id == reg.sham_calibration_id,
            sham.task_family_profile == reg.task_family_profile,
            sham.model_id == reg.model_id,
            sham.interface_hash == reg.interface_hash,
            sham.scaffold_hash == reg.scaffold_hash,
            sham.feedback_schema_hash == reg.feedback_schema_hash,
            sham.operator_hash == reg.sham_operator_hash,
            sham.reference_null_generator_hash == reg.reference_null_generator_hash,
            sham.paired_arm_contract_hash == reg.sham_paired_arm_contract_hash,
            sham.reference_arm_contract_hash == reg.sham_reference_arm_contract_hash,
            sham.proposed_arm_contract_hash == reg.sham_proposed_arm_contract_hash,
            sham.utility_scale_id == reg.utility_scale_id,
            bool(sham.development_manifest_hash),
            bool(sham.confirmatory_manifest_hash),
            sham.development_manifest_hash != sham.confirmatory_manifest_hash,
        )
    )
    if not metadata_matches:
        return (
            TriState.INCONCLUSIVE,
            _inconclusive_interval(),
            "sham calibration metadata mismatch",
            [],
        )
    if not (
        sham.freshness_pass is True
        and sham.operator_frozen_before_confirmatory is True
        and sham.development_confirmatory_disjoint is True
    ):
        return (
            TriState.INCONCLUSIVE,
            _inconclusive_interval(),
            "confirmatory sham provenance incomplete",
            [],
        )
    if sham.channel_checks_pass is not True:
        return (
            TriState.FAIL,
            _inconclusive_interval(),
            "sham channel checks failed",
            [],
        )

    ledger = sham_replacement_ledger(
        sham.pairs,
        registered_n=reg.registered_n_sham_pairs,
        max_replacements=reg.max_sham_pair_replacements,
        policy=reg.gate3_pair_replacement_policy,
    )
    if not ledger.valid:
        return (
            TriState.INCONCLUSIVE,
            _inconclusive_interval(),
            "; ".join(ledger.errors),
            [],
        )
    active_indices = set(ledger.active_indices)
    diffs: list[float] = []
    records: list[dict] = []
    unresolved = 0
    for index, pair in enumerate(sham.pairs):
        record = {
            "pair_id": pair.pair_id,
            "replacement_of": pair.replacement_of,
            "block_id": pair.block_id,
            "randomization_distribution_hash": pair.randomization_distribution_hash,
            "randomization_draw_receipt_hash": pair.randomization_draw_receipt_hash,
            "reference_branch_id": pair.reference_null.branch_id,
            "proposed_branch_id": pair.proposed_sham.branch_id,
            "reference_result_hash": pair.reference_null.verifier_result_hash,
            "proposed_result_hash": pair.proposed_sham.verifier_result_hash,
            "status": "unresolved",
            "reason": "",
        }
        if index not in active_indices:
            record.update(
                status="replaced_infrastructure",
                reason="retained in the started ledger; terminal replacement analyzed",
            )
            records.append(record)
            continue
        if pair.assignment_frozen is not True or pair.independence_ok is not True:
            unresolved += 1
            record["reason"] = "sham assignment or independent-unit audit failed"
            records.append(record)
            continue
        branches = (pair.reference_null, pair.proposed_sham)
        infra = [
            branch
            for branch in branches
            if branch.outcome == RawAttemptOutcome.INFRASTRUCTURE_INVALID
        ]
        if infra:
            if all(
                branch.infrastructure_outcome_independent and branch.utility is None
                for branch in infra
            ):
                record.update(
                    status="infrastructure_excluded",
                    reason="whole sham pair excluded",
                )
            else:
                record["reason"] = "ambiguous sham infrastructure attrition"
            unresolved += 1
            records.append(record)
            continue
        reference, ref_reason = _calibration_utility(reg, pair.reference_null)
        proposed, prop_reason = _calibration_utility(reg, pair.proposed_sham)
        if reference is None or proposed is None:
            unresolved += 1
            record["reason"] = f"{ref_reason}; {prop_reason}"
            records.append(record)
            continue
        difference = reference - proposed
        diffs.append(difference)
        record.update(
            status="analyzed",
            reason="ITT sham pair included",
            reference_utility=reference,
            proposed_utility=proposed,
            difference=difference,
        )
        records.append(record)

    def arm_rates(position: int) -> tuple[float, float]:
        arm = [
            (pair.reference_null, pair.proposed_sham)[position]
            for index, pair in enumerate(sham.pairs)
            if index in active_indices
            if (pair.reference_null, pair.proposed_sham)[position].outcome
            != RawAttemptOutcome.INFRASTRUCTURE_INVALID
        ]
        if not arm:
            return 0.0, 1.0
        valid = sum(
            branch.outcome == RawAttemptOutcome.ARTIFACT
            and branch.validity == Validity.VALID
            for branch in arm
        ) / len(arm)
        failures = sum(
            branch.outcome == RawAttemptOutcome.MODEL_FAILURE
            or (
                branch.outcome == RawAttemptOutcome.ARTIFACT
                and branch.validity == Validity.INVALID
            )
            for branch in arm
        ) / len(arm)
        return valid, failures

    reference_valid, reference_failures = arm_rates(0)
    proposed_valid, proposed_failures = arm_rates(1)
    infra_rate = (
        ledger.infrastructure_pair_count
        / len(sham.pairs)
        if sham.pairs
        else 1.0
    )
    if (
        min(reference_valid, proposed_valid) < reg.min_valid_candidate_rate
        or max(reference_failures, proposed_failures) > reg.max_model_failure_rate
        or infra_rate > reg.max_infrastructure_failure_rate
    ):
        return (
            TriState.FAIL,
            _inconclusive_interval(len(diffs)),
            "sham valid-submission or attrition-rate checks failed",
            records,
        )
    if unresolved or len(diffs) != reg.registered_n_sham_pairs:
        return (
            TriState.INCONCLUSIVE,
            _inconclusive_interval(len(diffs)),
            "sham fixed sample is incomplete or unresolved",
            records,
        )
    ci = (
        paired_binary_interval(diffs, 1.0 - reg.alpha_sham)
        if reg.feedback_estimand == "binary"
        else bounded_empirical_bernstein_interval(diffs, 1.0 - reg.alpha_sham)
    )
    if ci.degenerate:
        return (
            TriState.INCONCLUSIVE,
            ci,
            "sham equivalence interval unresolved",
            records,
        )
    if ci.lcb >= -reg.delta_sham and ci.ucb <= reg.delta_sham:
        return TriState.PASS, ci, "confirmatory sham equivalence passed", records
    if ci.lcb > reg.delta_sham or ci.ucb < -reg.delta_sham:
        return (
            TriState.FAIL,
            ci,
            "confirmatory sham difference lies outside equivalence band",
            records,
        )
    return (
        TriState.INCONCLUSIVE,
        ci,
        "sham interval crosses equivalence boundary",
        records,
    )


def evaluate_gate3(
    reg: Registration,
    ev: Gate3Evidence,
    astar: ArtifactScores,
    integrity: IntegrityEvidence,
) -> Gate3Result:
    sham_adequacy, sham_ci, sham_reason, sham_records = evaluate_sham_adequacy(reg, ev)
    (
        diffs,
        analyzed_ids,
        pair_unresolved,
        infra_excluded,
        pair_reasons,
        pair_records,
    ) = _feedback_differences(reg, ev, astar)
    (
        branch_health_pass,
        branch_health_reasons,
        truthful_valid_rate,
        neutral_valid_rate,
        truthful_failure_rate,
        neutral_failure_rate,
        pair_infra_rate,
    ) = _feedback_arm_health(reg, ev)
    if not diffs:
        eff = _inconclusive_interval()
    elif reg.feedback_estimand == "binary":
        eff = paired_binary_interval(diffs, 1.0 - reg.alpha_evidence)
    else:
        eff = bounded_empirical_bernstein_interval(diffs, 1.0 - reg.alpha_evidence)

    if not branch_health_pass:
        effect = EffectStatus.INCONCLUSIVE
        effect_reason = "; ".join(branch_health_reasons)
    elif sham_adequacy != TriState.PASS:
        effect = EffectStatus.INCONCLUSIVE
        effect_reason = f"sham_adequacy={sham_adequacy.value}"
    elif pair_unresolved or eff.degenerate:
        effect = EffectStatus.INCONCLUSIVE
        effect_reason = "; ".join(pair_reasons) or "feedback interval unresolved"
    elif eff.lcb - reg.delta_sham >= reg.delta_evidence:
        effect = EffectStatus.SUPPORTED
        effect_reason = "bias-adjusted feedback lower bound reaches delta_evidence"
    elif eff.ucb + reg.delta_sham < reg.delta_evidence:
        effect = EffectStatus.NOT_SUPPORTED
        effect_reason = "bias-adjusted feedback upper bound is below delta_evidence"
    else:
        effect = EffectStatus.INCONCLUSIVE
        effect_reason = "feedback interval crosses the adjusted evidence boundary"

    feedback_ledger = feedback_replacement_ledger(
        ev.pairs,
        registered_n=reg.registered_n_feedback_pairs,
        max_replacements=reg.max_feedback_pair_replacements,
        policy=reg.gate3_pair_replacement_policy,
    )
    active_feedback_pairs = (
        [ev.pairs[index] for index in feedback_ledger.active_indices]
        if feedback_ledger.valid
        else []
    )
    neutral_controls = neutral_controls_from_pairs(reg, active_feedback_pairs)
    neutral = recovery_from_controls(
        reg,
        neutral_controls,
        astar,
        ev.neutral_adequacy or AdequacyEvidence(),
        alpha_bound=reg.alpha_neutral,
        rho_threshold=reg.rho_placebo,
        expected_scope_contract_hash=reg.gate3_neutral_recovery_contract_hash,
        expected_distribution_hash=reg.gate3_pair_randomization_distribution_hash,
        hit_admissibility_override=(
            neutral_contract_matches(reg, integrity, ev),
            []
            if neutral_contract_matches(reg, integrity, ev)
            else ["neutral branch contract/channel audit is not admissible"],
        ),
    )
    in_gate2_scope = neutral_scope_matches(reg, integrity, ev)
    lineage_empty_hit = neutral.recovery == Recovery.RECOVERED and in_gate2_scope
    reason = f"{sham_reason}; {effect_reason}"
    return Gate3Result(
        checkpoint_scope=ev.checkpoint_scope,
        checkpoint_hash=ev.checkpoint_hash,
        window_hash=ev.window_hash,
        feedback_pairs_manifest_hash=ev.feedback_pairs_manifest_hash,
        design_checks_pass=ev.design_checks_pass,
        stopping_rule_pass=ev.stopping_rule_pass,
        registered_pairs_complete=ev.registered_pairs_complete,
        all_started_pairs_disclosed=ev.all_started_pairs_disclosed,
        no_pair_replacements=ev.no_pair_replacements,
        paired_contract_audit_pass=ev.paired_contract_audit_pass,
        truthful_channel_audit_pass=ev.truthful_channel_audit_pass,
        neutral_channel_audit_pass=ev.neutral_channel_audit_pass,
        started_pair_count=ev.started_pair_count,
        paired_arm_contract_hash=ev.paired_arm_contract_hash,
        truthful_arm_contract_hash=ev.truthful_arm_contract_hash,
        neutral_arm_contract_hash=ev.neutral_arm_contract_hash,
        neutral_recovery_contract_hash=ev.neutral_recovery_contract_hash,
        truthful_feedback_generator_hash=ev.truthful_feedback_generator_hash,
        neutral_sham_generator_hash=ev.neutral_sham_generator_hash,
        contract_preseal_receipt_hash=ev.contract_preseal_receipt_hash,
        contract_sealed_before_branches_pass=ev.contract_sealed_before_branches_pass,
        contract_sealed_event_index=ev.contract_sealed_event_index,
        first_branch_started_event_index=ev.first_branch_started_event_index,
        neutral_scope_audit_manifest_hash=ev.neutral_scope_audit_manifest_hash,
        neutral_challenger_policy_hash=ev.neutral_challenger_policy_hash,
        neutral_scope_contract={
            "model_id": ev.neutral_model_id,
            "interface_hash": ev.neutral_interface_hash,
            "resource_contract_hash": ev.neutral_resource_contract_hash,
            "k_manifest_hash": ev.neutral_k_manifest_hash,
            "e0_manifest_hash": ev.neutral_e0_manifest_hash,
            "web_manifest_hash": ev.neutral_web_manifest_hash,
            "opportunity_contract_hash": ev.neutral_opportunity_contract_hash,
            "challenger_policy_hash": ev.neutral_challenger_policy_hash,
        },
        sham_adequacy=sham_adequacy,
        feedback_effect=effect,
        effect_mean=None if not math.isfinite(eff.mean) else eff.mean,
        effect_lcb=None if not math.isfinite(eff.lcb) else eff.lcb,
        effect_ucb=None if not math.isfinite(eff.ucb) else eff.ucb,
        n_pairs_started=len(ev.pairs),
        n_pairs_analyzed=len(diffs),
        pair_ids_analyzed=analyzed_ids,
        pair_records=pair_records,
        pairs_unresolved=pair_unresolved,
        pairs_infrastructure_excluded=infra_excluded,
        truthful_valid_rate=truthful_valid_rate,
        neutral_valid_rate=neutral_valid_rate,
        truthful_model_failure_rate=truthful_failure_rate,
        neutral_model_failure_rate=neutral_failure_rate,
        pair_infrastructure_failure_rate=pair_infra_rate,
        branch_health_pass=branch_health_pass,
        branch_health_reasons=branch_health_reasons,
        sham_delta_null_mean=None if not math.isfinite(sham_ci.mean) else sham_ci.mean,
        sham_delta_null_lcb=None if not math.isfinite(sham_ci.lcb) else sham_ci.lcb,
        sham_delta_null_ucb=None if not math.isfinite(sham_ci.ucb) else sham_ci.ucb,
        sham_n=sham_ci.n,
        sham_all_started_pairs_disclosed=ev.sham.all_started_pairs_disclosed,
        sham_no_pair_replacements=ev.sham.no_pair_replacements,
        sham_started_pair_count=ev.sham.started_pair_count,
        sham_pair_records=sham_records,
        sham_development_manifest_hash=ev.sham.development_manifest_hash,
        sham_confirmatory_manifest_hash=ev.sham.confirmatory_manifest_hash,
        sham_paired_arm_contract_hash=ev.sham.paired_arm_contract_hash,
        sham_reference_arm_contract_hash=ev.sham.reference_arm_contract_hash,
        sham_proposed_arm_contract_hash=ev.sham.proposed_arm_contract_hash,
        sham_reference_null_generator_hash=ev.sham.reference_null_generator_hash,
        sham_contract_preseal_receipt_hash=ev.sham.contract_preseal_receipt_hash,
        sham_contract_sealed_event_index=ev.sham.contract_sealed_event_index,
        sham_first_branch_started_event_index=ev.sham.first_branch_started_event_index,
        neutral_recovery=neutral.recovery,
        neutral_adequacy_pass=neutral.adequacy_pass,
        neutral_adequacy_reasons=neutral.adequacy_reasons,
        neutral_positive_control_recall_lcb=neutral.positive_control_recall_lcb,
        neutral_positive_control_successes=neutral.positive_control_successes,
        neutral_positive_control_trials=neutral.positive_control_trials,
        neutral_adequacy_calibration_id=neutral.adequacy_calibration_id,
        neutral_adequacy_manifest_hash=neutral.adequacy_manifest_hash,
        neutral_classifications=neutral.classifications,
        neutral_n_ind=neutral.n_ind,
        neutral_hits=neutral.hits,
        neutral_admissible_hits=neutral.admissible_hits,
        neutral_unresolved=neutral.unresolved,
        neutral_p_upper=neutral.p_upper,
        neutral_reason=neutral.reason,
        neutral_in_gate2_scope=in_gate2_scope,
        lineage_empty_hit_refutes_core=lineage_empty_hit,
        reason=reason,
        neutral_contract_audit_pass=ev.neutral_contract_audit_pass,
    )
