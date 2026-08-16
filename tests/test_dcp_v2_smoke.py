"""Smoke + adversarial regression tests for the DCP-v2 evaluation core."""

from __future__ import annotations

import json
import importlib

import numpy as np

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
from dcp.registration import (
    PAIR_REPLACEMENT_POLICY_TRANSPORT,
    validate_registration,
)
from dcp.replacements import feedback_replacement_ledger
from dcp.stats import (
    equivalence_verdict,
    paired_binary_interval,
    paired_ci,
    zero_hit_upper_bound,
)
from dcp.types import (
    AdequacyEvidence,
    ArtifactScores,
    BranchOutcome,
    ControlAttempt,
    CoreVerdict,
    EffectStatus,
    EvidenceVerdict,
    FeedbackPair,
    Gate1Evidence,
    Gate2Evidence,
    Gate3Evidence,
    InconclusiveClass,
    RawAttemptOutcome,
    Recovery,
    ShamCalibration,
    ShamPair,
    TriState,
    Validity,
)

N_UNITS = 200
UNIT_IDS = tuple(f"private-{i}" for i in range(N_UNITS))


def scores(
    mean: float, n: int = N_UNITS, spread: float = 0.01, seed: int = 0
) -> list[float]:
    return list(np.random.default_rng(seed).normal(mean, spread, n))


def artifact(
    name: str,
    mean: float,
    *,
    seed: int,
    validity: Validity = Validity.VALID,
    unit_ids=UNIT_IDS,
) -> ArtifactScores:
    return ArtifactScores(
        name=name,
        per_unit=scores(mean, n=len(unit_ids), seed=seed),
        validity=validity,
        artifact_hash=f"sha256:{name}:{seed}",
        unit_ids=tuple(unit_ids),
    )


def base_registration(**over) -> Registration:
    values = dict(
        claim_id="smoke",
        audit_family_id="smoke-family-v1",
        model_id="model:test-v1",
        interface_hash="sha256:interface",
        task_family_profile="synthetic-optimizer-v1",
        inference_scope="exhaustive_finite_set",
        ci_method="finite_set_exact",
        delta_min=0.10,
        kappa=0.5,
        m_max=100,
        gate2_control_contract_hash="sha256:gate2-control-contract",
        challenge_distribution_hash="sha256:challenge-QB",
        audit_slot_id="audit-slot-001",
        audit_slot_reservation_receipt_hash="sha256:alpha-ledger-receipt",
    )
    values.update(over)
    return Registration(**values)


def evidence_registration(**over) -> Registration:
    values = dict(
        grade_requested="evidence",
        scaffold_hash="sha256:scaffold",
        feedback_schema_hash="sha256:feedback-schema",
        sham_operator_hash="sha256:sham-operator",
        utility_scale_id="utility:[0,1]:v1",
        sham_calibration_id="sham-confirmatory-v1",
        registered_n_feedback_pairs=200,
        registered_n_sham_pairs=1600,
        m_max=500,
        gate3_checkpoint_scope="lineage_prefix",
        gate3_paired_arm_contract_hash="sha256:gate3-paired-contract",
        gate3_truthful_arm_contract_hash="sha256:gate3-truthful-arm-contract",
        gate3_neutral_arm_contract_hash="sha256:gate3-neutral-arm-contract",
        gate3_neutral_recovery_contract_hash="sha256:gate3-neutral-recovery-contract",
        gate3_checkpoint_selection_rule_hash="sha256:selection-rule",
        gate3_resource_contract_hash="sha256:resource-contract",
        gate3_opportunity_contract_hash="sha256:opportunity-contract",
        gate3_branch_policy_hash="sha256:challenger-policy",
        truthful_feedback_generator_hash="sha256:truthful-feedback-generator",
        neutral_sham_generator_hash="sha256:sham-operator",
        gate3_pair_randomization_distribution_hash="sha256:gate3-pair-Q",
        sham_randomization_distribution_hash="sha256:sham-pair-Q",
        sham_paired_arm_contract_hash="sha256:sham-paired-contract",
        sham_reference_arm_contract_hash="sha256:sham-reference-contract",
        sham_proposed_arm_contract_hash="sha256:sham-proposed-contract",
        reference_null_generator_hash="sha256:reference-null-generator",
    )
    values.update(over)
    if values.get("feedback_estimand") == "binary":
        values.setdefault("feedback_utility_mapping", "canonical_p_wrapper_v1")
        values.setdefault("feedback_ci_method", "paired_binary_exact")
        values.setdefault("sham_ci_method", "paired_binary_exact")
        if "registered_n_sham_pairs" not in over:
            values["registered_n_sham_pairs"] = 400
    return base_registration(**values)


def gate1_ev(
    astar_mean: float = 0.90,
    baseline_mean: float = 0.70,
    astar_validity: Validity = Validity.VALID,
    baseline_validity: Validity = Validity.VALID,
) -> Gate1Evidence:
    return Gate1Evidence(
        astar=artifact("A*", astar_mean, seed=1, validity=astar_validity),
        baseline=artifact(
            "baseline", baseline_mean, seed=2, validity=baseline_validity
        ),
    )


def integrity_for(
    g1: Gate1Evidence,
    g2: Gate2Evidence | None = None,
    g3: Gate3Evidence | None = None,
    **over,
) -> IntegrityEvidence:
    g2 = g2 or Gate2Evidence()
    verifier_hash = "sha256:verifier-v1"
    values = dict(
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
        astar_hash=g1.astar.artifact_hash,
        baseline_hash=g1.baseline.artifact_hash,
        verifier_hash=verifier_hash,
        astar_results_hash=artifact_results_hash(g1.astar),
        baseline_results_hash=artifact_results_hash(g1.baseline),
        private_unit_manifest_hash=unit_manifest_hash(g1.astar.unit_ids),
        private_results_manifest_hash=private_results_manifest_hash(
            g1.astar, g1.baseline, verifier_hash
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
        recovery_ledger_manifest_hash=recovery_ledger_manifest_hash(g2.controls, g3),
        gate2_recovery_ledger_manifest_hash=recovery_ledger_manifest_hash(g2.controls),
        gate3_neutral_scope_manifest_hash=(
            gate3_neutral_scope_manifest_hash(g3, "sha256:selection-rule")
            if g3 is not None
            else ""
        ),
        gate3_neutral_recovery_ledger_manifest_hash=(
            gate3_neutral_recovery_ledger_manifest_hash(g3) if g3 is not None else ""
        ),
        gate3_contract_preseal_receipt_hash="sha256:gate3-preseal-receipt",
        sham_contract_preseal_receipt_hash="sha256:sham-preseal-receipt",
        claim_family_manifest_hash="sha256:claim-family",
        alpha_ledger_receipt_hash="sha256:alpha-ledger-receipt",
        audit_slot_registry_entry_hash="sha256:audit-slot-registry-entry",
        human_assistance="none",
        attribution_subject="autonomous_agent",
        web_access_used=False,
        web_replay_scope="not_used",
    )
    values.update(over)
    return IntegrityEvidence(**values)


def passing_adequacy() -> AdequacyEvidence:
    result = AdequacyEvidence(
        matched_model_present=True,
        materials_readable=True,
        opportunity_floor_met=True,
        health_audit_pass=True,
        positive_control_successes=99,
        positive_control_trials=100,
        calibration_id="positive-controls-v1",
    )
    result.checks_manifest_hash = adequacy_evidence_hash(result)
    return result


def controls(
    mean: float,
    count: int,
    *,
    spread: float = 0.01,
    seed0: int = 100,
    stratum: str = "matched",
    unit_ids=UNIT_IDS,
) -> list[ControlAttempt]:
    return [
        ControlAttempt(
            attempt_id=f"c{seed0 + i}",
            outcome=RawAttemptOutcome.ARTIFACT,
            per_unit=scores(mean, n=len(unit_ids), spread=spread, seed=seed0 + i),
            validity=Validity.VALID,
            artifact_hash=f"sha256:control:{seed0 + i}",
            unit_ids=tuple(unit_ids),
            stratum=stratum,
            scope_contract_hash="sha256:gate2-control-contract",
            prestart_contract_receipt_hash=f"sha256:control-prestart:{seed0 + i}",
            challenge_distribution_hash="sha256:challenge-QB",
            independent_draw_receipt_hash=f"sha256:challenge-draw:{seed0 + i}",
            independent_unit_id=f"rng:{seed0 + i}",
            independence_ok=True,
        )
        for i in range(count)
    ]


def gate2_ev(control_list=(), adequacy=None) -> Gate2Evidence:
    return Gate2Evidence(
        controls=list(control_list),
        adequacy=adequacy if adequacy is not None else passing_adequacy(),
    )


def feedback_pairs(
    truthful: float = 0.90,
    neutral: float = 0.60,
    *,
    count: int = 200,
    seed: int = 5000,
) -> list[FeedbackPair]:
    result = []
    for i in range(count):
        truthful_scores = scores(truthful, seed=10000 + seed + i)
        truthful_branch = BranchOutcome(
            outcome=RawAttemptOutcome.ARTIFACT,
            utility=float(np.mean(truthful_scores)),
            validity=Validity.VALID,
            branch_id=f"truthful-{i}",
            artifact_hash=f"sha256:truthful:{i}",
            execution_contract_hash="sha256:gate3-truthful-arm-contract",
            prestart_contract_receipt_hash=f"sha256:truthful-prestart:{i}",
            per_unit=truthful_scores,
            unit_ids=UNIT_IDS,
        )
        truthful_branch.verifier_result_hash = branch_result_hash(truthful_branch)
        neutral_scores = scores(neutral, seed=20000 + seed + i)
        neutral_branch = BranchOutcome(
            outcome=RawAttemptOutcome.ARTIFACT,
            utility=float(np.mean(neutral_scores)),
            validity=Validity.VALID,
            branch_id=f"neutral-{i}",
            artifact_hash=f"sha256:neutral:{i}",
            execution_contract_hash="sha256:gate3-neutral-arm-contract",
            prestart_contract_receipt_hash=f"sha256:neutral-prestart:{i}",
            per_unit=neutral_scores,
            unit_ids=UNIT_IDS,
        )
        neutral_branch.verifier_result_hash = branch_result_hash(neutral_branch)
        result.append(
            FeedbackPair(
                pair_id=f"pair-{i}",
                truthful=truthful_branch,
                neutral=neutral_branch,
                block_id=f"block-{i}",
                randomization_distribution_hash="sha256:gate3-pair-Q",
                randomization_draw_receipt_hash=f"sha256:gate3-pair-draw:{i}",
                assignment_frozen=True,
                independence_ok=True,
            )
        )
    return result


def failed_branch(
    *,
    branch_id: str,
    execution_contract_hash: str,
    infrastructure: bool,
) -> BranchOutcome:
    branch = BranchOutcome(
        outcome=(
            RawAttemptOutcome.INFRASTRUCTURE_INVALID
            if infrastructure
            else RawAttemptOutcome.MODEL_FAILURE
        ),
        validity=Validity.UNRESOLVED,
        branch_id=branch_id,
        execution_contract_hash=execution_contract_hash,
        prestart_contract_receipt_hash=f"sha256:prestart:{branch_id}",
        infrastructure_outcome_independent=infrastructure,
    )
    branch.verifier_result_hash = branch_result_hash(branch)
    return branch


def sham_calibration(
    reg: Registration,
    *,
    ref_mean: float = 0.80,
    proposed_mean: float = 0.80,
    count: int | None = None,
) -> ShamCalibration:
    count = reg.registered_n_sham_pairs if count is None else count
    if reg.feedback_estimand == "binary":
        refs = [float(i % 2) for i in range(count)]
        shams = list(refs)
    else:
        refs = scores(ref_mean, n=count, spread=0.001, seed=6001)
        shams = scores(proposed_mean, n=count, spread=0.001, seed=6002)
    pairs = []
    for i, (reference, proposed) in enumerate(zip(refs, shams)):
        reference_branch = BranchOutcome(
            outcome=RawAttemptOutcome.ARTIFACT,
            utility=reference,
            validity=Validity.VALID,
            branch_id=f"null-reference-{i}",
            artifact_hash=f"sha256:null-reference:{i}",
            execution_contract_hash="sha256:sham-reference-contract",
            prestart_contract_receipt_hash=f"sha256:sham-reference-prestart:{i}",
        )
        reference_branch.verifier_result_hash = branch_result_hash(reference_branch)
        proposed_branch = BranchOutcome(
            outcome=RawAttemptOutcome.ARTIFACT,
            utility=proposed,
            validity=Validity.VALID,
            branch_id=f"null-sham-{i}",
            artifact_hash=f"sha256:null-sham:{i}",
            execution_contract_hash="sha256:sham-proposed-contract",
            prestart_contract_receipt_hash=f"sha256:sham-proposed-prestart:{i}",
        )
        proposed_branch.verifier_result_hash = branch_result_hash(proposed_branch)
        pairs.append(
            ShamPair(
                pair_id=f"null-{i}",
                reference_null=reference_branch,
                proposed_sham=proposed_branch,
                block_id=f"null-block-{i}",
                randomization_distribution_hash=reg.sham_randomization_distribution_hash,
                randomization_draw_receipt_hash=f"sha256:sham-pair-draw:{i}",
                assignment_frozen=True,
                independence_ok=True,
            )
        )
    return ShamCalibration(
        pairs=pairs,
        calibration_id=reg.sham_calibration_id,
        development_manifest_hash="sha256:sham-development",
        confirmatory_manifest_hash=sham_pairs_manifest_hash(pairs),
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
        contract_preseal_receipt_hash="sha256:sham-preseal-receipt",
        contract_sealed_before_branches_pass=True,
        contract_sealed_event_index=50,
        first_branch_started_event_index=51,
        channel_checks_pass=True,
        freshness_pass=True,
        operator_frozen_before_confirmatory=True,
        development_confirmatory_disjoint=True,
        all_started_pairs_disclosed=True,
        no_pair_replacements=True,
        started_pair_count=len(pairs),
    )


def gate3_ev(
    reg: Registration,
    *,
    pairs=None,
    sham=None,
    neutral_adequacy=None,
    checkpoint_scope="lineage_prefix",
) -> Gate3Evidence:
    selected_pairs = (
        feedback_pairs(count=reg.registered_n_feedback_pairs)
        if pairs is None
        else pairs
    )
    for pair in selected_pairs:
        pair.randomization_distribution_hash = (
            reg.gate3_pair_randomization_distribution_hash
        )
    if reg.feedback_estimand == "binary":
        for pair in selected_pairs:
            pair.truthful.utility = None
            pair.neutral.utility = None
            pair.truthful.verifier_result_hash = branch_result_hash(pair.truthful)
            pair.neutral.verifier_result_hash = branch_result_hash(pair.neutral)
    selected_sham = (
        sham_calibration(reg, count=reg.registered_n_sham_pairs)
        if sham is None
        else sham
    )
    result = Gate3Evidence(
        pairs=selected_pairs,
        sham=selected_sham,
        neutral_adequacy=neutral_adequacy,
        design_checks_pass=True,
        stopping_rule_pass=True,
        registered_pairs_complete=True,
        all_started_pairs_disclosed=True,
        no_pair_replacements=True,
        paired_contract_audit_pass=True,
        truthful_channel_audit_pass=True,
        neutral_channel_audit_pass=True,
        started_pair_count=len(selected_pairs),
        checkpoint_scope=checkpoint_scope,
        checkpoint_hash="sha256:checkpoint",
        window_hash="sha256:window",
        feedback_pairs_manifest_hash=feedback_pairs_manifest_hash(selected_pairs),
        paired_arm_contract_hash=reg.gate3_paired_arm_contract_hash,
        truthful_arm_contract_hash=reg.gate3_truthful_arm_contract_hash,
        neutral_arm_contract_hash=reg.gate3_neutral_arm_contract_hash,
        neutral_recovery_contract_hash=reg.gate3_neutral_recovery_contract_hash,
        truthful_feedback_generator_hash=reg.truthful_feedback_generator_hash,
        neutral_sham_generator_hash=reg.neutral_sham_generator_hash,
        contract_preseal_receipt_hash="sha256:gate3-preseal-receipt",
        contract_sealed_before_branches_pass=True,
        contract_sealed_event_index=100,
        first_branch_started_event_index=101,
        neutral_model_id=reg.model_id,
        neutral_interface_hash=reg.interface_hash,
        neutral_resource_contract_hash="sha256:resource-contract",
        neutral_k_manifest_hash="sha256:K",
        neutral_e0_manifest_hash="sha256:E0",
        neutral_web_manifest_hash="sha256:W-obs-none",
        neutral_opportunity_contract_hash="sha256:opportunity-contract",
        neutral_challenger_policy_hash="sha256:challenger-policy",
        neutral_scope_audit_manifest_hash="pending",
    )
    result.neutral_scope_audit_manifest_hash = gate3_neutral_scope_manifest_hash(
        result, "sha256:selection-rule"
    )
    return result


def run(reg, g1, g2, g3=None, **kw):
    return evaluate(reg, g1, g2, g3, integrity=integrity_for(g1, g2, g3), **kw)


# Statistical primitives ---------------------------------------------------
def test_zero_hit_bound_matches_registered_examples():
    assert abs(zero_hit_upper_bound(59, 0.05) - 0.05) < 1e-3
    assert abs(zero_hit_upper_bound(72, 0.025) - 0.05) < 1e-3
    assert zero_hit_upper_bound(0, 0.05) == 1.0


def test_equivalence_rule_three_states():
    assert equivalence_verdict(np.linspace(-0.001, 0.001, 60), 0.02, 0.005) == "pass"
    assert (
        equivalence_verdict(0.2 + np.linspace(-0.001, 0.001, 60), 0.02, 0.005) == "fail"
    )
    assert (
        equivalence_verdict(np.random.default_rng(0).normal(0.0, 0.05, 60), 0.02, 0.005)
        == "inconclusive"
    )


def test_population_zero_variance_is_not_treated_as_exact():
    ci = paired_ci([0.1, 0.1], 0.95, method="student_t")
    assert ci.degenerate
    exact = paired_ci([0.1], 0.95, method="finite_set_exact")
    assert exact.lcb == exact.ucb == 0.1


def test_default_evidence_registration_is_numerically_valid():
    assert validate_registration(evidence_registration()) == []


# Core --------------------------------------------------------------------
def test_core_certified():
    reg, g1 = base_registration(), gate1_ev()
    cert = run(reg, g1, gate2_ev(controls(0.70, 80)))
    assert cert.verdict.core == CoreVerdict.CERTIFIED
    assert cert.gate2.no_feedback_recovery == Recovery.NOT_RECOVERED_WITHIN_SCOPE
    assert cert.verdict.core_inconclusive_class == InconclusiveClass.NULL


def test_core_refuted_by_any_recovery():
    reg, g1 = base_registration(), gate1_ev()
    ctrls = controls(0.70, 79) + controls(0.90, 1, seed0=900)
    cert = run(reg, g1, gate2_ev(ctrls))
    assert cert.verdict.core == CoreVerdict.REFUTED
    assert cert.gate2.hits == 1


def test_core_inconclusive_when_n_is_insufficient():
    reg, g1 = base_registration(m_max=40), gate1_ev()
    cert = run(reg, g1, gate2_ev(controls(0.70, 40)))
    assert cert.verdict.core == CoreVerdict.INCONCLUSIVE
    assert cert.gate2.p_upper > reg.rho
    assert (
        cert.verdict.core_inconclusive_class
        == InconclusiveClass.STATISTICAL_UNCERTAINTY
    )


def test_core_inconclusive_on_boundary_control():
    reg = base_registration(
        inference_scope="sampled_population",
        ci_method="bounded_empirical_bernstein",
    )
    g1 = gate1_ev(baseline_mean=0.50)
    ctrls = controls(0.50, 80) + controls(0.80, 1, spread=0.02, seed0=800)
    cert = run(reg, g1, gate2_ev(ctrls))
    assert cert.gate2.unresolved == 1
    assert cert.verdict.core == CoreVerdict.INCONCLUSIVE
    assert (
        cert.verdict.core_inconclusive_class
        == InconclusiveClass.STATISTICAL_UNCERTAINTY
    )


def test_missing_attempt_outcome_is_not_silently_counted_as_failure():
    reg, g1 = base_registration(m_max=80), gate1_ev()
    empty = [
        ControlAttempt(
            attempt_id=f"x{i}",
            stratum="matched",
            scope_contract_hash="sha256:gate2-control-contract",
            prestart_contract_receipt_hash=f"sha256:empty-prestart:{i}",
            challenge_distribution_hash="sha256:challenge-QB",
            independent_draw_receipt_hash=f"sha256:empty-draw:{i}",
            independent_unit_id=f"rng:x{i}",
            independence_ok=True,
        )
        for i in range(80)
    ]
    cert = run(reg, g1, gate2_ev(empty))
    assert cert.verdict.core == CoreVerdict.INCONCLUSIVE
    assert cert.gate2.unresolved == 80
    assert cert.verdict.core_inconclusive_class == InconclusiveClass.AUDIT_INCOMPLETE


def test_conflicting_failure_flag_cannot_hide_a_scored_hit():
    reg, g1 = base_registration(), gate1_ev()
    hidden = ControlAttempt(
        attempt_id="conflict",
        outcome=RawAttemptOutcome.MODEL_FAILURE,
        per_unit=scores(0.90, seed=123),
        validity=Validity.VALID,
        artifact_hash="sha256:hidden",
        unit_ids=UNIT_IDS,
        stratum="matched",
        scope_contract_hash="sha256:gate2-control-contract",
        prestart_contract_receipt_hash="sha256:hidden-prestart",
        challenge_distribution_hash="sha256:challenge-QB",
        independent_draw_receipt_hash="sha256:hidden-draw",
        independent_unit_id="rng:hidden",
        independence_ok=True,
    )
    cert = run(reg, g1, gate2_ev(controls(0.70, 80) + [hidden]))
    assert cert.verdict.core == CoreVerdict.INCONCLUSIVE
    assert any("conflicts with artifact data" in e for e in cert.integrity_errors)


def test_mmax_is_enforced_before_bonferroni_can_be_bypassed():
    reg, g1 = base_registration(m_max=1), gate1_ev()
    cert = run(reg, g1, gate2_ev(controls(0.70, 80)))
    assert cert.verdict.core == CoreVerdict.INCONCLUSIVE
    assert any("M_max" in e for e in cert.integrity_errors)


def test_duplicate_attempt_ids_fail_integrity():
    reg, g1 = base_registration(), gate1_ev()
    ctrls = controls(0.70, 80)
    ctrls[1].attempt_id = ctrls[0].attempt_id
    cert = run(reg, g1, gate2_ev(ctrls))
    assert cert.verdict.core == CoreVerdict.INCONCLUSIVE
    assert cert.integrity_errors


def test_heterogeneous_strata_cannot_be_pooled_post_hoc():
    reg, g1 = base_registration(), gate1_ev()
    ctrls = controls(0.70, 40) + controls(0.70, 40, seed0=1000, stratum="stronger")
    cert = run(reg, g1, gate2_ev(ctrls))
    assert cert.verdict.core == CoreVerdict.INCONCLUSIVE
    assert any("strata" in r for r in cert.gate2.adequacy_reasons)
    assert cert.verdict.core_inconclusive_class == InconclusiveClass.AUDIT_INCOMPLETE


def test_private_unit_mismatch_is_unresolved():
    reg, g1 = base_registration(), gate1_ev()
    bad_ids = tuple(reversed(UNIT_IDS))
    cert = run(reg, g1, gate2_ev(controls(0.70, 80, unit_ids=bad_ids)))
    assert cert.verdict.core == CoreVerdict.INCONCLUSIVE
    assert cert.gate2.unresolved == 80


def test_missing_integrity_envelope_is_fail_closed():
    reg, g1 = base_registration(), gate1_ev()
    cert = evaluate(reg, g1, gate2_ev(controls(0.70, 80)))
    assert cert.verdict.core == CoreVerdict.INCONCLUSIVE
    assert any("integrity evidence missing" in e for e in cert.integrity_errors)


def test_invalid_registration_returns_certificate_instead_of_crashing():
    reg, g1 = base_registration(m_max=0), gate1_ev()
    cert = run(reg, g1, gate2_ev())
    assert cert.verdict.core == CoreVerdict.INCONCLUSIVE
    assert cert.registration_errors
    assert cert.verdict.core_inconclusive_class == InconclusiveClass.AUDIT_INCOMPLETE


def test_nonfinite_scores_fail_closed():
    reg, g1 = base_registration(), gate1_ev()
    g1.astar.per_unit = [float("nan")] + list(g1.astar.per_unit[1:])
    cert = evaluate(reg, g1, gate2_ev(), integrity=integrity_for(g1))
    assert cert.verdict.core == CoreVerdict.INCONCLUSIVE
    assert cert.integrity_errors


def test_gate1_refutations_and_precedence():
    reg = base_registration()
    low = gate1_ev(astar_mean=0.78)
    assert (
        run(reg, low, gate2_ev(controls(0.60, 80))).verdict.core == CoreVerdict.REFUTED
    )

    invalid = gate1_ev(astar_validity=Validity.INVALID)
    assert (
        run(reg, invalid, gate2_ev(controls(0.70, 80))).verdict.core
        == CoreVerdict.REFUTED
    )

    both_invalid = gate1_ev(
        astar_validity=Validity.INVALID, baseline_validity=Validity.INVALID
    )
    assert (
        run(reg, both_invalid, gate2_ev(controls(0.70, 80))).verdict.core
        == CoreVerdict.INCONCLUSIVE
    )


# Gate 3 ------------------------------------------------------------------
def test_evidence_certified_with_confirmatory_sham_and_randomized_pairs():
    reg, g1 = evidence_registration(), gate1_ev()
    cert = run(reg, g1, gate2_ev(controls(0.70, 80)), gate3_ev(reg))
    assert cert.verdict.core == CoreVerdict.CERTIFIED
    assert cert.gate3.sham_adequacy == TriState.PASS
    assert cert.gate3.feedback_effect == EffectStatus.SUPPORTED
    assert cert.verdict.evidence == EvidenceVerdict.CERTIFIED
    assert cert.verdict.evidence_inconclusive_class == InconclusiveClass.NULL


def test_failed_or_nonconfirmatory_sham_blocks_evidence():
    reg, g1 = evidence_registration(), gate1_ev()
    bad = sham_calibration(reg, ref_mean=0.90, proposed_mean=0.70)
    cert = run(reg, g1, gate2_ev(controls(0.70, 80)), gate3_ev(reg, sham=bad))
    assert cert.gate3.sham_adequacy == TriState.FAIL
    assert cert.verdict.evidence == EvidenceVerdict.INCONCLUSIVE
    assert (
        cert.verdict.evidence_inconclusive_class == InconclusiveClass.AUDIT_INCOMPLETE
    )

    stale = sham_calibration(reg)
    stale.freshness_pass = False
    cert = run(reg, g1, gate2_ev(controls(0.70, 80)), gate3_ev(reg, sham=stale))
    assert cert.gate3.sham_adequacy == TriState.INCONCLUSIVE
    assert cert.verdict.evidence == EvidenceVerdict.INCONCLUSIVE
    assert (
        cert.verdict.evidence_inconclusive_class == InconclusiveClass.AUDIT_INCOMPLETE
    )


def test_confirmed_small_feedback_effect_refutes_evidence_grade():
    reg, g1 = (
        evidence_registration(registered_n_feedback_pairs=1600, m_max=3280),
        gate1_ev(),
    )
    pairs = feedback_pairs(truthful=0.61, neutral=0.60, count=1600)
    cert = run(reg, g1, gate2_ev(controls(0.70, 80)), gate3_ev(reg, pairs=pairs))
    assert cert.gate3.feedback_effect == EffectStatus.NOT_SUPPORTED
    assert cert.verdict.evidence == EvidenceVerdict.REFUTED


def test_binary_feedback_estimand_is_explicitly_supported():
    reg, g1 = evidence_registration(feedback_estimand="binary"), gate1_ev()
    pairs = feedback_pairs()
    for i, pair in enumerate(pairs[150:], start=150):
        pair.neutral.per_unit = scores(0.90, seed=30000 + i)
        pair.neutral.verifier_result_hash = branch_result_hash(pair.neutral)
    cert = run(reg, g1, gate2_ev(controls(0.70, 80)), gate3_ev(reg, pairs=pairs))
    assert cert.verdict.evidence == EvidenceVerdict.CERTIFIED
    assert (
        cert.gate3.pair_records[0]["neutral_p_classification"]["status"]
        == "confirmed_miss"
    )


def test_gate3_itt_records_failures_but_arm_collapse_blocks_evidence():
    reg, g1 = evidence_registration(), gate1_ev()
    pairs = feedback_pairs(truthful=0.30, neutral=0.20)
    for i, pair in enumerate(pairs):
        failure = BranchOutcome(
            outcome=RawAttemptOutcome.MODEL_FAILURE,
            branch_id=f"neutral-failure-{i}",
            execution_contract_hash="sha256:gate3-neutral-arm-contract",
            prestart_contract_receipt_hash=f"sha256:neutral-failure-prestart:{i}",
        )
        failure.verifier_result_hash = branch_result_hash(failure)
        pair.neutral = failure
    cert = run(reg, g1, gate2_ev(controls(0.70, 80)), gate3_ev(reg, pairs=pairs))
    assert cert.gate3.n_pairs_analyzed == 200
    assert cert.gate3.feedback_effect == EffectStatus.INCONCLUSIVE
    assert not cert.gate3.branch_health_pass

    unresolved = BranchOutcome(
        branch_id="neutral-unresolved-0",
        execution_contract_hash="sha256:gate3-neutral-arm-contract",
        prestart_contract_receipt_hash="sha256:neutral-unresolved-prestart:0",
    )
    unresolved.verifier_result_hash = branch_result_hash(unresolved)
    pairs[0].neutral = unresolved
    cert = run(reg, g1, gate2_ev(controls(0.70, 80)), gate3_ev(reg, pairs=pairs))
    assert cert.gate3.pairs_unresolved >= 1
    assert cert.verdict.evidence == EvidenceVerdict.INCONCLUSIVE


def test_gate3_rejects_out_of_range_normalized_utility():
    reg, g1 = evidence_registration(), gate1_ev()
    pairs = feedback_pairs()
    pairs[0].truthful.utility = 1.2
    cert = run(reg, g1, gate2_ev(controls(0.70, 80)), gate3_ev(reg, pairs=pairs))
    assert cert.verdict.evidence == EvidenceVerdict.INCONCLUSIVE


def test_neutral_recovery_requires_adequacy_and_uses_separate_bound_alpha():
    reg, g1 = evidence_registration(), gate1_ev()
    missing = gate3_ev(reg)
    cert = run(reg, g1, gate2_ev(controls(0.70, 80)), missing)
    assert cert.gate3.neutral_recovery == Recovery.INCONCLUSIVE

    complete = gate3_ev(
        reg,
        neutral_adequacy=passing_adequacy(),
    )
    cert = run(reg, g1, gate2_ev(controls(0.70, 80)), complete)
    assert cert.gate3.neutral_recovery == Recovery.NOT_RECOVERED_WITHIN_SCOPE
    assert (
        abs(cert.gate3.neutral_p_upper - zero_hit_upper_bound(200, reg.alpha_neutral))
        < 1e-12
    )


def test_missing_neutral_adequacy_cannot_hide_a_recovery_witness():
    reg, g1 = (
        evidence_registration(
            gate3_checkpoint_scope="lineage_empty",
            gate3_neutral_recovery_contract_hash="sha256:gate2-control-contract",
            gate3_pair_randomization_distribution_hash="sha256:challenge-QB",
        ),
        gate1_ev(),
    )
    pairs = feedback_pairs()
    pairs[0].neutral.per_unit = scores(0.90, seed=8800)
    pairs[0].neutral.utility = float(np.mean(pairs[0].neutral.per_unit))
    pairs[0].neutral.verifier_result_hash = branch_result_hash(pairs[0].neutral)
    g3 = gate3_ev(
        reg,
        pairs=pairs,
        checkpoint_scope="lineage_empty",
    )
    cert = run(reg, g1, gate2_ev(controls(0.70, 80)), g3)
    assert cert.gate3.neutral_recovery == Recovery.RECOVERED
    assert cert.verdict.core == CoreVerdict.REFUTED


def test_necessity_grade_and_lineage_empty_hit_have_distinct_effects():
    reg, g1 = evidence_registration(necessity_claim_requested=True), gate1_ev()
    pairs = feedback_pairs()
    pairs[0].neutral.per_unit = scores(0.90, seed=9000)
    pairs[0].neutral.utility = float(np.mean(pairs[0].neutral.per_unit))
    pairs[0].neutral.verifier_result_hash = branch_result_hash(pairs[0].neutral)
    late = gate3_ev(
        reg,
        pairs=pairs,
        neutral_adequacy=passing_adequacy(),
        checkpoint_scope="lineage_prefix",
    )
    cert = run(reg, g1, gate2_ev(controls(0.70, 80)), late)
    assert cert.verdict.core == CoreVerdict.CERTIFIED
    assert cert.verdict.evidence == EvidenceVerdict.REFUTED

    early_reg = evidence_registration(
        necessity_claim_requested=True,
        gate3_checkpoint_scope="lineage_empty",
        gate3_neutral_recovery_contract_hash="sha256:gate2-control-contract",
        gate3_pair_randomization_distribution_hash="sha256:challenge-QB",
    )
    early = gate3_ev(
        early_reg,
        pairs=pairs,
        neutral_adequacy=passing_adequacy(),
        checkpoint_scope="lineage_empty",
    )
    cert = run(early_reg, g1, gate2_ev(controls(0.70, 80)), early)
    assert cert.verdict.core == CoreVerdict.REFUTED


def test_global_mmax_includes_all_truthful_and_neutral_candidate_slots():
    reg, g1 = evidence_registration(m_max=479), gate1_ev()
    g3 = gate3_ev(reg, neutral_adequacy=passing_adequacy())
    cert = run(reg, g1, gate2_ev(controls(0.70, 80)), g3)
    assert cert.verdict.core == CoreVerdict.CERTIFIED
    assert cert.verdict.evidence == EvidenceVerdict.INCONCLUSIVE
    assert any("M_max" in e for e in cert.gate3_integrity_errors)


def test_certificate_is_strict_json_and_contains_recomputable_statistics():
    reg, g1 = evidence_registration(), gate1_ev()
    cert = run(reg, g1, gate2_ev(controls(0.70, 80)), gate3_ev(reg))
    payload = json.loads(cert.to_json())
    assert payload["protocol"]["formal_certificate_issued"] is False
    assert payload["protocol"]["registry_status"].startswith("pending_external")
    assert payload["integrity"]["complete"] is True
    assert len(payload["no_feedback_recovery"]["attempts"]) == 80
    assert payload["feedback_test"]["sham_delta_null_ci"][0] is not None
    assert len(payload["feedback_test"]["pair_ids_analyzed"]) == 200
    assert len(payload["feedback_test"]["pair_records"]) == 200
    assert len(payload["feedback_test"]["sham_pair_records"]) == 1600
    assert payload["no_feedback_recovery"]["positive_control"]["successes"] == 99
    assert payload["scope"]["registered_n_feedback_pairs"] == 200
    assert payload["scope"]["gate2_profile"] == "single_matched_stratum_v1"
    assert payload["fields"]["external_recovery"] == "not_assessed"
    assert payload["verdict"]["core_inconclusive_class"] == "null"


def test_strict_json_also_works_for_invalid_inputs():
    reg, g1 = base_registration(m_max=0), gate1_ev()
    cert = run(reg, g1, gate2_ev())
    payload = json.loads(cert.to_json())
    assert payload["verdict"]["core"] == "inconclusive"


# Reviewer-discovered fail-open regressions --------------------------------
def test_runtime_schema_rejects_truthy_strings_and_unknown_enums():
    reg, g1, g2 = base_registration(), gate1_ev(), gate2_ev(controls(0.70, 80))
    frozen = integrity_for(g1, g2)
    frozen.registration_frozen = "false"
    cert = evaluate(reg, g1, g2, integrity=frozen)
    assert cert.verdict.core == CoreVerdict.INCONCLUSIVE
    json.loads(cert.to_json())

    frozen = integrity_for(g1, g2)
    g1.astar.validity = "not_checked"
    cert = evaluate(reg, g1, g2, integrity=frozen)
    assert cert.verdict.core == CoreVerdict.INCONCLUSIVE
    json.loads(cert.to_json())

    g1 = gate1_ev()
    g2 = gate2_ev(controls(0.70, 80))
    frozen = integrity_for(g1, g2)
    g2.controls[0].outcome = "totally_invalid_tag"
    cert = evaluate(reg, g1, g2, integrity=frozen)
    assert cert.verdict.core == CoreVerdict.INCONCLUSIVE


def test_malformed_nested_gate1_returns_json_audit_instead_of_crashing():
    reg = base_registration()
    malformed = Gate1Evidence(astar=None, baseline=None)
    cert = evaluate(
        reg,
        malformed,
        Gate2Evidence(),
        integrity=IntegrityEvidence(),
    )
    assert cert.verdict.core == CoreVerdict.INCONCLUSIVE
    assert json.loads(cert.to_json())["verdict"]["core"] == "inconclusive"


def test_fixed_feedback_and_sham_sample_sizes_cannot_expand_post_hoc():
    reg, g1, g2 = evidence_registration(), gate1_ev(), gate2_ev(controls(0.70, 80))
    extra_feedback = gate3_ev(reg, pairs=feedback_pairs(count=201))
    cert = run(reg, g1, g2, extra_feedback)
    assert cert.verdict.core == CoreVerdict.CERTIFIED
    assert cert.verdict.evidence == EvidenceVerdict.INCONCLUSIVE
    assert any("original pair slots" in e for e in cert.gate3_integrity_errors)

    extra_sham = gate3_ev(reg, sham=sham_calibration(reg, count=1601))
    cert = run(reg, g1, g2, extra_sham)
    assert cert.verdict.evidence == EvidenceVerdict.INCONCLUSIVE
    assert any("sham pairs" in e for e in cert.gate3_integrity_errors)


def test_registered_preaction_transport_replacement_keeps_fixed_terminal_n():
    reg = evidence_registration(
        gate3_pair_replacement_policy=PAIR_REPLACEMENT_POLICY_TRANSPORT,
        max_feedback_pair_replacements=1,
        max_sham_pair_replacements=1,
        m_max=502,
    )
    pairs = feedback_pairs(count=201)
    pairs[0].truthful = failed_branch(
        branch_id="truthful-infrastructure-parent",
        execution_contract_hash=reg.gate3_truthful_arm_contract_hash,
        infrastructure=True,
    )
    feedback_replacement = pairs.pop()
    feedback_replacement.replacement_of = pairs[0].pair_id
    pairs.insert(1, feedback_replacement)

    sham = sham_calibration(reg, count=1601)
    sham.pairs[0].reference_null = failed_branch(
        branch_id="sham-infrastructure-parent",
        execution_contract_hash=reg.sham_reference_arm_contract_hash,
        infrastructure=True,
    )
    sham_replacement = sham.pairs.pop()
    sham_replacement.replacement_of = sham.pairs[0].pair_id
    sham.pairs.insert(1, sham_replacement)
    sham.no_pair_replacements = False
    sham.started_pair_count = len(sham.pairs)
    sham.confirmatory_manifest_hash = sham_pairs_manifest_hash(sham.pairs)

    g3 = gate3_ev(reg, pairs=pairs, sham=sham)
    g3.no_pair_replacements = False
    g3.feedback_pairs_manifest_hash = feedback_pairs_manifest_hash(g3.pairs)
    g1, g2 = gate1_ev(), gate2_ev(controls(0.70, 80))
    cert = run(reg, g1, g2, g3)

    assert cert.registration_errors == []
    assert cert.gate3_integrity_errors == []
    assert cert.verdict.evidence == EvidenceVerdict.CERTIFIED
    assert cert.gate3.n_pairs_started == 201
    assert cert.gate3.n_pairs_analyzed == 200
    assert cert.gate3.sham_started_pair_count == 1601
    assert cert.gate3.sham_n == 1600
    assert cert.gate3.pair_records[0]["status"] == "replaced_infrastructure"
    assert cert.gate3.sham_pair_records[0]["status"] == "replaced_infrastructure"
    payload = cert.to_dict()
    assert payload["scope"]["gate3_pair_replacement_policy"] == (
        PAIR_REPLACEMENT_POLICY_TRANSPORT
    )
    assert payload["scope"]["max_feedback_pair_replacements"] == 1
    assert payload["scope"]["max_sham_pair_replacements"] == 1


def test_replacement_cannot_follow_model_failure():
    reg = evidence_registration(
        gate3_pair_replacement_policy=PAIR_REPLACEMENT_POLICY_TRANSPORT,
        max_feedback_pair_replacements=1,
        m_max=502,
    )
    pairs = feedback_pairs(count=201)
    pairs[0].truthful = failed_branch(
        branch_id="truthful-model-failure-parent",
        execution_contract_hash=reg.gate3_truthful_arm_contract_hash,
        infrastructure=False,
    )
    replacement = pairs.pop()
    replacement.replacement_of = pairs[0].pair_id
    pairs.insert(1, replacement)
    g3 = gate3_ev(reg, pairs=pairs)
    g3.no_pair_replacements = False
    g3.feedback_pairs_manifest_hash = feedback_pairs_manifest_hash(g3.pairs)
    cert = run(reg, gate1_ev(), gate2_ev(controls(0.70, 80)), g3)

    assert cert.verdict.evidence == EvidenceVerdict.INCONCLUSIVE
    assert any(
        "without independently attested infrastructure attrition" in error
        for error in cert.gate3_integrity_errors
    )


def test_transport_replacement_must_be_immediate():
    pairs = feedback_pairs(count=201)
    pairs[0].truthful = failed_branch(
        branch_id="truthful-delayed-infrastructure-parent",
        execution_contract_hash="sha256:gate3-truthful-arm-contract",
        infrastructure=True,
    )
    pairs[-1].replacement_of = pairs[0].pair_id
    ledger = feedback_replacement_ledger(
        pairs,
        registered_n=200,
        max_replacements=1,
        policy=PAIR_REPLACEMENT_POLICY_TRANSPORT,
    )

    assert ledger.valid is False
    assert any("must immediately follow" in error for error in ledger.errors)


def test_replaceable_transport_failure_cannot_be_left_unreplaced():
    reg = evidence_registration(
        gate3_pair_replacement_policy=PAIR_REPLACEMENT_POLICY_TRANSPORT,
        max_feedback_pair_replacements=1,
    )
    pairs = feedback_pairs()
    pairs[0].truthful = failed_branch(
        branch_id="truthful-unreplaced-infrastructure",
        execution_contract_hash=reg.gate3_truthful_arm_contract_hash,
        infrastructure=True,
    )
    g3 = gate3_ev(reg, pairs=pairs)
    g3.feedback_pairs_manifest_hash = feedback_pairs_manifest_hash(g3.pairs)
    cert = run(reg, gate1_ev(), gate2_ev(controls(0.70, 80)), g3)

    assert cert.verdict.evidence == EvidenceVerdict.INCONCLUSIVE
    assert any(
        "before the registered replacement allowance was exhausted" in error
        for error in cert.gate3_integrity_errors
    )


def test_replacement_does_not_erase_neutral_recovery_witness():
    reg = evidence_registration(
        necessity_claim_requested=True,
        gate3_pair_replacement_policy=PAIR_REPLACEMENT_POLICY_TRANSPORT,
        max_feedback_pair_replacements=1,
        m_max=502,
    )
    pairs = feedback_pairs(count=201)
    pairs[0].truthful = failed_branch(
        branch_id="truthful-infrastructure-with-neutral-hit",
        execution_contract_hash=reg.gate3_truthful_arm_contract_hash,
        infrastructure=True,
    )
    pairs[0].neutral.per_unit = scores(0.91, seed=77123)
    pairs[0].neutral.utility = float(np.mean(pairs[0].neutral.per_unit))
    pairs[0].neutral.verifier_result_hash = branch_result_hash(pairs[0].neutral)
    replacement = pairs.pop()
    replacement.replacement_of = pairs[0].pair_id
    pairs.insert(1, replacement)
    g3 = gate3_ev(reg, pairs=pairs, neutral_adequacy=passing_adequacy())
    g3.no_pair_replacements = False
    g3.feedback_pairs_manifest_hash = feedback_pairs_manifest_hash(g3.pairs)
    cert = run(reg, gate1_ev(), gate2_ev(controls(0.70, 80)), g3)

    assert cert.gate3_neutral_hit_integrity_errors == []
    assert cert.gate3.neutral_hits == 1
    assert any(
        item.status.value == "confirmed_hit"
        for item in cert.gate3.neutral_classifications
    )
    assert cert.verdict.evidence == EvidenceVerdict.REFUTED


def test_pair_neutral_is_the_only_necessity_recovery_ledger():
    reg = evidence_registration(necessity_claim_requested=True)
    g1, g2 = gate1_ev(), gate2_ev(controls(0.70, 80))
    pairs = feedback_pairs()
    pairs[17].neutral.per_unit = scores(0.90, seed=44017)
    pairs[17].neutral.utility = float(np.mean(pairs[17].neutral.per_unit))
    pairs[17].neutral.verifier_result_hash = branch_result_hash(pairs[17].neutral)
    cert = run(
        reg,
        g1,
        g2,
        gate3_ev(reg, pairs=pairs, neutral_adequacy=passing_adequacy()),
    )
    assert cert.gate3.neutral_hits == 1
    assert cert.verdict.evidence == EvidenceVerdict.REFUTED


def test_frozen_baseline_and_score_vectors_cannot_be_substituted():
    reg, g1, g2 = base_registration(), gate1_ev(), gate2_ev(controls(0.70, 80))
    frozen = integrity_for(g1, g2)
    g1.baseline.per_unit = scores(0.10, seed=451)
    cert = evaluate(reg, g1, g2, integrity=frozen)
    assert cert.verdict.core == CoreVerdict.INCONCLUSIVE
    assert any(
        "baseline verifier-result hash mismatch" in e for e in cert.integrity_errors
    )

    g1 = gate1_ev()
    frozen = integrity_for(g1, g2)
    g1.baseline.artifact_hash = "sha256:substituted-baseline"
    cert = evaluate(reg, g1, g2, integrity=frozen)
    assert cert.verdict.core == CoreVerdict.INCONCLUSIVE
    assert any("baseline hash" in e for e in cert.integrity_errors)


def test_model_contract_failure_rate_is_an_adequacy_hard_gate():
    reg, g1 = base_registration(), gate1_ev()
    failures = [
        ControlAttempt(
            attempt_id=f"failure-{i}",
            outcome=RawAttemptOutcome.MODEL_FAILURE,
            stratum="matched",
            scope_contract_hash="sha256:gate2-control-contract",
            prestart_contract_receipt_hash=f"sha256:failure-prestart:{i}",
            challenge_distribution_hash="sha256:challenge-QB",
            independent_draw_receipt_hash=f"sha256:failure-draw:{i}",
            independent_unit_id=f"failure-rng-{i}",
            independence_ok=True,
        )
        for i in range(40)
    ]
    g2 = gate2_ev(controls(0.70, 40) + failures)
    cert = run(reg, g1, g2)
    assert cert.verdict.core == CoreVerdict.INCONCLUSIVE
    assert any("model-failure rate" in r for r in cert.gate2.adequacy_reasons)


def test_lineage_empty_witness_is_not_dropped_by_grade_or_gate3_error():
    reg = evidence_registration(
        grade_requested="core",
        gate3_checkpoint_scope="lineage_empty",
        gate3_neutral_recovery_contract_hash="sha256:gate2-control-contract",
        gate3_pair_randomization_distribution_hash="sha256:challenge-QB",
    )
    g1, g2 = gate1_ev(), gate2_ev(controls(0.70, 80))
    pairs = feedback_pairs()
    pairs[0].neutral.per_unit = scores(0.90, seed=9900)
    pairs[0].neutral.utility = float(np.mean(pairs[0].neutral.per_unit))
    pairs[0].neutral.verifier_result_hash = branch_result_hash(pairs[0].neutral)
    valid = gate3_ev(reg, pairs=pairs, checkpoint_scope="lineage_empty")
    cert = run(reg, g1, g2, valid)
    assert cert.verdict.core == CoreVerdict.REFUTED

    malformed = gate3_ev(reg, pairs=pairs, checkpoint_scope="lineage_empty")
    malformed.window_hash = ""
    cert = run(reg, g1, g2, malformed)
    assert cert.verdict.core == CoreVerdict.INCONCLUSIVE


def test_private_finite_set_scope_does_not_make_gate3_exact():
    reg = evidence_registration(
        inference_scope="exhaustive_finite_set",
        ci_method="finite_set_exact",
    )
    g1, g2 = gate1_ev(), gate2_ev(controls(0.70, 80))
    cert = run(reg, g1, g2, gate3_ev(reg))
    assert cert.gate3.sham_adequacy == TriState.PASS
    assert cert.gate3.feedback_effect == EffectStatus.SUPPORTED
    assert cert.verdict.evidence == EvidenceVerdict.CERTIFIED

    invalid = evidence_registration(
        feedback_inference_scope="exhaustive_finite_set",
        feedback_ci_method="finite_set_exact",
    )
    assert validate_registration(invalid)


def test_validity_is_bound_into_frozen_main_result_hashes():
    reg, g2 = base_registration(), gate2_ev(controls(0.70, 80))
    g1 = gate1_ev(astar_validity=Validity.INVALID)
    frozen = integrity_for(g1, g2)
    g1.astar.validity = Validity.VALID
    cert = evaluate(reg, g1, g2, integrity=frozen)
    assert cert.verdict.core == CoreVerdict.INCONCLUSIVE
    assert any("A* verifier-result hash mismatch" in e for e in cert.integrity_errors)


def test_feedback_private_scores_must_align_and_determine_continuous_utility():
    reg, g1, g2 = evidence_registration(), gate1_ev(), gate2_ev(controls(0.70, 80))
    pairs = feedback_pairs()
    pairs[0].truthful.per_unit = [0.90]
    pairs[0].truthful.utility = 0.90
    pairs[0].truthful.verifier_result_hash = branch_result_hash(pairs[0].truthful)
    cert = run(reg, g1, g2, gate3_ev(reg, pairs=pairs))
    assert cert.verdict.evidence == EvidenceVerdict.INCONCLUSIVE
    assert any("misaligned" in e for e in cert.gate3_integrity_errors)

    pairs = feedback_pairs()
    pairs[0].truthful.utility = 0.10
    pairs[0].truthful.verifier_result_hash = branch_result_hash(pairs[0].truthful)
    cert = run(reg, g1, g2, gate3_ev(reg, pairs=pairs))
    assert cert.gate3.feedback_effect == EffectStatus.INCONCLUSIVE


def test_branch_and_control_raw_outcomes_are_mutually_exclusive():
    reg, g1, g2 = evidence_registration(), gate1_ev(), gate2_ev(controls(0.70, 80))
    pairs = feedback_pairs()
    contradictory = BranchOutcome(
        outcome=RawAttemptOutcome.MODEL_FAILURE,
        validity=Validity.UNRESOLVED,
        branch_id="contradictory-failure",
        artifact_hash="sha256:hidden-artifact",
        execution_contract_hash="sha256:gate3-neutral-arm-contract",
        prestart_contract_receipt_hash="sha256:contradictory-prestart",
        per_unit=scores(0.95, seed=777),
        unit_ids=UNIT_IDS,
    )
    contradictory.verifier_result_hash = branch_result_hash(contradictory)
    pairs[0].neutral = contradictory
    cert = run(reg, g1, g2, gate3_ev(reg, pairs=pairs))
    assert cert.verdict.evidence == EvidenceVerdict.INCONCLUSIVE
    assert any("conflicts with artifact data" in e for e in cert.gate3_integrity_errors)

    bad_infra = ControlAttempt(
        attempt_id="bad-infra",
        outcome=RawAttemptOutcome.INFRASTRUCTURE_INVALID,
        validity=Validity.VALID,
        artifact_hash="sha256:not-infra",
        stratum="matched",
        scope_contract_hash="sha256:gate2-control-contract",
        prestart_contract_receipt_hash="sha256:bad-infra-prestart",
        challenge_distribution_hash="sha256:challenge-QB",
        independent_draw_receipt_hash="sha256:bad-infra-draw",
        infrastructure_outcome_independent=True,
    )
    core_g2 = gate2_ev(controls(0.70, 80) + [bad_infra])
    cert = run(base_registration(), gate1_ev(), core_g2)
    assert cert.verdict.core == CoreVerdict.INCONCLUSIVE


def test_lineage_empty_unresolved_candidate_blocks_core():
    reg = evidence_registration(
        inference_scope="sampled_population",
        ci_method="bounded_empirical_bernstein",
        gate3_checkpoint_scope="lineage_empty",
        gate3_neutral_recovery_contract_hash="sha256:gate2-control-contract",
        gate3_pair_randomization_distribution_hash="sha256:challenge-QB",
    )
    g1, g2 = gate1_ev(baseline_mean=0.50), gate2_ev(controls(0.50, 80))
    pairs = feedback_pairs()
    pairs[0].neutral.per_unit = scores(0.80, seed=64001)
    pairs[0].neutral.utility = float(np.mean(pairs[0].neutral.per_unit))
    pairs[0].neutral.verifier_result_hash = branch_result_hash(pairs[0].neutral)
    cert = run(
        reg,
        g1,
        g2,
        gate3_ev(reg, pairs=pairs, checkpoint_scope="lineage_empty"),
    )
    assert cert.gate3.neutral_unresolved >= 1
    assert cert.verdict.core == CoreVerdict.INCONCLUSIVE


def test_checkpoint_scope_cannot_be_relabelled_without_breaking_manifest():
    reg, g1, g2 = (
        evidence_registration(
            gate3_checkpoint_scope="lineage_empty",
            gate3_neutral_recovery_contract_hash="sha256:gate2-control-contract",
            gate3_pair_randomization_distribution_hash="sha256:challenge-QB",
        ),
        gate1_ev(),
        gate2_ev(controls(0.70, 80)),
    )
    pairs = feedback_pairs()
    pairs[0].neutral.per_unit = scores(0.90, seed=62001)
    pairs[0].neutral.utility = float(np.mean(pairs[0].neutral.per_unit))
    pairs[0].neutral.verifier_result_hash = branch_result_hash(pairs[0].neutral)
    g3 = gate3_ev(reg, pairs=pairs, checkpoint_scope="lineage_empty")
    g3.checkpoint_scope = "lineage_prefix"
    cert = run(reg, g1, g2, g3)
    assert cert.verdict.core == CoreVerdict.INCONCLUSIVE
    assert any("scope manifest" in e for e in cert.gate3_integrity_errors)


def test_neutral_hit_is_monotone_necessity_veto_even_if_effect_unresolved():
    reg = evidence_registration(necessity_claim_requested=True)
    g1, g2, pairs = gate1_ev(), gate2_ev(controls(0.70, 80)), feedback_pairs()
    unresolved = BranchOutcome(
        branch_id="truthful-unresolved",
        execution_contract_hash="sha256:gate3-truthful-arm-contract",
        prestart_contract_receipt_hash="sha256:truthful-unresolved-prestart",
    )
    unresolved.verifier_result_hash = branch_result_hash(unresolved)
    pairs[0].truthful = unresolved
    pairs[1].neutral.per_unit = scores(0.90, seed=63001)
    pairs[1].neutral.utility = float(np.mean(pairs[1].neutral.per_unit))
    pairs[1].neutral.verifier_result_hash = branch_result_hash(pairs[1].neutral)
    cert = run(
        reg,
        g1,
        g2,
        gate3_ev(reg, pairs=pairs, neutral_adequacy=passing_adequacy()),
    )
    assert cert.gate3.feedback_effect == EffectStatus.INCONCLUSIVE
    assert cert.gate3.neutral_recovery == Recovery.RECOVERED
    assert cert.verdict.evidence == EvidenceVerdict.REFUTED


def test_neutral_hit_survives_unrelated_sham_integrity_failure():
    reg = evidence_registration(necessity_claim_requested=True)
    g1, g2, pairs = gate1_ev(), gate2_ev(controls(0.70, 80)), feedback_pairs()
    pairs[0].neutral.per_unit = scores(0.90, seed=63002)
    pairs[0].neutral.utility = float(np.mean(pairs[0].neutral.per_unit))
    pairs[0].neutral.verifier_result_hash = branch_result_hash(pairs[0].neutral)
    pairs[0].independence_ok = False  # a concrete hit needs no zero-hit IID claim
    sham = sham_calibration(reg)
    sham.reference_arm_contract_hash = "sha256:crippled-reference-contract"
    for pair in sham.pairs:
        pair.reference_null.execution_contract_hash = (
            "sha256:crippled-reference-contract"
        )
        pair.reference_null.verifier_result_hash = branch_result_hash(
            pair.reference_null
        )
    sham.confirmatory_manifest_hash = sham_pairs_manifest_hash(sham.pairs)

    cert = run(
        reg,
        g1,
        g2,
        gate3_ev(
            reg,
            pairs=pairs,
            sham=sham,
            neutral_adequacy=passing_adequacy(),
        ),
    )
    assert any("reference-arm contract" in e for e in cert.gate3_integrity_errors)
    assert cert.gate3_neutral_hit_integrity_errors == []
    assert cert.gate3.feedback_effect == EffectStatus.INCONCLUSIVE
    assert cert.gate3.neutral_recovery == Recovery.RECOVERED
    assert cert.verdict.core == CoreVerdict.CERTIFIED
    assert cert.verdict.evidence == EvidenceVerdict.REFUTED
    assert (
        cert.to_dict()["protocol"]["record_type"] == "complete_kernel_decision_record"
    )


def test_lineage_empty_neutral_hit_survives_truthful_contract_failure():
    reg = evidence_registration(
        necessity_claim_requested=True,
        gate3_checkpoint_scope="lineage_empty",
        gate3_neutral_recovery_contract_hash="sha256:gate2-control-contract",
        gate3_pair_randomization_distribution_hash="sha256:challenge-QB",
    )
    g1, g2, pairs = gate1_ev(), gate2_ev(controls(0.70, 80)), feedback_pairs()
    pairs[0].neutral.per_unit = scores(0.90, seed=63003)
    pairs[0].neutral.utility = float(np.mean(pairs[0].neutral.per_unit))
    pairs[0].neutral.verifier_result_hash = branch_result_hash(pairs[0].neutral)
    g3 = gate3_ev(reg, pairs=pairs, checkpoint_scope="lineage_empty")
    g3.pairs[1].truthful.execution_contract_hash = "sha256:wrong-truthful-contract"
    g3.pairs[1].truthful.verifier_result_hash = branch_result_hash(g3.pairs[1].truthful)
    g3.feedback_pairs_manifest_hash = feedback_pairs_manifest_hash(g3.pairs)

    cert = run(reg, g1, g2, g3)
    assert any(
        "truthful.execution_contract_hash" in e for e in cert.gate3_integrity_errors
    )
    assert cert.gate3_neutral_hit_integrity_errors == []
    assert cert.gate3.neutral_recovery == Recovery.RECOVERED
    assert cert.verdict.core == CoreVerdict.REFUTED


def test_explicit_neutral_audit_preserves_hit_when_paired_audit_fails():
    reg = evidence_registration(
        necessity_claim_requested=True,
        gate3_checkpoint_scope="lineage_empty",
        gate3_neutral_recovery_contract_hash="sha256:gate2-control-contract",
        gate3_pair_randomization_distribution_hash="sha256:challenge-QB",
    )
    g1, g2, pairs = gate1_ev(), gate2_ev(controls(0.70, 80)), feedback_pairs()
    pairs[0].neutral.per_unit = scores(0.90, seed=63009)
    pairs[0].neutral.utility = float(np.mean(pairs[0].neutral.per_unit))
    pairs[0].neutral.verifier_result_hash = branch_result_hash(pairs[0].neutral)
    g3 = gate3_ev(reg, pairs=pairs, checkpoint_scope="lineage_empty")
    g3.paired_contract_audit_pass = False
    g3.neutral_contract_audit_pass = True
    g3.neutral_scope_audit_manifest_hash = gate3_neutral_scope_manifest_hash(
        g3, "sha256:selection-rule"
    )

    cert = run(reg, g1, g2, g3)
    assert any("paired contract audit failed" in e for e in cert.gate3_integrity_errors)
    assert cert.gate3_neutral_hit_integrity_errors == []
    assert cert.gate3.feedback_effect == EffectStatus.INCONCLUSIVE
    assert cert.gate3.neutral_recovery == Recovery.RECOVERED
    assert cert.gate3.neutral_contract_audit_pass is True
    assert cert.verdict.core == CoreVerdict.REFUTED
    assert cert.to_dict()["feedback_test"]["neutral_contract_audit_pass"] is True


def test_missing_neutral_audit_keeps_exact_legacy_paired_fallback():
    reg = evidence_registration(
        gate3_checkpoint_scope="lineage_empty",
        gate3_neutral_recovery_contract_hash="sha256:gate2-control-contract",
        gate3_pair_randomization_distribution_hash="sha256:challenge-QB",
    )
    g1, g2, pairs = gate1_ev(), gate2_ev(controls(0.70, 80)), feedback_pairs()
    pairs[0].neutral.per_unit = scores(0.90, seed=63010)
    pairs[0].neutral.utility = float(np.mean(pairs[0].neutral.per_unit))
    pairs[0].neutral.verifier_result_hash = branch_result_hash(pairs[0].neutral)
    g3 = gate3_ev(reg, pairs=pairs, checkpoint_scope="lineage_empty")
    assert g3.neutral_contract_audit_pass is None
    g3.paired_contract_audit_pass = False
    g3.neutral_scope_audit_manifest_hash = gate3_neutral_scope_manifest_hash(
        g3, "sha256:selection-rule"
    )

    cert = run(reg, g1, g2, g3)
    assert cert.verdict.core == CoreVerdict.INCONCLUSIVE
    assert cert.gate3.neutral_recovery == Recovery.INCONCLUSIVE
    assert "neutral witness paired-contract audit failed" in (
        cert.gate3_neutral_hit_integrity_errors
    )
    assert "neutral_contract_audit_pass" not in cert.to_dict()["feedback_test"]


def test_explicit_invalid_neutral_audit_fails_closed():
    reg = evidence_registration(
        gate3_checkpoint_scope="lineage_empty",
        gate3_neutral_recovery_contract_hash="sha256:gate2-control-contract",
        gate3_pair_randomization_distribution_hash="sha256:challenge-QB",
    )
    g1, g2, pairs = gate1_ev(), gate2_ev(controls(0.70, 80)), feedback_pairs()
    pairs[0].neutral.per_unit = scores(0.90, seed=63011)
    pairs[0].neutral.utility = float(np.mean(pairs[0].neutral.per_unit))
    pairs[0].neutral.verifier_result_hash = branch_result_hash(pairs[0].neutral)
    g3 = gate3_ev(reg, pairs=pairs, checkpoint_scope="lineage_empty")
    g3.neutral_contract_audit_pass = "yes"  # type: ignore[assignment]
    g3.neutral_scope_audit_manifest_hash = gate3_neutral_scope_manifest_hash(
        g3, "sha256:selection-rule"
    )

    cert = run(reg, g1, g2, g3)
    assert cert.verdict.core == CoreVerdict.INCONCLUSIVE
    assert cert.gate3.neutral_recovery == Recovery.INCONCLUSIVE
    assert any(
        "neutral_contract_audit_pass must be a boolean" in e
        for e in cert.gate3_neutral_hit_integrity_errors
    )


def test_new_neutral_scope_hash_is_independent_of_paired_audit():
    reg = evidence_registration()
    g3 = gate3_ev(reg)
    g3.neutral_contract_audit_pass = True
    paired_true_hash = gate3_neutral_scope_manifest_hash(
        g3, "sha256:selection-rule"
    )
    g3.paired_contract_audit_pass = False
    paired_false_hash = gate3_neutral_scope_manifest_hash(
        g3, "sha256:selection-rule"
    )
    g3.neutral_contract_audit_pass = False
    neutral_false_hash = gate3_neutral_scope_manifest_hash(
        g3, "sha256:selection-rule"
    )

    assert paired_false_hash == paired_true_hash
    assert neutral_false_hash != paired_true_hash


def test_invalid_neutral_contract_cannot_create_monotone_hit():
    reg = evidence_registration(
        gate3_checkpoint_scope="lineage_empty",
        gate3_neutral_recovery_contract_hash="sha256:gate2-control-contract",
        gate3_pair_randomization_distribution_hash="sha256:challenge-QB",
    )
    g1, g2, pairs = gate1_ev(), gate2_ev(controls(0.70, 80)), feedback_pairs()
    pairs[0].neutral.per_unit = scores(0.90, seed=63004)
    pairs[0].neutral.utility = float(np.mean(pairs[0].neutral.per_unit))
    pairs[0].neutral.execution_contract_hash = "sha256:wrong-neutral-contract"
    pairs[0].neutral.verifier_result_hash = branch_result_hash(pairs[0].neutral)
    g3 = gate3_ev(reg, pairs=pairs, checkpoint_scope="lineage_empty")

    cert = run(reg, g1, g2, g3)
    assert cert.gate3.neutral_recovery == Recovery.INCONCLUSIVE
    assert cert.verdict.core == CoreVerdict.INCONCLUSIVE
    assert any(
        "neutral.execution_contract_hash" in e
        for e in cert.gate3_neutral_hit_integrity_errors
    )


def test_unfrozen_neutral_assignment_cannot_false_refute_necessity():
    reg = evidence_registration(necessity_claim_requested=True)
    g1, g2, pairs = gate1_ev(), gate2_ev(controls(0.70, 80)), feedback_pairs()
    pairs[0].neutral.per_unit = scores(0.95, seed=63005)
    pairs[0].neutral.utility = float(np.mean(pairs[0].neutral.per_unit))
    pairs[0].neutral.verifier_result_hash = branch_result_hash(pairs[0].neutral)
    pairs[0].assignment_frozen = False

    cert = run(reg, g1, g2, gate3_ev(reg, pairs=pairs))
    assert cert.gate3.neutral_recovery == Recovery.INCONCLUSIVE
    assert cert.verdict.core == CoreVerdict.CERTIFIED
    assert cert.verdict.evidence == EvidenceVerdict.INCONCLUSIVE
    assert any(
        "assignment was not frozen" in e
        for e in cert.gate3_neutral_hit_integrity_errors
    )


def test_unfrozen_lineage_empty_assignment_cannot_false_refute_core():
    reg = evidence_registration(
        necessity_claim_requested=True,
        gate3_checkpoint_scope="lineage_empty",
        gate3_neutral_recovery_contract_hash="sha256:gate2-control-contract",
        gate3_pair_randomization_distribution_hash="sha256:challenge-QB",
    )
    g1, g2, pairs = gate1_ev(), gate2_ev(controls(0.70, 80)), feedback_pairs()
    pairs[0].neutral.per_unit = scores(0.95, seed=63006)
    pairs[0].neutral.utility = float(np.mean(pairs[0].neutral.per_unit))
    pairs[0].neutral.verifier_result_hash = branch_result_hash(pairs[0].neutral)
    pairs[0].assignment_frozen = False

    cert = run(
        reg,
        g1,
        g2,
        gate3_ev(reg, pairs=pairs, checkpoint_scope="lineage_empty"),
    )
    assert cert.gate3.neutral_recovery == Recovery.INCONCLUSIVE
    assert cert.verdict.core == CoreVerdict.INCONCLUSIVE
    assert cert.verdict.core != CoreVerdict.REFUTED


def test_incomplete_neutral_ledger_has_monotone_core_ordering():
    early_reg = evidence_registration(
        necessity_claim_requested=True,
        gate3_checkpoint_scope="lineage_empty",
        gate3_neutral_recovery_contract_hash="sha256:gate2-control-contract",
        gate3_pair_randomization_distribution_hash="sha256:challenge-QB",
    )
    g1, g2 = gate1_ev(), gate2_ev(controls(0.70, 80))

    no_hit = gate3_ev(early_reg, checkpoint_scope="lineage_empty")
    no_hit.all_started_pairs_disclosed = False
    cert = run(early_reg, g1, g2, no_hit)
    assert cert.verdict.core == CoreVerdict.INCONCLUSIVE
    assert any(
        "started-pair ledger is not complete" in e
        for e in cert.gate3_neutral_ledger_integrity_errors
    )

    pairs = feedback_pairs()
    pairs[0].neutral.per_unit = scores(0.95, seed=63007)
    pairs[0].neutral.utility = float(np.mean(pairs[0].neutral.per_unit))
    pairs[0].neutral.verifier_result_hash = branch_result_hash(pairs[0].neutral)
    with_hit = gate3_ev(early_reg, pairs=pairs, checkpoint_scope="lineage_empty")
    with_hit.all_started_pairs_disclosed = False
    cert = run(early_reg, g1, g2, with_hit)
    assert cert.gate3.neutral_recovery == Recovery.RECOVERED
    assert cert.verdict.core == CoreVerdict.REFUTED

    late_reg = evidence_registration(necessity_claim_requested=True)
    late = gate3_ev(late_reg)
    late.all_started_pairs_disclosed = False
    cert = run(late_reg, g1, g2, late)
    assert cert.verdict.core == CoreVerdict.CERTIFIED
    assert cert.verdict.evidence == EvidenceVerdict.INCONCLUSIVE


def test_neutral_hit_survives_unrelated_gate3_evaluation_exception(monkeypatch):
    reg = evidence_registration(necessity_claim_requested=True)
    g1, g2, pairs = gate1_ev(), gate2_ev(controls(0.70, 80)), feedback_pairs()
    pairs[0].neutral.per_unit = scores(0.95, seed=63008)
    pairs[0].neutral.utility = float(np.mean(pairs[0].neutral.per_unit))
    pairs[0].neutral.verifier_result_hash = branch_result_hash(pairs[0].neutral)
    g3 = gate3_ev(reg, pairs=pairs)

    evaluate_module = importlib.import_module("dcp.evaluate")

    def broken_effect_path(*_args, **_kwargs):
        raise ArithmeticError("synthetic truthful/sham evaluation failure")

    monkeypatch.setattr(evaluate_module, "evaluate_gate3", broken_effect_path)
    cert = run(reg, g1, g2, g3)
    assert any("evaluation input error" in e for e in cert.gate3_integrity_errors)
    assert cert.gate3.neutral_recovery == Recovery.RECOVERED
    assert cert.verdict.core == CoreVerdict.CERTIFIED
    assert cert.verdict.evidence == EvidenceVerdict.REFUTED


def test_binary_effect_uses_finite_sample_exact_interval_and_binary_sham():
    ci = paired_binary_interval([1.0] * 199 + [0.0], 0.995)
    assert ci.lcb < 0.97

    reg, g1, g2 = (
        evidence_registration(feedback_estimand="binary"),
        gate1_ev(),
        gate2_ev(controls(0.70, 80)),
    )
    sham = sham_calibration(reg, count=reg.registered_n_sham_pairs)
    sham.pairs[0].reference_null.utility = 0.5
    sham.pairs[0].reference_null.verifier_result_hash = branch_result_hash(
        sham.pairs[0].reference_null
    )
    sham.confirmatory_manifest_hash = sham_pairs_manifest_hash(sham.pairs)
    cert = run(reg, g1, g2, gate3_ev(reg, sham=sham))
    assert cert.gate3.sham_adequacy == TriState.INCONCLUSIVE
    assert cert.verdict.evidence == EvidenceVerdict.INCONCLUSIVE


def test_pair_randomization_and_started_ledgers_are_hard_requirements():
    reg, g1, g2 = evidence_registration(), gate1_ev(), gate2_ev(controls(0.70, 80))
    pairs = feedback_pairs()
    pairs[0].independence_ok = False
    g3 = gate3_ev(reg, pairs=pairs)
    cert = run(reg, g1, g2, g3)
    assert cert.gate3.feedback_effect == EffectStatus.INCONCLUSIVE

    g3 = gate3_ev(reg)
    g3.all_started_pairs_disclosed = False
    cert = run(reg, g1, g2, g3)
    assert cert.verdict.evidence == EvidenceVerdict.INCONCLUSIVE
    assert any("started-pair ledger" in e for e in cert.gate3_integrity_errors)


def test_family_alpha_budget_and_canonical_mapping_are_registered():
    assert validate_registration(base_registration(family_max_audits=2))
    assert validate_registration(
        evidence_registration(feedback_utility_mapping="free-form-mapping")
    )


def test_input_snapshot_and_malformed_top_level_records_are_safe():
    reg, g1, g2 = base_registration(), gate1_ev(), gate2_ev(controls(0.70, 80))
    cert = run(reg, g1, g2)
    before = cert.to_dict()
    reg.delta_min = 0.99
    assert cert.registration.delta_min == 0.10
    assert json.loads(cert.to_json())["registration"]["frozen"]["delta_min"] == 0.10
    cert.registration.delta_min = 100.0
    cert.gate1.effect_lcb = 999.0
    assert cert.to_dict() == before

    malformed = evaluate(None, g1, g2, integrity=object())
    assert malformed.verdict.core == CoreVerdict.INCONCLUSIVE
    json.loads(malformed.to_json())


def test_blank_independent_ids_cannot_inflate_zero_hit_sample_size():
    reg, g1 = base_registration(), gate1_ev()
    ctrls = controls(0.70, 80)
    for i, control in enumerate(ctrls, start=1):
        control.independent_unit_id = " " * i
    cert = run(reg, g1, gate2_ev(ctrls))
    assert cert.verdict.core == CoreVerdict.INCONCLUSIVE
    assert any("independent_unit_id missing" in e for e in cert.integrity_errors)


def test_independent_unit_ids_must_be_canonical_before_cluster_counting():
    reg, g1 = base_registration(), gate1_ev()
    ctrls = controls(0.70, 80)
    for i in range(40):
        ctrls[i].independent_unit_id = f"rng:{i}"
        ctrls[40 + i].independent_unit_id = f"rng:{i} "
    cert = run(reg, g1, gate2_ev(ctrls))
    assert cert.verdict.core == CoreVerdict.INCONCLUSIVE
    assert any("independent_unit_id missing" in e for e in cert.integrity_errors)


def test_private_unit_ids_must_be_canonical_before_effective_n_is_counted():
    reg, g1 = base_registration(), gate1_ev()
    bad_ids = list(g1.astar.unit_ids)
    bad_ids[0] += " "
    g1.astar.unit_ids = tuple(bad_ids)
    g1.baseline.unit_ids = tuple(bad_ids)
    g2 = gate2_ev(controls(0.70, 80, unit_ids=tuple(bad_ids)))
    cert = run(reg, g1, g2)
    assert cert.verdict.core == CoreVerdict.INCONCLUSIVE
    assert any("private-unit ids" in e for e in cert.integrity_errors)


def test_gate2_hit_requires_admissible_model_and_health_scope():
    reg, g1 = base_registration(), gate1_ev()
    ad = passing_adequacy()
    ad.matched_model_present = False
    ad.checks_manifest_hash = adequacy_evidence_hash(ad)
    g2 = gate2_ev(controls(0.70, 80) + controls(0.90, 1, seed0=900), ad)
    cert = run(reg, g1, g2)
    assert cert.verdict.core == CoreVerdict.INCONCLUSIVE
    assert any("contradicts candidate-level" in e for e in cert.integrity_errors)

    wrong_scope = controls(0.90, 1, seed0=902)
    wrong_scope[0].scope_contract_hash = "sha256:wrong-model-contract"
    cert = run(reg, g1, gate2_ev(wrong_scope))
    assert cert.gate2.hits == 0
    assert cert.gate2.classifications[0].status.value == "execution_contract_violation"
    assert cert.verdict.core == CoreVerdict.INCONCLUSIVE

    # Search-coverage failures cannot erase an already admissible counterexample.
    ad = passing_adequacy()
    ad.materials_readable = False
    ad.checks_manifest_hash = adequacy_evidence_hash(ad)
    cert = run(reg, g1, gate2_ev(controls(0.90, 1, seed0=901), ad))
    assert cert.gate2.admissible_hits == 1
    assert cert.gate2.p_upper is None
    assert cert.verdict.core == CoreVerdict.REFUTED

    # An auxiliary channel-health failure blocks no-hit certification only.
    ad = passing_adequacy()
    ad.health_audit_pass = False
    ad.checks_manifest_hash = adequacy_evidence_hash(ad)
    cert = run(reg, g1, gate2_ev(controls(0.90, 1, seed0=903), ad))
    assert cert.gate2.admissible_hits == 1
    assert cert.verdict.core == CoreVerdict.REFUTED


def test_gate2_recovery_hit_survives_unrelated_candidate_integrity_error():
    reg, g1 = base_registration(), gate1_ev()
    hit = controls(0.90, 1, seed0=1900)[0]
    unrelated = controls(0.70, 1, seed0=1901)[0]
    unrelated.independent_unit_id = " "
    g2 = gate2_ev([hit, unrelated])

    cert = evaluate(
        reg,
        g1,
        g2,
        integrity=integrity_for(g1, g2, recovery_ledger_complete=False),
    )

    assert cert.integrity_errors
    assert cert.gate2.no_feedback_recovery == Recovery.RECOVERED
    assert cert.gate2.admissible_hits == 1
    assert cert.verdict.core == CoreVerdict.REFUTED


def test_gate2_recovery_witness_must_itself_have_a_complete_local_envelope():
    reg, g1 = base_registration(), gate1_ev()
    malformed_hit = controls(0.90, 1, seed0=1910)[0]
    malformed_hit.prestart_contract_receipt_hash = ""
    g2 = gate2_ev([malformed_hit])

    cert = evaluate(reg, g1, g2, integrity=integrity_for(g1, g2))

    assert cert.integrity_errors
    assert cert.gate2.no_feedback_recovery == Recovery.INCONCLUSIVE
    assert cert.verdict.core == CoreVerdict.INCONCLUSIVE


def test_gate2_local_hit_cannot_bypass_a_tampered_target_envelope():
    reg, g1 = base_registration(), gate1_ev()
    g2 = gate2_ev(controls(0.90, 1, seed0=1920))
    frozen = integrity_for(
        g1,
        g2,
        astar_results_hash="sha256:tampered-target-results",
    )

    cert = evaluate(reg, g1, g2, integrity=frozen)

    assert cert.integrity_errors
    assert cert.gate2.no_feedback_recovery == Recovery.INCONCLUSIVE
    assert cert.verdict.core == CoreVerdict.INCONCLUSIVE


def test_gate2_local_hit_must_remain_bound_to_the_frozen_recovery_ledger():
    reg, g1 = base_registration(), gate1_ev()
    g2 = gate2_ev(controls(0.90, 1, seed0=1930))
    frozen = integrity_for(
        g1,
        g2,
        gate2_recovery_ledger_manifest_hash="sha256:tampered-ledger",
    )

    cert = evaluate(reg, g1, g2, integrity=frozen)

    assert cert.integrity_errors
    assert cert.gate2.no_feedback_recovery == Recovery.INCONCLUSIVE
    assert cert.verdict.core == CoreVerdict.INCONCLUSIVE


def test_gate3_placebo_contract_is_frozen_not_self_attested():
    reg, g1, g2 = evidence_registration(), gate1_ev(), gate2_ev(controls(0.70, 80))
    g3 = gate3_ev(reg)
    g3.neutral_model_id = "weak-model"
    g3.neutral_interface_hash = "weak-interface"
    g3.neutral_resource_contract_hash = "sha256:crippled-budget"
    g3.neutral_scope_audit_manifest_hash = gate3_neutral_scope_manifest_hash(
        g3, "sha256:selection-rule"
    )
    cert = run(reg, g1, g2, g3)
    assert cert.verdict.core == CoreVerdict.CERTIFIED
    assert cert.verdict.evidence == EvidenceVerdict.INCONCLUSIVE
    assert any("paired contract" in e for e in cert.gate3_integrity_errors)


def test_gate3_checkpoint_scope_is_registered_even_if_manifest_is_rehashed():
    reg = evidence_registration(
        gate3_checkpoint_scope="lineage_empty",
        gate3_neutral_recovery_contract_hash="sha256:gate2-control-contract",
        gate3_pair_randomization_distribution_hash="sha256:challenge-QB",
    )
    g1, g2 = gate1_ev(), gate2_ev(controls(0.70, 80))
    g3 = gate3_ev(reg, checkpoint_scope="lineage_empty")
    g3.checkpoint_scope = "lineage_prefix"
    g3.neutral_scope_audit_manifest_hash = gate3_neutral_scope_manifest_hash(
        g3, "sha256:selection-rule"
    )
    cert = run(reg, g1, g2, g3)
    assert cert.verdict.core == CoreVerdict.INCONCLUSIVE
    assert any("frozen registration" in e for e in cert.gate3_integrity_errors)


def test_zero_hit_bound_uses_independent_draws_from_one_frozen_distribution():
    reg, g1 = base_registration(), gate1_ev()
    ctrls = controls(0.70, 80)
    ctrls[0].challenge_distribution_hash = "sha256:posthoc-prompt-list"
    cert = run(reg, g1, gate2_ev(ctrls))
    assert cert.gate2.classifications[0].status.value == "execution_contract_violation"
    assert cert.gate2.n_ind == 79
    assert cert.gate2.p_upper is None
    assert cert.verdict.core == CoreVerdict.INCONCLUSIVE

    ctrls = controls(0.70, 80)
    ctrls[1].independent_draw_receipt_hash = ctrls[0].independent_draw_receipt_hash
    cert = run(reg, g1, gate2_ev(ctrls))
    assert cert.verdict.core == CoreVerdict.INCONCLUSIVE
    assert any("draw receipt is reused" in e for e in cert.integrity_errors)

    ctrls = controls(0.70, 80)
    for i in range(40):
        ctrls[40 + i].independent_unit_id = ctrls[i].independent_unit_id
        ctrls[40 + i].independent_draw_receipt_hash = ctrls[
            i
        ].independent_draw_receipt_hash
    cert = run(reg, g1, gate2_ev(ctrls))
    assert cert.gate2.n_ind == 40
    assert cert.verdict.core == CoreVerdict.INCONCLUSIVE


def test_gate3_pair_randomization_distribution_is_frozen():
    reg, g1, g2 = evidence_registration(), gate1_ev(), gate2_ev(controls(0.70, 80))
    g3 = gate3_ev(reg)
    g3.pairs[0].randomization_distribution_hash = "sha256:posthoc-pair-Q"
    g3.feedback_pairs_manifest_hash = feedback_pairs_manifest_hash(g3.pairs)
    g3.neutral_scope_audit_manifest_hash = gate3_neutral_scope_manifest_hash(
        g3, "sha256:selection-rule"
    )
    cert = run(reg, g1, g2, g3)
    assert cert.verdict.evidence == EvidenceVerdict.INCONCLUSIVE
    assert any("distribution_hash differs" in e for e in cert.gate3_integrity_errors)


def test_sham_reference_arm_cannot_be_crippled_and_self_rehashed():
    reg, g1, g2 = evidence_registration(), gate1_ev(), gate2_ev(controls(0.70, 80))
    sham = sham_calibration(reg)
    sham.reference_arm_contract_hash = "sha256:crippled-reference-contract"
    for pair in sham.pairs:
        pair.reference_null.execution_contract_hash = (
            "sha256:crippled-reference-contract"
        )
        pair.reference_null.verifier_result_hash = branch_result_hash(
            pair.reference_null
        )
    sham.confirmatory_manifest_hash = sham_pairs_manifest_hash(sham.pairs)
    cert = run(reg, g1, g2, gate3_ev(reg, sham=sham))
    assert cert.verdict.evidence == EvidenceVerdict.INCONCLUSIVE
    assert any("reference-arm contract" in e for e in cert.gate3_integrity_errors)


def test_calibrated_sham_operator_must_be_the_target_neutral_operator():
    reg = evidence_registration(
        neutral_sham_generator_hash="sha256:uncalibrated-target-sham"
    )
    cert = run(
        reg,
        gate1_ev(),
        gate2_ev(controls(0.70, 80)),
        gate3_ev(reg),
    )
    assert cert.verdict.evidence == EvidenceVerdict.NOT_TESTED
    assert any("calibrated sham operator" in e for e in cert.registration_errors)


if __name__ == "__main__":
    raise SystemExit(0)
