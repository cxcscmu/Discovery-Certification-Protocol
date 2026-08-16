"""Auditable, strict-JSON certificate assembly (proposal §8.1 / Appendix A)."""

from __future__ import annotations

import json
import math
from dataclasses import asdict
from enum import Enum
from typing import Optional

from dcp.registration import PAIR_REPLACEMENT_POLICY_NONE, Registration
from dcp.types import (
    EffectStatus,
    Gate1Result,
    Gate2Result,
    Gate3Result,
    IntegrityEvidence,
    Verdict,
)


def build_certificate(
    reg: Registration,
    integrity: Optional[IntegrityEvidence],
    reg_errors: list[str],
    integrity_errors: list[str],
    gate3_integrity_errors: list[str],
    gate3_neutral_hit_integrity_errors: list[str],
    gate3_neutral_ledger_integrity_errors: list[str],
    g1: Gate1Result,
    g2: Gate2Result,
    verdict: Verdict,
    g3: Optional[Gate3Result] = None,
) -> dict:
    formal_core = not reg_errors and not integrity_errors
    decisive_neutral_veto = bool(
        g3 is not None and g3.neutral_recovery.value == "recovered"
    )
    formal_evidence = formal_core and (
        decisive_neutral_veto
        or (
            not gate3_integrity_errors and (not reg.requests_evidence or g3 is not None)
        )
    )
    cert: dict = {
        "protocol": {
            "name": "DCP-v2",
            "implementation": "dcp-evaluation-core/0.4.2",
            "grade_requested": reg.grade_requested,
            "record_type": (
                "complete_kernel_decision_record"
                if formal_evidence
                else "complete_core_with_inconclusive_evidence"
                if formal_core
                else "inconclusive_audit"
            ),
            "formal_certificate_issued": False,
            "registry_status": "pending_external_append_only_registry",
            "issuance_note": (
                "The audit slot and alpha were consumed before the confirmatory run. "
                "A protocol registry must verify that receipt and countersign this record."
            ),
        },
        "claim": {
            "claim_id": reg.claim_id,
            "necessity_claim_requested": reg.necessity_claim_requested,
        },
        "scope": {
            "model": reg.model_id,
            "interface_hash": reg.interface_hash,
            "task_family_profile": reg.task_family_profile,
            "audit_family_id": reg.audit_family_id,
            "family_alpha_total": reg.family_alpha_total,
            "family_max_audits": reg.family_max_audits,
            "audit_slot_id": reg.audit_slot_id,
            "audit_slot_reservation_receipt_hash": reg.audit_slot_reservation_receipt_hash,
            "inference_scope": reg.inference_scope,
            "ci_method": reg.ci_method,
            "score_range_id": reg.score_range_id,
            "score_range": [0.0, 1.0],
            "feedback_inference_scope": reg.feedback_inference_scope,
            "feedback_ci_method": reg.feedback_ci_method,
            "sham_inference_scope": reg.sham_inference_scope,
            "sham_ci_method": reg.sham_ci_method,
            "delta_min": reg.delta_min,
            "kappa": reg.kappa,
            "epsilon": _safe_epsilon(reg),
            "rho": reg.rho,
            "m_max": reg.m_max,
            "gate2_profile": "single_matched_stratum_v1",
            "recovery_stratum": reg.recovery_stratum,
            "gate2_control_contract_hash": reg.gate2_control_contract_hash,
            "challenge_distribution_hash": reg.challenge_distribution_hash,
            "alpha_total": reg.alpha_total,
            "alpha_allocation": reg.active_alphas(),
            "registered_n_feedback_pairs": reg.registered_n_feedback_pairs,
            "registered_n_sham_pairs": reg.registered_n_sham_pairs,
            "gate3_checkpoint_scope": reg.gate3_checkpoint_scope,
            "gate3_paired_arm_contract_hash": reg.gate3_paired_arm_contract_hash,
            "gate3_truthful_arm_contract_hash": reg.gate3_truthful_arm_contract_hash,
            "gate3_neutral_arm_contract_hash": reg.gate3_neutral_arm_contract_hash,
            "gate3_neutral_recovery_contract_hash": reg.gate3_neutral_recovery_contract_hash,
            "gate3_pair_randomization_distribution_hash": reg.gate3_pair_randomization_distribution_hash,
            "sham_randomization_distribution_hash": reg.sham_randomization_distribution_hash,
            "delta_evidence": reg.delta_evidence,
            "delta_sham": reg.delta_sham,
            "rho_placebo": reg.rho_placebo,
            "max_model_failure_rate": reg.max_model_failure_rate,
            "max_execution_contract_violation_rate": reg.max_execution_contract_violation_rate,
        },
        "registration": {
            "complete": not reg_errors,
            "errors": reg_errors,
            "frozen": _registration_dict(reg),
        },
        "integrity": {
            "complete": not integrity_errors,
            "errors": integrity_errors,
            "gate3_complete": not gate3_integrity_errors,
            "gate3_errors": gate3_integrity_errors,
            "neutral_candidate_integrity_complete": not gate3_neutral_hit_integrity_errors,
            "neutral_candidate_errors": gate3_neutral_hit_integrity_errors,
            "neutral_ledger_integrity_complete": not gate3_neutral_ledger_integrity_errors,
            "neutral_ledger_errors": gate3_neutral_ledger_integrity_errors,
            "neutral_positive_witness_preserved": decisive_neutral_veto,
            "evidence": asdict(integrity)
            if isinstance(integrity, IntegrityEvidence)
            else None,
        },
        "fields": {
            "result_validity": g1.result_validity.value,
            "no_feedback_recovery": g2.no_feedback_recovery.value,
            "feedback_effect": g3.feedback_effect.value
            if g3
            else EffectStatus.NOT_TESTED.value,
            "sham_adequacy": g3.sham_adequacy.value if g3 else "not_tested",
            "neutral_recovery": g3.neutral_recovery.value if g3 else "not_tested",
            "initial_evidence_effect": "not_tested",
            "external_recovery": "not_assessed",
            "human_assistance": integrity.human_assistance
            if isinstance(integrity, IntegrityEvidence)
            else "unresolved",
            "attribution_subject": integrity.attribution_subject
            if isinstance(integrity, IntegrityEvidence)
            else "unresolved",
            "historical_novelty": "not_assessed",
        },
        "validity": {
            "status": g1.result_validity.value,
            "astar_validity": g1.astar_validity.value,
            "baseline_validity": g1.baseline_validity.value,
            "x": g1.x,
            "effect_mean": g1.effect_mean,
            "effect_ci": [g1.effect_lcb, g1.effect_ucb],
            "delta_min": reg.delta_min,
            "epsilon": _safe_epsilon(reg),
            "alpha_main": reg.alpha_main,
            "baseline_fails_p": g1.baseline_fails_p.value,
            "reason": g1.reason,
        },
        "no_feedback_recovery": {
            "status": g2.no_feedback_recovery.value,
            "adequacy_pass": g2.adequacy_pass,
            "adequacy_reasons": g2.adequacy_reasons,
            "positive_control": {
                "successes": g2.positive_control_successes,
                "trials": g2.positive_control_trials,
                "lcb": g2.positive_control_recall_lcb,
                "alpha": reg.alpha_adequacy,
                "calibration_id": g2.adequacy_calibration_id,
                "manifest_hash": g2.adequacy_manifest_hash,
            },
            "a_i": g2.a_i,
            "n_started": g2.n_started,
            "n_evaluable": g2.n_evaluable,
            "n_ind": g2.n_ind,
            "hits": g2.hits,
            "admissible_hits": g2.admissible_hits,
            "unresolved": g2.unresolved,
            "hit_admissibility_pass": g2.hit_admissibility_pass,
            "hit_admissibility_reasons": g2.hit_admissibility_reasons,
            "best_control_margin": g2.best_control_margin,
            "p_upper": g2.p_upper,
            "rho": reg.rho,
            "alpha_score": reg.alpha_score,
            "alpha_recovery": reg.alpha_recovery,
            "attempt_breakdown": _attempt_breakdown(g2),
            "attempts": [_classification_dict(c) for c in g2.classifications],
            "reason": g2.reason,
        },
        "verdict": {
            "core": verdict.core.value,
            "evidence": verdict.evidence.value,
            "core_inconclusive_class": verdict.core_inconclusive_class.value,
            "evidence_inconclusive_class": verdict.evidence_inconclusive_class.value,
            "statement": verdict.statement,
            "reason": verdict.reason,
        },
    }

    if g3 is not None:
        cert["feedback_test"] = {
            "checkpoint_scope": g3.checkpoint_scope,
            "checkpoint_hash": g3.checkpoint_hash,
            "window_hash": g3.window_hash,
            "feedback_pairs_manifest_hash": g3.feedback_pairs_manifest_hash,
            "design_checks_pass": g3.design_checks_pass,
            "stopping_rule_pass": g3.stopping_rule_pass,
            "registered_pairs_complete": g3.registered_pairs_complete,
            "all_started_pairs_disclosed": g3.all_started_pairs_disclosed,
            "no_pair_replacements": g3.no_pair_replacements,
            "paired_contract_audit_pass": g3.paired_contract_audit_pass,
            "truthful_channel_audit_pass": g3.truthful_channel_audit_pass,
            "neutral_channel_audit_pass": g3.neutral_channel_audit_pass,
            "started_pair_count": g3.started_pair_count,
            "paired_arm_contract_hash": g3.paired_arm_contract_hash,
            "truthful_arm_contract_hash": g3.truthful_arm_contract_hash,
            "neutral_arm_contract_hash": g3.neutral_arm_contract_hash,
            "neutral_recovery_contract_hash": g3.neutral_recovery_contract_hash,
            "truthful_feedback_generator_hash": g3.truthful_feedback_generator_hash,
            "neutral_sham_generator_hash": g3.neutral_sham_generator_hash,
            "contract_preseal_receipt_hash": g3.contract_preseal_receipt_hash,
            "contract_sealed_before_branches_pass": g3.contract_sealed_before_branches_pass,
            "contract_sealed_event_index": g3.contract_sealed_event_index,
            "first_branch_started_event_index": g3.first_branch_started_event_index,
            "neutral_scope_audit_manifest_hash": g3.neutral_scope_audit_manifest_hash,
            "neutral_challenger_policy_hash": g3.neutral_challenger_policy_hash,
            "neutral_scope_contract": g3.neutral_scope_contract,
            "neutral_in_gate2_scope": g3.neutral_in_gate2_scope,
            "estimand": reg.feedback_estimand,
            "utility_mapping": reg.feedback_utility_mapping,
            "utility_scale_id": reg.utility_scale_id,
            "sham_calibration_id": reg.sham_calibration_id,
            "sham_contract": {
                "paired_arm_contract_hash": g3.sham_paired_arm_contract_hash,
                "reference_arm_contract_hash": g3.sham_reference_arm_contract_hash,
                "proposed_arm_contract_hash": g3.sham_proposed_arm_contract_hash,
                "reference_null_generator_hash": g3.sham_reference_null_generator_hash,
                "proposed_sham_generator_hash": reg.sham_operator_hash,
                "contract_preseal_receipt_hash": g3.sham_contract_preseal_receipt_hash,
                "contract_sealed_event_index": g3.sham_contract_sealed_event_index,
                "first_branch_started_event_index": g3.sham_first_branch_started_event_index,
            },
            "sham_adequacy": g3.sham_adequacy.value,
            "sham_delta_null_mean": g3.sham_delta_null_mean,
            "sham_delta_null_ci": [g3.sham_delta_null_lcb, g3.sham_delta_null_ucb],
            "sham_n": g3.sham_n,
            "sham_all_started_pairs_disclosed": g3.sham_all_started_pairs_disclosed,
            "sham_no_pair_replacements": g3.sham_no_pair_replacements,
            "sham_started_pair_count": g3.sham_started_pair_count,
            "delta_sham": reg.delta_sham,
            "alpha_sham": reg.alpha_sham,
            "feedback_effect": g3.feedback_effect.value,
            "effect_mean": g3.effect_mean,
            "effect_ci": [g3.effect_lcb, g3.effect_ucb],
            "n_pairs_started": g3.n_pairs_started,
            "n_pairs_analyzed": g3.n_pairs_analyzed,
            "pair_ids_analyzed": g3.pair_ids_analyzed,
            "pair_records": g3.pair_records,
            "pairs_unresolved": g3.pairs_unresolved,
            "pairs_infrastructure_excluded": g3.pairs_infrastructure_excluded,
            "branch_health": {
                "pass": g3.branch_health_pass,
                "reasons": g3.branch_health_reasons,
                "truthful_valid_rate": g3.truthful_valid_rate,
                "neutral_valid_rate": g3.neutral_valid_rate,
                "truthful_model_failure_rate": g3.truthful_model_failure_rate,
                "neutral_model_failure_rate": g3.neutral_model_failure_rate,
                "pair_infrastructure_failure_rate": g3.pair_infrastructure_failure_rate,
            },
            "delta_evidence": reg.delta_evidence,
            "alpha_evidence": reg.alpha_evidence,
            "development_manifest_hash": g3.sham_development_manifest_hash,
            "confirmatory_manifest_hash": g3.sham_confirmatory_manifest_hash,
            "sham_pair_records": g3.sham_pair_records,
            "neutral_recovery": {
                "status": g3.neutral_recovery.value,
                "adequacy_pass": g3.neutral_adequacy_pass,
                "adequacy_reasons": g3.neutral_adequacy_reasons,
                "positive_control": {
                    "successes": g3.neutral_positive_control_successes,
                    "trials": g3.neutral_positive_control_trials,
                    "lcb": g3.neutral_positive_control_recall_lcb,
                    "alpha": reg.alpha_adequacy,
                    "calibration_id": g3.neutral_adequacy_calibration_id,
                    "manifest_hash": g3.neutral_adequacy_manifest_hash,
                },
                "n_ind": g3.neutral_n_ind,
                "hits": g3.neutral_hits,
                "admissible_hits": g3.neutral_admissible_hits,
                "unresolved": g3.neutral_unresolved,
                "p_upper": g3.neutral_p_upper,
                "rho_placebo": reg.rho_placebo,
                "alpha_neutral": reg.alpha_neutral,
                "attempts": [
                    _classification_dict(c) for c in g3.neutral_classifications
                ],
                "reason": g3.neutral_reason,
            },
            "lineage_empty_hit_refutes_core": g3.lineage_empty_hit_refutes_core,
            "reason": g3.reason,
        }
        if g3.neutral_contract_audit_pass is not None:
            cert["feedback_test"]["neutral_contract_audit_pass"] = (
                g3.neutral_contract_audit_pass
            )
    if reg.gate3_pair_replacement_policy != PAIR_REPLACEMENT_POLICY_NONE:
        cert["scope"]["gate3_pair_replacement_policy"] = (
            reg.gate3_pair_replacement_policy
        )
        cert["scope"]["max_feedback_pair_replacements"] = (
            reg.max_feedback_pair_replacements
        )
        cert["scope"]["max_sham_pair_replacements"] = (
            reg.max_sham_pair_replacements
        )
    return _sanitize(cert)


def _registration_dict(reg: Registration) -> dict:
    """Serialize new defaults without changing legacy no-replacement records."""

    payload = asdict(reg)
    if (
        reg.gate3_pair_replacement_policy == PAIR_REPLACEMENT_POLICY_NONE
        and reg.max_feedback_pair_replacements == 0
        and reg.max_sham_pair_replacements == 0
    ):
        payload.pop("gate3_pair_replacement_policy", None)
        payload.pop("max_feedback_pair_replacements", None)
        payload.pop("max_sham_pair_replacements", None)
    return payload


def _attempt_breakdown(g2: Gate2Result) -> dict[str, int]:
    counts: dict[str, int] = {}
    for c in g2.classifications:
        counts[c.status.value] = counts.get(c.status.value, 0) + 1
    return counts


def _classification_dict(c) -> dict:
    return {
        "attempt_id": c.attempt_id,
        "artifact_hash": c.artifact_hash,
        "verifier_result_hash": c.verifier_result_hash,
        "stratum": c.stratum,
        "scope_contract_hash": c.scope_contract_hash,
        "prestart_contract_receipt_hash": c.prestart_contract_receipt_hash,
        "challenge_distribution_hash": c.challenge_distribution_hash,
        "independent_draw_receipt_hash": c.independent_draw_receipt_hash,
        "independent_unit_id": c.independent_unit_id,
        "status": c.status.value,
        "d_mean": c.d_mean,
        "adjusted_ci": [c.d_lcb, c.d_ucb],
        "counts_in_denominator": c.counts_in_denominator,
        "counts_in_n_ind": c.counts_in_n_ind,
        "reason": c.reason,
    }


def certificate_json(cert: dict, indent: Optional[int] = 2) -> str:
    # NaN/Infinity are invalid JSON and must never leak into a certificate.
    return json.dumps(cert, indent=indent, sort_keys=False, allow_nan=False)


def _safe_epsilon(reg: Registration):
    try:
        value = float(reg.kappa) * float(reg.delta_min)
    except (TypeError, ValueError, OverflowError):
        return None
    return value if math.isfinite(value) else None


def _sanitize(value):
    if value is None or isinstance(value, (str, int, bool)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(k): _sanitize(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_sanitize(v) for v in value]
    return f"<non-json:{type(value).__name__}>"
