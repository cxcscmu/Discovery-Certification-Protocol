"""Frozen DCP-v2 registration and fail-closed numeric constraints."""

from __future__ import annotations

import json
import math
import unicodedata
from dataclasses import dataclass, field

RHO_MAX = 0.05
RHO_PLACEBO_MAX = 0.05
ALPHA_MAX = 0.05
POSITIVE_CONTROL_RECALL_FLOOR = 0.80
VALID_CANDIDATE_RATE_FLOOR = 0.50
INFRASTRUCTURE_FAILURE_RATE_CAP = 0.20
MODEL_FAILURE_RATE_CAP = 0.20
PAIR_REPLACEMENT_POLICY_NONE = "none"
PAIR_REPLACEMENT_POLICY_TRANSPORT = "preaction_transport_pair_replacement_v1"


@dataclass
class Registration:
    claim_id: str
    audit_family_id: str = ""
    model_id: str = ""
    interface_hash: str = ""
    task_family_profile: str = ""
    grade_requested: str = "core"  # core | evidence

    # Registered inference scope.  A sampled population uses the stated model
    # assumptions; an exhaustive finite set is evaluated exactly.
    inference_scope: str = "sampled_population"
    ci_method: str = "bounded_empirical_bernstein"
    score_range_id: str = "normalized_unit_interval_v1"
    feedback_inference_scope: str = "sampled_population"
    feedback_ci_method: str = "bounded_empirical_bernstein"
    sham_inference_scope: str = "sampled_population"
    sham_ci_method: str = "bounded_empirical_bernstein"

    # Gate 1.
    delta_min: float = 0.05
    kappa: float = 0.0
    alpha_main: float = 0.005

    # Gate 2.  m_max is global across all candidate artifacts whose score
    # classification can change this certificate (main + neutral recovery).
    m_max: int = 100
    recovery_stratum: str = "matched"
    gate2_control_contract_hash: str = ""
    challenge_distribution_hash: str = ""
    rho: float = 0.05
    alpha_score: float = 0.005
    alpha_recovery: float = 0.020
    alpha_adequacy: float = 0.005
    positive_control_recall_min: float = 0.80
    min_valid_candidate_rate: float = 0.50
    max_infrastructure_failure_rate: float = 0.20
    max_model_failure_rate: float = 0.20
    max_execution_contract_violation_rate: float = 0.0
    min_n_ind: int = 1

    # Gate 3.
    delta_evidence: float = 0.05
    delta_sham: float = 0.02
    rho_placebo: float = 0.05
    alpha_evidence: float = 0.005
    alpha_sham: float = 0.005
    alpha_neutral: float = 0.005  # zero-hit neutral-recovery bound only
    feedback_estimand: str = "continuous"  # continuous | binary
    feedback_utility_mapping: str = "mean_normalized_private_units_v1"
    registered_n_feedback_pairs: int = 2
    registered_n_sham_pairs: int = 2
    gate3_pair_replacement_policy: str = PAIR_REPLACEMENT_POLICY_NONE
    max_feedback_pair_replacements: int = 0
    max_sham_pair_replacements: int = 0
    worst_utility: float = 0.0
    necessity_claim_requested: bool = False

    scaffold_hash: str = ""
    feedback_schema_hash: str = ""
    sham_operator_hash: str = ""
    utility_scale_id: str = ""
    sham_calibration_id: str = ""
    gate3_checkpoint_scope: str = "lineage_prefix"
    gate3_paired_arm_contract_hash: str = ""
    gate3_truthful_arm_contract_hash: str = ""
    gate3_neutral_arm_contract_hash: str = ""
    gate3_neutral_recovery_contract_hash: str = ""
    gate3_checkpoint_selection_rule_hash: str = ""
    gate3_resource_contract_hash: str = ""
    gate3_opportunity_contract_hash: str = ""
    gate3_branch_policy_hash: str = ""
    truthful_feedback_generator_hash: str = ""
    neutral_sham_generator_hash: str = ""
    gate3_pair_randomization_distribution_hash: str = ""
    sham_randomization_distribution_hash: str = ""
    sham_paired_arm_contract_hash: str = ""
    sham_reference_arm_contract_hash: str = ""
    sham_proposed_arm_contract_hash: str = ""
    reference_null_generator_hash: str = ""
    min_feedback_arm_valid_rate: float = 0.80
    max_feedback_arm_model_failure_rate: float = 0.10
    max_feedback_pair_infrastructure_rate: float = 0.10

    alpha_total: float = 0.05
    family_alpha_total: float = 0.05
    family_max_audits: int = 1
    audit_slot_id: str = ""
    audit_slot_reservation_receipt_hash: str = ""
    notes: dict = field(default_factory=dict)

    @property
    def epsilon(self) -> float:
        return self.kappa * self.delta_min

    @property
    def requests_evidence(self) -> bool:
        return self.grade_requested == "evidence"

    @property
    def exact_finite_set(self) -> bool:
        return self.inference_scope == "exhaustive_finite_set"

    def active_alphas(self) -> dict[str, float]:
        alphas = {
            "alpha_main": self.alpha_main,
            "alpha_score": self.alpha_score,
            "alpha_recovery": self.alpha_recovery,
            "alpha_adequacy": self.alpha_adequacy,
        }
        if self.requests_evidence:
            alphas.update(
                alpha_evidence=self.alpha_evidence,
                alpha_sham=self.alpha_sham,
                alpha_neutral=self.alpha_neutral,
            )
        return alphas


def _finite_number(value: object) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


def _required_text(value: object, name: str, errors: list[str]) -> None:
    if (
        not isinstance(value, str)
        or not value.strip()
        or "unspecified" in value.lower()
    ):
        errors.append(f"{name} must be an explicit non-placeholder string")


def _canonical_identifier(value: object, name: str, errors: list[str]) -> None:
    _required_text(value, name, errors)
    if not isinstance(value, str) or not value.strip():
        return
    if (
        value != value.strip()
        or unicodedata.normalize("NFC", value) != value
        or any(
            char.isspace() or unicodedata.category(char).startswith("C")
            for char in value
        )
    ):
        errors.append(f"{name} must be a canonical whitespace-free identifier")


def validate_registration(reg: Registration) -> list[str]:
    errors: list[str] = []

    _canonical_identifier(reg.claim_id, "claim_id", errors)
    _canonical_identifier(reg.audit_family_id, "audit_family_id", errors)
    _required_text(reg.model_id, "model_id", errors)
    _required_text(reg.interface_hash, "interface_hash", errors)
    _required_text(reg.task_family_profile, "task_family_profile", errors)

    if reg.grade_requested not in ("core", "evidence"):
        errors.append(
            f"grade_requested must be core|evidence, got {reg.grade_requested!r}"
        )

    valid_scope_method = {
        ("sampled_population", "bounded_empirical_bernstein"),
        ("exhaustive_finite_set", "finite_set_exact"),
    }
    if (reg.inference_scope, reg.ci_method) not in valid_scope_method:
        errors.append(
            "inference_scope/ci_method must be "
            "sampled_population/bounded_empirical_bernstein "
            "or exhaustive_finite_set/finite_set_exact"
        )
    if reg.score_range_id != "normalized_unit_interval_v1":
        errors.append("score_range_id must be normalized_unit_interval_v1")

    if not _finite_number(reg.delta_min) or not reg.delta_min > 0:
        errors.append("delta_min must be finite and > 0")
    if not _finite_number(reg.kappa) or not (0.0 <= reg.kappa < 1.0):
        errors.append("kappa must satisfy 0 <= kappa < 1")
    if _finite_number(reg.delta_min) and _finite_number(reg.kappa):
        if not (0.0 <= reg.epsilon < reg.delta_min):
            errors.append("epsilon must satisfy 0 <= epsilon < delta_min")

    if not _finite_number(reg.rho) or not (0.0 < reg.rho <= RHO_MAX):
        errors.append(f"rho must satisfy 0 < rho <= {RHO_MAX}")
    if not isinstance(reg.m_max, int) or isinstance(reg.m_max, bool) or reg.m_max < 1:
        errors.append("m_max must be an integer >= 1")
    _canonical_identifier(reg.recovery_stratum, "recovery_stratum", errors)
    _required_text(
        reg.gate2_control_contract_hash, "gate2_control_contract_hash", errors
    )
    _required_text(
        reg.challenge_distribution_hash, "challenge_distribution_hash", errors
    )
    if (
        not isinstance(reg.min_n_ind, int)
        or isinstance(reg.min_n_ind, bool)
        or reg.min_n_ind < 1
    ):
        errors.append("min_n_ind must be an integer >= 1")

    if type(reg.necessity_claim_requested) is not bool:
        errors.append("necessity_claim_requested must be a boolean")

    for name in (
        "positive_control_recall_min",
        "min_valid_candidate_rate",
        "max_infrastructure_failure_rate",
        "max_model_failure_rate",
        "max_execution_contract_violation_rate",
    ):
        value = getattr(reg, name)
        if not _finite_number(value) or not (0.0 <= value <= 1.0):
            errors.append(f"{name} must be finite and in [0,1]")
    if _finite_number(reg.positive_control_recall_min) and (
        reg.positive_control_recall_min < POSITIVE_CONTROL_RECALL_FLOOR
    ):
        errors.append(
            f"positive_control_recall_min cannot be below protocol floor "
            f"{POSITIVE_CONTROL_RECALL_FLOOR}"
        )
    if _finite_number(reg.min_valid_candidate_rate) and (
        reg.min_valid_candidate_rate < VALID_CANDIDATE_RATE_FLOOR
    ):
        errors.append(
            f"min_valid_candidate_rate cannot be below protocol floor "
            f"{VALID_CANDIDATE_RATE_FLOOR}"
        )
    if _finite_number(reg.max_infrastructure_failure_rate) and (
        reg.max_infrastructure_failure_rate > INFRASTRUCTURE_FAILURE_RATE_CAP
    ):
        errors.append(
            f"max_infrastructure_failure_rate cannot exceed protocol cap "
            f"{INFRASTRUCTURE_FAILURE_RATE_CAP}"
        )
    if _finite_number(reg.max_model_failure_rate) and (
        reg.max_model_failure_rate > MODEL_FAILURE_RATE_CAP
    ):
        errors.append(
            f"max_model_failure_rate cannot exceed protocol cap "
            f"{MODEL_FAILURE_RATE_CAP}"
        )
    if _finite_number(reg.max_execution_contract_violation_rate) and (
        reg.max_execution_contract_violation_rate != 0.0
    ):
        errors.append("max_execution_contract_violation_rate must be 0 in this kernel")

    if not _finite_number(reg.alpha_total) or not (0.0 < reg.alpha_total <= ALPHA_MAX):
        errors.append(f"alpha_total must satisfy 0 < alpha_total <= {ALPHA_MAX}")
    for name, alpha in reg.active_alphas().items():
        if not _finite_number(alpha) or not (0.0 < alpha < 1.0):
            errors.append(f"{name} must be finite and in (0,1), got {alpha}")
    if all(_finite_number(a) for a in reg.active_alphas().values()) and _finite_number(
        reg.alpha_total
    ):
        budget = sum(reg.active_alphas().values())
        if budget > reg.alpha_total + 1e-12:
            errors.append(
                f"sum(active alphas)={budget:.4f} exceeds alpha_total={reg.alpha_total:.4f}"
            )
    if not _finite_number(reg.family_alpha_total) or not (
        0.0 < reg.family_alpha_total <= ALPHA_MAX
    ):
        errors.append(
            f"family_alpha_total must satisfy 0 < family_alpha_total <= {ALPHA_MAX}"
        )
    if (
        not isinstance(reg.family_max_audits, int)
        or isinstance(reg.family_max_audits, bool)
        or reg.family_max_audits < 1
    ):
        errors.append("family_max_audits must be an integer >= 1")
    elif _finite_number(reg.alpha_total) and _finite_number(reg.family_alpha_total):
        if reg.alpha_total * reg.family_max_audits > reg.family_alpha_total + 1e-12:
            errors.append("alpha_total * family_max_audits exceeds family_alpha_total")
    _canonical_identifier(reg.audit_slot_id, "audit_slot_id", errors)
    _canonical_identifier(
        reg.audit_slot_reservation_receipt_hash,
        "audit_slot_reservation_receipt_hash",
        errors,
    )

    if reg.requests_evidence:
        if not _finite_number(reg.delta_evidence) or not reg.delta_evidence > 0:
            errors.append("delta_evidence must be finite and > 0 for evidence grade")
        if (
            not _finite_number(reg.delta_sham)
            or not _finite_number(reg.delta_evidence)
            or not (0.0 < reg.delta_sham <= reg.delta_evidence / 2.0)
        ):
            errors.append("delta_sham must satisfy 0 < delta_sham <= delta_evidence/2")
        if not _finite_number(reg.rho_placebo) or not (
            0.0 < reg.rho_placebo <= RHO_PLACEBO_MAX
        ):
            errors.append(
                f"rho_placebo must satisfy 0 < rho_placebo <= {RHO_PLACEBO_MAX}"
            )
        if reg.feedback_estimand not in ("continuous", "binary"):
            errors.append("feedback_estimand must be continuous|binary")
        if reg.feedback_estimand == "continuous":
            if reg.feedback_utility_mapping != "mean_normalized_private_units_v1":
                errors.append(
                    "continuous feedback requires mean_normalized_private_units_v1 mapping"
                )
            for prefix, scope, method in (
                ("feedback", reg.feedback_inference_scope, reg.feedback_ci_method),
                ("sham", reg.sham_inference_scope, reg.sham_ci_method),
            ):
                if (scope, method) != (
                    "sampled_population",
                    "bounded_empirical_bernstein",
                ):
                    errors.append(
                        f"continuous {prefix} requires sampled_population/"
                        "bounded_empirical_bernstein"
                    )
        elif reg.feedback_estimand == "binary":
            if reg.feedback_utility_mapping != "canonical_p_wrapper_v1":
                errors.append("binary feedback requires canonical_p_wrapper_v1 mapping")
            if (
                reg.feedback_inference_scope,
                reg.feedback_ci_method,
            ) != ("sampled_population", "paired_binary_exact"):
                errors.append(
                    "binary feedback requires sampled_population/paired_binary_exact"
                )
            if (reg.sham_inference_scope, reg.sham_ci_method) != (
                "sampled_population",
                "paired_binary_exact",
            ):
                errors.append(
                    "binary sham requires sampled_population/paired_binary_exact"
                )
        if (
            not isinstance(reg.registered_n_feedback_pairs, int)
            or isinstance(reg.registered_n_feedback_pairs, bool)
            or reg.registered_n_feedback_pairs < 2
        ):
            errors.append("registered_n_feedback_pairs must be an integer >= 2")
        if (
            not isinstance(reg.registered_n_sham_pairs, int)
            or isinstance(reg.registered_n_sham_pairs, bool)
            or reg.registered_n_sham_pairs < 2
        ):
            errors.append("registered_n_sham_pairs must be an integer >= 2")
        if reg.gate3_pair_replacement_policy not in {
            PAIR_REPLACEMENT_POLICY_NONE,
            PAIR_REPLACEMENT_POLICY_TRANSPORT,
        }:
            errors.append(
                "gate3_pair_replacement_policy must be "
                "none|preaction_transport_pair_replacement_v1"
            )
        for name in (
            "max_feedback_pair_replacements",
            "max_sham_pair_replacements",
        ):
            value = getattr(reg, name)
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 0
            ):
                errors.append(f"{name} must be an integer >= 0")
        if reg.gate3_pair_replacement_policy == PAIR_REPLACEMENT_POLICY_NONE:
            if (
                reg.max_feedback_pair_replacements != 0
                or reg.max_sham_pair_replacements != 0
            ):
                errors.append(
                    "replacement limits must be zero when replacement policy is none"
                )
        elif (
            isinstance(reg.max_feedback_pair_replacements, int)
            and not isinstance(reg.max_feedback_pair_replacements, bool)
            and isinstance(reg.registered_n_feedback_pairs, int)
            and not isinstance(reg.registered_n_feedback_pairs, bool)
            and _finite_number(reg.max_feedback_pair_infrastructure_rate)
            and reg.max_feedback_pair_replacements
            > math.floor(
                reg.registered_n_feedback_pairs
                * reg.max_feedback_pair_infrastructure_rate
                + 1e-12
            )
        ):
            errors.append(
                "max_feedback_pair_replacements exceeds the registered "
                "feedback infrastructure-attrition cap"
            )
        if (
            reg.gate3_pair_replacement_policy
            == PAIR_REPLACEMENT_POLICY_TRANSPORT
            and isinstance(reg.max_sham_pair_replacements, int)
            and not isinstance(reg.max_sham_pair_replacements, bool)
            and isinstance(reg.registered_n_sham_pairs, int)
            and not isinstance(reg.registered_n_sham_pairs, bool)
            and _finite_number(reg.max_infrastructure_failure_rate)
            and reg.max_sham_pair_replacements
            > math.floor(
                reg.registered_n_sham_pairs
                * reg.max_infrastructure_failure_rate
                + 1e-12
            )
        ):
            errors.append(
                "max_sham_pair_replacements exceeds the registered sham "
                "infrastructure-attrition cap"
            )
        if not _finite_number(reg.worst_utility) or reg.worst_utility != 0.0:
            errors.append("normalized Gate-3 ITT requires worst_utility=0")
        for name in (
            "scaffold_hash",
            "feedback_schema_hash",
            "sham_operator_hash",
            "utility_scale_id",
            "sham_calibration_id",
            "gate3_paired_arm_contract_hash",
            "gate3_truthful_arm_contract_hash",
            "gate3_neutral_arm_contract_hash",
            "gate3_neutral_recovery_contract_hash",
            "gate3_checkpoint_selection_rule_hash",
            "gate3_resource_contract_hash",
            "gate3_opportunity_contract_hash",
            "gate3_branch_policy_hash",
            "truthful_feedback_generator_hash",
            "neutral_sham_generator_hash",
            "gate3_pair_randomization_distribution_hash",
            "sham_randomization_distribution_hash",
            "sham_paired_arm_contract_hash",
            "sham_reference_arm_contract_hash",
            "sham_proposed_arm_contract_hash",
            "reference_null_generator_hash",
        ):
            _required_text(getattr(reg, name), name, errors)
        if reg.neutral_sham_generator_hash != reg.sham_operator_hash:
            errors.append(
                "target neutral-sham generator must equal the calibrated sham operator"
            )
        if reg.gate3_checkpoint_scope not in {"lineage_empty", "lineage_prefix"}:
            errors.append("gate3_checkpoint_scope must be lineage_empty|lineage_prefix")
        for name in (
            "min_feedback_arm_valid_rate",
            "max_feedback_arm_model_failure_rate",
            "max_feedback_pair_infrastructure_rate",
        ):
            value = getattr(reg, name)
            if not _finite_number(value) or not (0.0 <= value <= 1.0):
                errors.append(f"{name} must be finite and in [0,1]")
        if (
            _finite_number(reg.min_feedback_arm_valid_rate)
            and reg.min_feedback_arm_valid_rate < VALID_CANDIDATE_RATE_FLOOR
        ):
            errors.append(
                "min_feedback_arm_valid_rate cannot be below protocol floor "
                f"{VALID_CANDIDATE_RATE_FLOOR}"
            )
        if (
            _finite_number(reg.max_feedback_arm_model_failure_rate)
            and reg.max_feedback_arm_model_failure_rate > MODEL_FAILURE_RATE_CAP
        ):
            errors.append(
                "max_feedback_arm_model_failure_rate cannot exceed protocol cap "
                f"{MODEL_FAILURE_RATE_CAP}"
            )
        if (
            _finite_number(reg.max_feedback_pair_infrastructure_rate)
            and reg.max_feedback_pair_infrastructure_rate
            > INFRASTRUCTURE_FAILURE_RATE_CAP
        ):
            errors.append(
                "max_feedback_pair_infrastructure_rate cannot exceed protocol cap "
                f"{INFRASTRUCTURE_FAILURE_RATE_CAP}"
            )
    elif reg.necessity_claim_requested:
        errors.append("necessity_claim_requested requires grade_requested='evidence'")

    if not isinstance(reg.notes, dict):
        errors.append("notes must be a JSON object")
    else:
        try:
            json.dumps(reg.notes, allow_nan=False)
        except (TypeError, ValueError, OverflowError):
            errors.append("notes must be strict-JSON serializable")

    return errors
