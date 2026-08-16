"""Typed evidence and result records for the DCP-v2 evaluation core.

Defaults are deliberately fail-closed.  A missing validity decision, adequacy
attestation, independent-unit id, or provenance check is ``unresolved`` rather
than silently treated as a successful audit.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Sequence


class Validity(str, Enum):
    VALID = "valid"
    INVALID = "invalid"
    UNRESOLVED = "unresolved"


class RawAttemptOutcome(str, Enum):
    """Mutually exclusive outcome recorded before score classification."""

    ARTIFACT = "artifact"
    MODEL_FAILURE = "model_failure"
    EXECUTION_CONTRACT_VIOLATION = "execution_contract_violation"
    INFRASTRUCTURE_INVALID = "infrastructure_invalid"
    UNRESOLVED = "unresolved"


class AttemptStatus(str, Enum):
    CONFIRMED_HIT = "confirmed_hit"
    CONFIRMED_MISS = "confirmed_miss"
    MODEL_FAILURE = "model_failure"
    EXECUTION_CONTRACT_VIOLATION = "execution_contract_violation"
    INFRASTRUCTURE_INVALID = "infrastructure_invalid"
    UNRESOLVED = "unresolved"


class TriState(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    INCONCLUSIVE = "inconclusive"


class Recovery(str, Enum):
    RECOVERED = "recovered"
    NOT_RECOVERED_WITHIN_SCOPE = "not_recovered_within_scope"
    INCONCLUSIVE = "inconclusive"


class EffectStatus(str, Enum):
    SUPPORTED = "supported"
    NOT_SUPPORTED = "not_supported"
    INCONCLUSIVE = "inconclusive"
    NOT_TESTED = "not_tested"


class CoreVerdict(str, Enum):
    CERTIFIED = "certified"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"


class EvidenceVerdict(str, Enum):
    CERTIFIED = "certified"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"
    NOT_TESTED = "not_tested"


class InconclusiveClass(str, Enum):
    """Why a grade is inconclusive; it never changes the grade itself."""

    NULL = "null"
    AUDIT_INCOMPLETE = "audit_incomplete"
    STATISTICAL_UNCERTAINTY = "statistical_uncertainty"


@dataclass
class ArtifactScores:
    """One artifact evaluated on an explicitly ordered private-unit manifest."""

    name: str
    per_unit: Sequence[float]
    validity: Validity = Validity.UNRESOLVED
    artifact_hash: str = ""
    unit_ids: Sequence[str] = field(default_factory=tuple)


@dataclass
class IntegrityEvidence:
    """Non-statistical audit envelope required for a sealed decision record.

    The harness/provenance layer produces these attestations.  The numerical
    kernel does not try to infer them from scores.
    """

    registration_frozen: bool = False
    claim_frozen: bool = False
    provenance_pass: bool = False
    iterative_lineage_eligible: bool = False
    lineage_dataflow_audit_pass: bool = False
    challenger_contract_pass: bool = False
    private_isolation_pass: bool = False
    symmetric_verifier_pass: bool = False
    inference_assumptions_pass: bool = False
    feedback_inference_assumptions_pass: bool = False
    sham_inference_assumptions_pass: bool = False
    familywise_budget_audit_pass: bool = False

    astar_hash: str = ""
    baseline_hash: str = ""
    verifier_hash: str = ""
    astar_results_hash: str = ""
    baseline_results_hash: str = ""
    private_unit_manifest_hash: str = ""
    private_results_manifest_hash: str = ""
    p_hash: str = ""
    resource_contract_hash: str = ""
    selection_rule_hash: str = ""
    k_manifest_hash: str = ""
    e0_manifest_hash: str = ""
    lineage_manifest_hash: str = ""
    observed_web_manifest_hash: str = ""
    challenger_policy_hash: str = ""
    opportunity_contract_hash: str = ""
    recovery_ledger_complete: bool = False
    recovery_ledger_manifest_hash: str = ""
    gate2_recovery_ledger_manifest_hash: str = ""
    gate3_neutral_scope_manifest_hash: str = ""
    gate3_neutral_recovery_ledger_manifest_hash: str = ""
    gate3_contract_preseal_receipt_hash: str = ""
    sham_contract_preseal_receipt_hash: str = ""
    claim_family_manifest_hash: str = ""
    alpha_ledger_receipt_hash: str = ""
    audit_slot_registry_entry_hash: str = ""

    human_assistance: str = ""
    attribution_subject: str = ""
    web_access_used: bool = False
    web_replay_scope: str = ""


@dataclass
class Gate1Evidence:
    astar: ArtifactScores
    baseline: ArtifactScores


@dataclass
class ControlAttempt:
    """One challenger slot with an explicit, mutually exclusive raw outcome."""

    attempt_id: str
    outcome: RawAttemptOutcome = RawAttemptOutcome.UNRESOLVED
    per_unit: Optional[Sequence[float]] = None
    validity: Validity = Validity.UNRESOLVED
    artifact_hash: str = ""
    unit_ids: Sequence[str] = field(default_factory=tuple)
    stratum: str = ""
    scope_contract_hash: str = ""
    prestart_contract_receipt_hash: str = ""
    challenge_distribution_hash: str = ""
    independent_draw_receipt_hash: str = ""
    independent_unit_id: str = ""
    independence_ok: bool = False
    infrastructure_outcome_independent: bool = False


@dataclass
class AdequacyEvidence:
    """Observed adequacy checks; thresholds live in ``Registration``."""

    matched_model_present: bool = False
    materials_readable: bool = False
    opportunity_floor_met: bool = False
    health_audit_pass: bool = False
    positive_control_successes: int = -1
    positive_control_trials: int = -1
    calibration_id: str = ""
    checks_manifest_hash: str = ""


@dataclass
class Gate2Evidence:
    controls: Sequence[ControlAttempt] = field(default_factory=tuple)
    adequacy: AdequacyEvidence = field(default_factory=AdequacyEvidence)


@dataclass
class ShamPair:
    """One randomized confirmatory reference-null/proposed-sham pair."""

    pair_id: str
    reference_null: BranchOutcome
    proposed_sham: BranchOutcome
    block_id: str = ""
    randomization_distribution_hash: str = ""
    randomization_draw_receipt_hash: str = ""
    assignment_frozen: bool = False
    independence_ok: bool = False
    # Empty for an originally allocated pair.  A replacement points to the
    # immediately preceding failed pair in the same registered slot.  The
    # failed pair remains in ``ShamCalibration.pairs``.
    replacement_of: str = ""


@dataclass
class ShamCalibration:
    """Fresh confirmatory null-calibration evidence for one sham operator."""

    pairs: Sequence[ShamPair]

    calibration_id: str = ""
    development_manifest_hash: str = ""
    confirmatory_manifest_hash: str = ""
    task_family_profile: str = ""
    model_id: str = ""
    interface_hash: str = ""
    scaffold_hash: str = ""
    feedback_schema_hash: str = ""
    operator_hash: str = ""
    reference_null_generator_hash: str = ""
    utility_scale_id: str = ""
    paired_arm_contract_hash: str = ""
    reference_arm_contract_hash: str = ""
    proposed_arm_contract_hash: str = ""
    contract_preseal_receipt_hash: str = ""
    contract_sealed_before_branches_pass: bool = False
    contract_sealed_event_index: int = -1
    first_branch_started_event_index: int = -1

    channel_checks_pass: bool = False
    freshness_pass: bool = False
    operator_frozen_before_confirmatory: bool = False
    development_confirmatory_disjoint: bool = False
    all_started_pairs_disclosed: bool = False
    no_pair_replacements: bool = False
    started_pair_count: int = -1


@dataclass
class BranchOutcome:
    """One truthful or neutral branch outcome before ITT mapping."""

    outcome: RawAttemptOutcome = RawAttemptOutcome.UNRESOLVED
    utility: Optional[float] = None
    validity: Validity = Validity.UNRESOLVED
    branch_id: str = ""
    artifact_hash: str = ""
    verifier_result_hash: str = ""
    execution_contract_hash: str = ""
    prestart_contract_receipt_hash: str = ""
    per_unit: Optional[Sequence[float]] = None
    unit_ids: Sequence[str] = field(default_factory=tuple)
    infrastructure_outcome_independent: bool = False


@dataclass
class FeedbackPair:
    pair_id: str
    truthful: BranchOutcome
    neutral: BranchOutcome
    block_id: str = ""
    randomization_distribution_hash: str = ""
    randomization_draw_receipt_hash: str = ""
    assignment_frozen: bool = False
    independence_ok: bool = False
    # Empty for an originally allocated pair.  A replacement points to the
    # immediately preceding failed pair in the same registered slot.  The
    # failed pair remains in ``Gate3Evidence.pairs``.
    replacement_of: str = ""


@dataclass
class Gate3Evidence:
    """Randomized pairs; each neutral branch is also the recovery ledger."""

    pairs: Sequence[FeedbackPair]
    sham: ShamCalibration
    neutral_adequacy: Optional[AdequacyEvidence] = None

    design_checks_pass: bool = False
    stopping_rule_pass: bool = False
    registered_pairs_complete: bool = False
    all_started_pairs_disclosed: bool = False
    no_pair_replacements: bool = False
    paired_contract_audit_pass: bool = False
    truthful_channel_audit_pass: bool = False
    neutral_channel_audit_pass: bool = False
    started_pair_count: int = -1
    checkpoint_scope: str = ""  # lineage_empty | lineage_prefix
    checkpoint_hash: str = ""
    window_hash: str = ""
    feedback_pairs_manifest_hash: str = ""
    paired_arm_contract_hash: str = ""
    truthful_arm_contract_hash: str = ""
    neutral_arm_contract_hash: str = ""
    neutral_recovery_contract_hash: str = ""
    truthful_feedback_generator_hash: str = ""
    neutral_sham_generator_hash: str = ""
    contract_preseal_receipt_hash: str = ""
    contract_sealed_before_branches_pass: bool = False
    contract_sealed_event_index: int = -1
    first_branch_started_event_index: int = -1
    neutral_model_id: str = ""
    neutral_interface_hash: str = ""
    neutral_resource_contract_hash: str = ""
    neutral_k_manifest_hash: str = ""
    neutral_e0_manifest_hash: str = ""
    neutral_web_manifest_hash: str = ""
    neutral_opportunity_contract_hash: str = ""
    neutral_challenger_policy_hash: str = ""
    neutral_scope_audit_manifest_hash: str = ""
    # New producers may attest the neutral execution contract independently
    # of the two-arm effect contract.  ``None`` is the legacy wire value: old
    # bundles fall back to ``paired_contract_audit_pass`` exactly as before.
    # Keep this extension last so legacy positional construction is unchanged.
    neutral_contract_audit_pass: Optional[bool] = None


@dataclass
class Gate1Result:
    result_validity: TriState
    astar_validity: Validity
    baseline_validity: Validity
    x: Optional[float]
    effect_mean: Optional[float]
    effect_lcb: Optional[float]
    effect_ucb: Optional[float]
    utility_pass: bool
    utility_confirmed_below: bool
    baseline_fails_p: TriState
    baseline_satisfies_p: bool
    reason: str


@dataclass
class ControlClassification:
    attempt_id: str
    artifact_hash: str
    verifier_result_hash: str
    status: AttemptStatus
    d_mean: Optional[float]
    d_lcb: Optional[float]
    d_ucb: Optional[float]
    counts_in_denominator: bool
    counts_in_n_ind: bool
    stratum: str
    scope_contract_hash: str
    prestart_contract_receipt_hash: str
    challenge_distribution_hash: str
    independent_draw_receipt_hash: str
    independent_unit_id: str
    reason: str


@dataclass
class Gate2Result:
    no_feedback_recovery: Recovery
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
    a_i: Optional[float]
    reason: str


@dataclass
class Gate3Result:
    checkpoint_scope: str
    checkpoint_hash: str
    window_hash: str
    feedback_pairs_manifest_hash: str
    design_checks_pass: bool
    stopping_rule_pass: bool
    registered_pairs_complete: bool
    all_started_pairs_disclosed: bool
    no_pair_replacements: bool
    paired_contract_audit_pass: bool
    truthful_channel_audit_pass: bool
    neutral_channel_audit_pass: bool
    started_pair_count: int
    paired_arm_contract_hash: str
    truthful_arm_contract_hash: str
    neutral_arm_contract_hash: str
    neutral_recovery_contract_hash: str
    truthful_feedback_generator_hash: str
    neutral_sham_generator_hash: str
    contract_preseal_receipt_hash: str
    contract_sealed_before_branches_pass: bool
    contract_sealed_event_index: int
    first_branch_started_event_index: int
    neutral_scope_audit_manifest_hash: str
    neutral_challenger_policy_hash: str
    neutral_scope_contract: dict
    sham_adequacy: TriState
    feedback_effect: EffectStatus
    effect_mean: Optional[float]
    effect_lcb: Optional[float]
    effect_ucb: Optional[float]
    n_pairs_started: int
    n_pairs_analyzed: int
    pair_ids_analyzed: list[str]
    pair_records: list[dict]
    pairs_unresolved: int
    pairs_infrastructure_excluded: int
    truthful_valid_rate: float
    neutral_valid_rate: float
    truthful_model_failure_rate: float
    neutral_model_failure_rate: float
    pair_infrastructure_failure_rate: float
    branch_health_pass: bool
    branch_health_reasons: list[str]
    sham_delta_null_mean: Optional[float]
    sham_delta_null_lcb: Optional[float]
    sham_delta_null_ucb: Optional[float]
    sham_n: int
    sham_all_started_pairs_disclosed: bool
    sham_no_pair_replacements: bool
    sham_started_pair_count: int
    sham_pair_records: list[dict]
    sham_development_manifest_hash: str
    sham_confirmatory_manifest_hash: str
    sham_paired_arm_contract_hash: str
    sham_reference_arm_contract_hash: str
    sham_proposed_arm_contract_hash: str
    sham_reference_null_generator_hash: str
    sham_contract_preseal_receipt_hash: str
    sham_contract_sealed_event_index: int
    sham_first_branch_started_event_index: int
    neutral_recovery: Recovery
    neutral_adequacy_pass: bool
    neutral_adequacy_reasons: list[str]
    neutral_positive_control_recall_lcb: Optional[float]
    neutral_positive_control_successes: int
    neutral_positive_control_trials: int
    neutral_adequacy_calibration_id: str
    neutral_adequacy_manifest_hash: str
    neutral_classifications: list[ControlClassification]
    neutral_n_ind: int
    neutral_hits: int
    neutral_admissible_hits: int
    neutral_unresolved: int
    neutral_p_upper: Optional[float]
    neutral_reason: str
    neutral_in_gate2_scope: bool
    lineage_empty_hit_refutes_core: bool
    reason: str
    # Omitted from legacy certificates.  See Gate3Evidence for fallback
    # semantics.
    neutral_contract_audit_pass: Optional[bool] = None


@dataclass
class Verdict:
    core: CoreVerdict
    evidence: EvidenceVerdict
    core_inconclusive_class: InconclusiveClass
    evidence_inconclusive_class: InconclusiveClass
    statement: str
    reason: str
