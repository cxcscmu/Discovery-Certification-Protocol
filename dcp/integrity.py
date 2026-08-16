"""Strict schema, provenance, and cross-gate integrity checks.

Dataclass annotations are not runtime validation.  This module therefore
rejects truthy strings, unknown enum tags, malformed nested records, and
unbound verifier results before any gate may issue a formal verdict.
"""

from __future__ import annotations

import hashlib
import json
import math
import unicodedata
from typing import Optional, Sequence

from dcp.registration import Registration
from dcp.replacements import (
    feedback_replacement_ledger,
    sham_replacement_ledger,
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
    IntegrityEvidence,
    RawAttemptOutcome,
    ShamCalibration,
    ShamPair,
    Validity,
)


def _hash(payload: object) -> str:
    encoded = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _float_tokens(values: Sequence[float]) -> list[str]:
    return [float(value).hex() for value in values]


def unit_manifest_hash(unit_ids: Sequence[str]) -> str:
    return _hash({"unit_ids": list(unit_ids)})


def artifact_results_hash(artifact: ArtifactScores) -> str:
    """Canonical digest binding an artifact to ordered private results."""
    return _hash(
        {
            "artifact_hash": artifact.artifact_hash,
            "validity": artifact.validity.value,
            "unit_ids": list(artifact.unit_ids),
            "scores": _float_tokens(artifact.per_unit),
        }
    )


def private_results_manifest_hash(
    astar: ArtifactScores, baseline: ArtifactScores, verifier_hash: str
) -> str:
    return _hash(
        {
            "verifier_hash": verifier_hash,
            "astar_results_hash": artifact_results_hash(astar),
            "baseline_results_hash": artifact_results_hash(baseline),
        }
    )


def control_result_hash(control: ControlAttempt) -> str:
    return _hash(
        {
            "attempt_id": control.attempt_id,
            "outcome": control.outcome.value,
            "validity": control.validity.value,
            "artifact_hash": control.artifact_hash,
            "unit_ids": list(control.unit_ids),
            "scores": None
            if control.per_unit is None
            else _float_tokens(control.per_unit),
            "stratum": control.stratum,
            "scope_contract_hash": control.scope_contract_hash,
            "prestart_contract_receipt_hash": control.prestart_contract_receipt_hash,
            "challenge_distribution_hash": control.challenge_distribution_hash,
            "independent_draw_receipt_hash": control.independent_draw_receipt_hash,
            "independent_unit_id": control.independent_unit_id,
            "independence_ok": control.independence_ok,
            "infrastructure_outcome_independent": control.infrastructure_outcome_independent,
        }
    )


def recovery_ledger_manifest_hash(
    controls: Sequence[ControlAttempt], gate3: Optional[Gate3Evidence] = None
) -> str:
    payload: dict[str, object] = {
        "gate2_attempt_result_hashes": [
            control_result_hash(control) for control in controls
        ]
    }
    if gate3 is not None:
        neutral_ledger = {
            "checkpoint_scope": gate3.checkpoint_scope,
            "checkpoint_hash": gate3.checkpoint_hash,
            "window_hash": gate3.window_hash,
            "paired_arm_contract_hash": gate3.paired_arm_contract_hash,
            "truthful_arm_contract_hash": gate3.truthful_arm_contract_hash,
            "neutral_arm_contract_hash": gate3.neutral_arm_contract_hash,
            "neutral_recovery_contract_hash": gate3.neutral_recovery_contract_hash,
            "truthful_feedback_generator_hash": gate3.truthful_feedback_generator_hash,
            "neutral_sham_generator_hash": gate3.neutral_sham_generator_hash,
            "contract_preseal_receipt_hash": gate3.contract_preseal_receipt_hash,
            "contract_sealed_event_index": gate3.contract_sealed_event_index,
            "first_branch_started_event_index": gate3.first_branch_started_event_index,
            "paired_contract_audit_pass": gate3.paired_contract_audit_pass,
            "truthful_channel_audit_pass": gate3.truthful_channel_audit_pass,
            "neutral_channel_audit_pass": gate3.neutral_channel_audit_pass,
            "neutral_result_hashes": [
                branch_result_hash(pair.neutral) for pair in gate3.pairs
            ],
        }
        if gate3.neutral_contract_audit_pass is not None:
            neutral_ledger["neutral_contract_audit_pass"] = (
                gate3.neutral_contract_audit_pass
            )
        payload["gate3_neutral_ledger"] = neutral_ledger
    return _hash(payload)


def branch_result_hash(branch: BranchOutcome) -> str:
    return _hash(
        {
            "branch_id": branch.branch_id,
            "outcome": branch.outcome.value,
            "validity": branch.validity.value,
            "artifact_hash": branch.artifact_hash,
            "execution_contract_hash": branch.execution_contract_hash,
            "prestart_contract_receipt_hash": branch.prestart_contract_receipt_hash,
            "utility": None if branch.utility is None else float(branch.utility).hex(),
            "unit_ids": list(branch.unit_ids),
            "scores": None
            if branch.per_unit is None
            else _float_tokens(branch.per_unit),
            "infrastructure_outcome_independent": branch.infrastructure_outcome_independent,
        }
    )


def adequacy_evidence_hash(adequacy: AdequacyEvidence) -> str:
    return _hash(
        {
            "matched_model_present": adequacy.matched_model_present,
            "materials_readable": adequacy.materials_readable,
            "opportunity_floor_met": adequacy.opportunity_floor_met,
            "health_audit_pass": adequacy.health_audit_pass,
            "positive_control_successes": adequacy.positive_control_successes,
            "positive_control_trials": adequacy.positive_control_trials,
            "calibration_id": adequacy.calibration_id,
        }
    )


def feedback_pairs_manifest_hash(pairs: Sequence[FeedbackPair]) -> str:
    replacement_aware = any(pair.replacement_of for pair in pairs)
    return _hash(
        {
            "pairs": [
                (
                    {
                        "replacement_of": pair.replacement_of,
                        "pair_id": pair.pair_id,
                        "block_id": pair.block_id,
                        "randomization_distribution_hash": pair.randomization_distribution_hash,
                        "randomization_draw_receipt_hash": pair.randomization_draw_receipt_hash,
                        "assignment_frozen": pair.assignment_frozen,
                        "independence_ok": pair.independence_ok,
                        "truthful_result_hash": branch_result_hash(pair.truthful),
                        "neutral_result_hash": branch_result_hash(pair.neutral),
                    }
                    if replacement_aware
                    else {
                    "pair_id": pair.pair_id,
                    "block_id": pair.block_id,
                    "randomization_distribution_hash": pair.randomization_distribution_hash,
                    "randomization_draw_receipt_hash": pair.randomization_draw_receipt_hash,
                    "assignment_frozen": pair.assignment_frozen,
                    "independence_ok": pair.independence_ok,
                    "truthful_result_hash": branch_result_hash(pair.truthful),
                    "neutral_result_hash": branch_result_hash(pair.neutral),
                    }
                )
                for pair in pairs
            ]
        }
    )


def sham_pairs_manifest_hash(pairs: Sequence[ShamPair]) -> str:
    replacement_aware = any(pair.replacement_of for pair in pairs)
    return _hash(
        {
            "pairs": [
                (
                    {
                        "replacement_of": pair.replacement_of,
                        "pair_id": pair.pair_id,
                        "block_id": pair.block_id,
                        "randomization_distribution_hash": pair.randomization_distribution_hash,
                        "randomization_draw_receipt_hash": pair.randomization_draw_receipt_hash,
                        "assignment_frozen": pair.assignment_frozen,
                        "independence_ok": pair.independence_ok,
                        "reference_result_hash": branch_result_hash(pair.reference_null),
                        "proposed_result_hash": branch_result_hash(pair.proposed_sham),
                    }
                    if replacement_aware
                    else {
                    "pair_id": pair.pair_id,
                    "block_id": pair.block_id,
                    "randomization_distribution_hash": pair.randomization_distribution_hash,
                    "randomization_draw_receipt_hash": pair.randomization_draw_receipt_hash,
                    "assignment_frozen": pair.assignment_frozen,
                    "independence_ok": pair.independence_ok,
                    "reference_result_hash": branch_result_hash(pair.reference_null),
                    "proposed_result_hash": branch_result_hash(pair.proposed_sham),
                    }
                )
                for pair in pairs
            ]
        }
    )


def gate3_scope_manifest_hash(gate3: Gate3Evidence, selection_rule_hash: str) -> str:
    payload = {
        "selection_rule_hash": selection_rule_hash,
        "checkpoint_scope": gate3.checkpoint_scope,
        "checkpoint_hash": gate3.checkpoint_hash,
        "window_hash": gate3.window_hash,
        "paired_arm_contract_hash": gate3.paired_arm_contract_hash,
        "truthful_arm_contract_hash": gate3.truthful_arm_contract_hash,
        "neutral_arm_contract_hash": gate3.neutral_arm_contract_hash,
        "neutral_recovery_contract_hash": gate3.neutral_recovery_contract_hash,
        "truthful_feedback_generator_hash": gate3.truthful_feedback_generator_hash,
        "neutral_sham_generator_hash": gate3.neutral_sham_generator_hash,
        "contract_preseal_receipt_hash": gate3.contract_preseal_receipt_hash,
        "contract_sealed_before_branches_pass": gate3.contract_sealed_before_branches_pass,
        "contract_sealed_event_index": gate3.contract_sealed_event_index,
        "first_branch_started_event_index": gate3.first_branch_started_event_index,
        "neutral_model_id": gate3.neutral_model_id,
        "neutral_interface_hash": gate3.neutral_interface_hash,
        "neutral_resource_contract_hash": gate3.neutral_resource_contract_hash,
        "neutral_k_manifest_hash": gate3.neutral_k_manifest_hash,
        "neutral_e0_manifest_hash": gate3.neutral_e0_manifest_hash,
        "neutral_web_manifest_hash": gate3.neutral_web_manifest_hash,
        "neutral_opportunity_contract_hash": gate3.neutral_opportunity_contract_hash,
        "neutral_challenger_policy_hash": gate3.neutral_challenger_policy_hash,
        "sham_contract": {
            "paired_arm_contract_hash": gate3.sham.paired_arm_contract_hash,
            "reference_arm_contract_hash": gate3.sham.reference_arm_contract_hash,
            "proposed_arm_contract_hash": gate3.sham.proposed_arm_contract_hash,
            "reference_null_generator_hash": gate3.sham.reference_null_generator_hash,
            "operator_hash": gate3.sham.operator_hash,
            "contract_preseal_receipt_hash": gate3.sham.contract_preseal_receipt_hash,
            "contract_sealed_before_branches_pass": gate3.sham.contract_sealed_before_branches_pass,
            "contract_sealed_event_index": gate3.sham.contract_sealed_event_index,
            "first_branch_started_event_index": gate3.sham.first_branch_started_event_index,
        },
    }
    if gate3.neutral_contract_audit_pass is not None:
        payload["neutral_contract_audit_pass"] = gate3.neutral_contract_audit_pass
    return _hash(payload)


def gate3_neutral_scope_manifest_hash(
    gate3: Gate3Evidence, selection_rule_hash: str
) -> str:
    """Bind only the scope needed to judge a neutral recovery witness.

    Truthful-arm and sham-calibration fields are intentionally excluded.  A
    defect in either may invalidate the feedback-effect estimate, but it must
    not erase an otherwise valid neutral artifact that reaches ``P``.
    """
    payload = {
        "selection_rule_hash": selection_rule_hash,
        "checkpoint_scope": gate3.checkpoint_scope,
        "checkpoint_hash": gate3.checkpoint_hash,
        "window_hash": gate3.window_hash,
        "paired_arm_contract_hash": gate3.paired_arm_contract_hash,
        "neutral_arm_contract_hash": gate3.neutral_arm_contract_hash,
        "neutral_recovery_contract_hash": gate3.neutral_recovery_contract_hash,
        "neutral_sham_generator_hash": gate3.neutral_sham_generator_hash,
        "contract_preseal_receipt_hash": gate3.contract_preseal_receipt_hash,
        "contract_sealed_before_branches_pass": gate3.contract_sealed_before_branches_pass,
        "contract_sealed_event_index": gate3.contract_sealed_event_index,
        "first_branch_started_event_index": gate3.first_branch_started_event_index,
        "neutral_channel_audit_pass": gate3.neutral_channel_audit_pass,
        "neutral_model_id": gate3.neutral_model_id,
        "neutral_interface_hash": gate3.neutral_interface_hash,
        "neutral_resource_contract_hash": gate3.neutral_resource_contract_hash,
        "neutral_k_manifest_hash": gate3.neutral_k_manifest_hash,
        "neutral_e0_manifest_hash": gate3.neutral_e0_manifest_hash,
        "neutral_web_manifest_hash": gate3.neutral_web_manifest_hash,
        "neutral_opportunity_contract_hash": gate3.neutral_opportunity_contract_hash,
        "neutral_challenger_policy_hash": gate3.neutral_challenger_policy_hash,
    }
    if gate3.neutral_contract_audit_pass is None:
        # Preserve the exact legacy hash payload.  For new records the neutral
        # witness hash is deliberately independent of a truthful/paired audit.
        payload["paired_contract_audit_pass"] = gate3.paired_contract_audit_pass
    else:
        payload["neutral_contract_audit_pass"] = gate3.neutral_contract_audit_pass
    return _hash(payload)


def gate3_neutral_recovery_ledger_manifest_hash(gate3: Gate3Evidence) -> str:
    """Bind the neutral candidates without depending on truthful/sham data."""
    replacement_aware = any(pair.replacement_of for pair in gate3.pairs)
    return _hash(
        {
            "neutral_pairs": [
                (
                    {
                        "replacement_of": pair.replacement_of,
                        "pair_id": pair.pair_id,
                        "block_id": pair.block_id,
                        "randomization_distribution_hash": pair.randomization_distribution_hash,
                        "randomization_draw_receipt_hash": pair.randomization_draw_receipt_hash,
                        "assignment_frozen": pair.assignment_frozen,
                        "neutral_result_hash": branch_result_hash(pair.neutral),
                    }
                    if replacement_aware
                    else {
                    "pair_id": pair.pair_id,
                    "block_id": pair.block_id,
                    "randomization_distribution_hash": pair.randomization_distribution_hash,
                    "randomization_draw_receipt_hash": pair.randomization_draw_receipt_hash,
                    "assignment_frozen": pair.assignment_frozen,
                    "neutral_result_hash": branch_result_hash(pair.neutral),
                    }
                )
                for pair in gate3.pairs
            ]
        }
    )


def _explicit(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value.strip())
        and "unspecified" not in value.lower()
    )


def _canonical_id(value: object) -> bool:
    return bool(
        _explicit(value)
        and value == value.strip()
        and unicodedata.normalize("NFC", value) == value
        and not any(
            char.isspace() or unicodedata.category(char).startswith("C")
            for char in value
        )
    )


def _finite_number(value: object) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


def _sequence(value: object) -> bool:
    return isinstance(value, (list, tuple))


def _bool(value: object, label: str, errors: list[str]) -> None:
    if type(value) is not bool:
        errors.append(f"{label} must be a boolean")


def _required_true(value: object, label: str, errors: list[str]) -> None:
    if type(value) is not bool:
        errors.append(f"{label} must be a boolean")
    elif value is not True:
        errors.append(f"{label} not attested")


def _validate_artifact(
    artifact: object, label: str, errors: list[str]
) -> Optional[ArtifactScores]:
    if not isinstance(artifact, ArtifactScores):
        errors.append(f"{label} must be an ArtifactScores record")
        return None
    if not isinstance(artifact.validity, Validity):
        errors.append(f"{label}.validity has an unknown enum tag")
    if not _explicit(artifact.name):
        errors.append(f"{label}.name missing")
    if not _explicit(artifact.artifact_hash):
        errors.append(f"{label}.artifact_hash missing")
    if not _sequence(artifact.unit_ids) or not _sequence(artifact.per_unit):
        errors.append(f"{label} unit_ids/per_unit must be JSON arrays")
        return artifact
    ids = list(artifact.unit_ids)
    scores = list(artifact.per_unit)
    if not ids or len(ids) != len(scores):
        errors.append(f"{label} private-unit ids/scores are empty or misaligned")
    elif len(set(ids)) != len(ids) or any(not _canonical_id(x) for x in ids):
        errors.append(f"{label} private-unit ids are missing or duplicated")
    if not scores or not all(_finite_number(x) for x in scores):
        errors.append(f"{label} scores must be finite JSON numbers")
    elif not all(0.0 <= float(x) <= 1.0 for x in scores):
        errors.append(f"{label} normalized scores must be in [0,1]")
    return artifact


def _validate_adequacy(
    adequacy: object, label: str, errors: list[str]
) -> Optional[AdequacyEvidence]:
    if not isinstance(adequacy, AdequacyEvidence):
        errors.append(f"{label} must be an AdequacyEvidence record")
        return None
    for name in (
        "matched_model_present",
        "materials_readable",
        "opportunity_floor_met",
        "health_audit_pass",
    ):
        _bool(getattr(adequacy, name), f"{label}.{name}", errors)
    h, n = adequacy.positive_control_successes, adequacy.positive_control_trials
    if (
        not isinstance(h, int)
        or isinstance(h, bool)
        or not isinstance(n, int)
        or isinstance(n, bool)
        or n < 1
        or not (0 <= h <= n)
    ):
        errors.append(f"{label} positive-control h/n are malformed")
    if not _explicit(adequacy.calibration_id):
        errors.append(f"{label}.calibration_id missing")
    if not _explicit(adequacy.checks_manifest_hash):
        errors.append(f"{label}.checks_manifest_hash missing")
    else:
        try:
            if adequacy_evidence_hash(adequacy) != adequacy.checks_manifest_hash:
                errors.append(f"{label}.checks_manifest_hash mismatch")
        except (TypeError, ValueError, AttributeError, OverflowError):
            errors.append(f"{label} adequacy hash could not be recomputed")
    return adequacy


def _validate_control(
    control: object, label: str, errors: list[str]
) -> Optional[ControlAttempt]:
    if not isinstance(control, ControlAttempt):
        errors.append(f"{label} must be a ControlAttempt record")
        return None
    if not isinstance(control.outcome, RawAttemptOutcome):
        errors.append(f"{label}.outcome has an unknown enum tag")
    if not isinstance(control.validity, Validity):
        errors.append(f"{label}.validity has an unknown enum tag")
    for name in ("independence_ok", "infrastructure_outcome_independent"):
        _bool(getattr(control, name), f"{label}.{name}", errors)
    for name in ("attempt_id", "stratum"):
        if not _canonical_id(getattr(control, name)):
            errors.append(f"{label}.{name} missing or non-canonical")
    if not _explicit(control.scope_contract_hash):
        errors.append(f"{label}.scope_contract_hash missing")
    if not _canonical_id(control.prestart_contract_receipt_hash):
        errors.append(f"{label}.prestart_contract_receipt_hash missing")
    if not _explicit(control.challenge_distribution_hash):
        errors.append(f"{label}.challenge_distribution_hash missing")
    if not _canonical_id(control.independent_draw_receipt_hash):
        errors.append(f"{label}.independent_draw_receipt_hash missing")
    if control.independence_ok is True and not _canonical_id(
        control.independent_unit_id
    ):
        errors.append(f"{label}.independent_unit_id missing")
    elif not isinstance(control.independent_unit_id, str):
        errors.append(f"{label}.independent_unit_id must be a string")
    if control.per_unit is not None:
        if not _sequence(control.per_unit) or not all(
            _finite_number(x) for x in control.per_unit
        ):
            errors.append(f"{label}.per_unit must contain finite JSON numbers")
        elif not all(0.0 <= float(x) <= 1.0 for x in control.per_unit):
            errors.append(f"{label}.per_unit normalized scores must be in [0,1]")
    if not _sequence(control.unit_ids) or any(
        not _canonical_id(x) for x in control.unit_ids
    ):
        errors.append(f"{label}.unit_ids must be canonical whitespace-free string ids")

    has_scores = control.per_unit is not None
    has_units = bool(control.unit_ids)
    has_artifact = _explicit(control.artifact_hash)
    if control.outcome == RawAttemptOutcome.ARTIFACT:
        if not has_artifact:
            errors.append(f"{label}.artifact_hash missing for artifact outcome")
    elif control.outcome == RawAttemptOutcome.MODEL_FAILURE:
        if (
            has_scores
            or has_units
            or has_artifact
            or control.validity == Validity.VALID
        ):
            errors.append(f"{label} model failure conflicts with artifact data")
        if control.infrastructure_outcome_independent is not False:
            errors.append(f"{label} model failure has an infrastructure-only flag")
    elif control.outcome == RawAttemptOutcome.EXECUTION_CONTRACT_VIOLATION:
        if (
            has_scores
            or has_units
            or has_artifact
            or control.validity == Validity.VALID
        ):
            errors.append(
                f"{label} execution-contract violation conflicts with artifact data"
            )
        if control.infrastructure_outcome_independent is not False:
            errors.append(
                f"{label} execution-contract violation has an infrastructure-only flag"
            )
    elif control.outcome == RawAttemptOutcome.INFRASTRUCTURE_INVALID:
        if (
            has_scores
            or has_units
            or has_artifact
            or control.validity != Validity.UNRESOLVED
        ):
            errors.append(
                f"{label} infrastructure failure conflicts with artifact data"
            )
    elif control.outcome == RawAttemptOutcome.UNRESOLVED:
        if (
            has_scores
            or has_units
            or has_artifact
            or control.validity != Validity.UNRESOLVED
            or control.infrastructure_outcome_independent is not False
        ):
            errors.append(f"{label} unresolved outcome contains contradictory data")
    return control


def validate_integrity(
    reg: Registration,
    integrity: Optional[IntegrityEvidence],
    gate1: Gate1Evidence,
    gate2: Gate2Evidence,
) -> list[str]:
    """Validate the Core schema and invariants before running Gates 1/2."""
    errors: list[str] = []
    if not isinstance(gate1, Gate1Evidence):
        return ["gate1 evidence must be a Gate1Evidence record"]
    if not isinstance(gate2, Gate2Evidence):
        return ["gate2 evidence must be a Gate2Evidence record"]
    if not isinstance(integrity, IntegrityEvidence):
        return ["integrity evidence missing or malformed"]

    for name in (
        "registration_frozen",
        "claim_frozen",
        "provenance_pass",
        "iterative_lineage_eligible",
        "lineage_dataflow_audit_pass",
        "challenger_contract_pass",
        "private_isolation_pass",
        "symmetric_verifier_pass",
        "inference_assumptions_pass",
        "familywise_budget_audit_pass",
        "recovery_ledger_complete",
    ):
        _required_true(getattr(integrity, name), name, errors)
    _bool(integrity.web_access_used, "web_access_used", errors)

    required_hashes = (
        "astar_hash",
        "baseline_hash",
        "verifier_hash",
        "astar_results_hash",
        "baseline_results_hash",
        "private_unit_manifest_hash",
        "private_results_manifest_hash",
        "p_hash",
        "resource_contract_hash",
        "selection_rule_hash",
        "k_manifest_hash",
        "e0_manifest_hash",
        "lineage_manifest_hash",
        "observed_web_manifest_hash",
        "challenger_policy_hash",
        "opportunity_contract_hash",
        "recovery_ledger_manifest_hash",
        "gate2_recovery_ledger_manifest_hash",
        "claim_family_manifest_hash",
        "alpha_ledger_receipt_hash",
        "audit_slot_registry_entry_hash",
    )
    for name in required_hashes:
        if not _explicit(getattr(integrity, name)):
            errors.append(f"{name} missing")
    if (
        _explicit(integrity.alpha_ledger_receipt_hash)
        and integrity.alpha_ledger_receipt_hash
        != reg.audit_slot_reservation_receipt_hash
    ):
        errors.append("audit-slot reservation receipt differs from frozen registration")

    allowed_human = {"none", "operational", "fixed_scientific", "adaptive_scientific"}
    allowed_subject = {
        "autonomous_agent",
        "agent_given_fixed_human_input",
        "human_agent_joint",
    }
    if integrity.human_assistance not in allowed_human:
        errors.append("human_assistance is missing or invalid")
    if integrity.attribution_subject not in allowed_subject:
        errors.append("attribution_subject is missing or invalid")
    if (
        integrity.human_assistance == "adaptive_scientific"
        and integrity.attribution_subject != "human_agent_joint"
    ):
        errors.append(
            "adaptive scientific assistance requires human_agent_joint attribution"
        )
    if (
        integrity.attribution_subject == "autonomous_agent"
        and integrity.human_assistance not in {"none", "operational"}
    ):
        errors.append(
            "autonomous attribution conflicts with scientific human assistance"
        )

    valid_web_scopes = {
        "not_used",
        "observed_bytes_frozen",
        "observed_request_response_frozen",
    }
    if integrity.web_replay_scope not in valid_web_scopes:
        errors.append("web_replay_scope is missing or invalid")
    if integrity.web_access_used is True and integrity.web_replay_scope == "not_used":
        errors.append("Web was used but no frozen replay scope was supplied")
    if integrity.web_access_used is False and integrity.web_replay_scope != "not_used":
        errors.append("Web replay scope conflicts with web_access_used=false")

    astar = _validate_artifact(gate1.astar, "A*", errors)
    baseline = _validate_artifact(gate1.baseline, "baseline", errors)
    if astar is not None and baseline is not None:
        if astar.artifact_hash != integrity.astar_hash:
            errors.append("A* hash does not match frozen integrity envelope")
        if baseline.artifact_hash != integrity.baseline_hash:
            errors.append("baseline hash does not match frozen integrity envelope")
        if tuple(baseline.unit_ids) != tuple(astar.unit_ids):
            errors.append("baseline and A* private-unit manifests differ")
        try:
            if (
                unit_manifest_hash(astar.unit_ids)
                != integrity.private_unit_manifest_hash
            ):
                errors.append("private-unit manifest hash mismatch")
            astar_hash = artifact_results_hash(astar)
            baseline_hash = artifact_results_hash(baseline)
            if astar_hash != integrity.astar_results_hash:
                errors.append("A* verifier-result hash mismatch")
            if baseline_hash != integrity.baseline_results_hash:
                errors.append("baseline verifier-result hash mismatch")
            if (
                private_results_manifest_hash(astar, baseline, integrity.verifier_hash)
                != integrity.private_results_manifest_hash
            ):
                errors.append("private-results manifest hash mismatch")
        except (TypeError, ValueError, AttributeError, OverflowError):
            errors.append("private-result hashes could not be recomputed")

    _validate_adequacy(gate2.adequacy, "gate2.adequacy", errors)
    if not _sequence(gate2.controls):
        errors.append("gate2.controls must be a JSON array")
        controls: list[ControlAttempt] = []
    else:
        controls = []
        for index, item in enumerate(gate2.controls):
            parsed = _validate_control(item, f"gate2.controls[{index}]", errors)
            if parsed is not None:
                controls.append(parsed)
    attempt_ids = [a.attempt_id for a in controls]
    if len(set(attempt_ids)) != len(attempt_ids):
        errors.append("control attempt ids are duplicated")
    receipt_ids = [a.prestart_contract_receipt_hash for a in controls]
    if len(set(receipt_ids)) != len(receipt_ids):
        errors.append("control prestart contract receipts are duplicated")
    unit_to_draw: dict[str, str] = {}
    draw_to_unit: dict[str, str] = {}
    for attempt in controls:
        unit = attempt.independent_unit_id
        draw = attempt.independent_draw_receipt_hash
        if unit in unit_to_draw and unit_to_draw[unit] != draw:
            errors.append("one independent episode maps to multiple draw receipts")
        if draw in draw_to_unit and draw_to_unit[draw] != unit:
            errors.append("one draw receipt is reused across independent episodes")
        unit_to_draw[unit] = draw
        draw_to_unit[draw] = unit
    if (
        isinstance(gate2.adequacy, AdequacyEvidence)
        and gate2.adequacy.matched_model_present is False
        and any(
            a.scope_contract_hash == reg.gate2_control_contract_hash for a in controls
        )
    ):
        errors.append(
            "gate2 adequacy contradicts candidate-level matched contract receipts"
        )
    if isinstance(reg.m_max, int) and len(controls) > reg.m_max:
        errors.append(
            f"main candidate slots {len(controls)} exceed registered M_max={reg.m_max}"
        )
    try:
        if (
            recovery_ledger_manifest_hash(controls)
            != integrity.gate2_recovery_ledger_manifest_hash
        ):
            errors.append("Gate-2 recovery-ledger manifest hash mismatch")
    except (TypeError, ValueError, AttributeError, OverflowError):
        errors.append("recovery-ledger manifest hash could not be recomputed")
    return errors


def validate_gate2_hit_integrity(
    reg: Registration,
    integrity: Optional[IntegrityEvidence],
    gate1: Gate1Evidence,
    gate2: Gate2Evidence,
) -> tuple[list[str], list[int]]:
    """Validate positive Gate-2 witnesses without requiring a clean full ledger.

    A concrete recovery is a monotone counterexample.  Malformed or missing
    records for other challenger slots may block a zero-hit bound, but must not
    erase a separately complete candidate that reaches ``P``.  The returned
    indices identify candidate-local envelopes that are safe to score.  Score
    classification remains the responsibility of Gate 2.
    """

    errors: list[str] = []
    if not isinstance(gate1, Gate1Evidence):
        return ["gate1 evidence must be a Gate1Evidence record"], []
    if not isinstance(gate2, Gate2Evidence):
        return ["gate2 evidence must be a Gate2Evidence record"], []
    if not isinstance(integrity, IntegrityEvidence):
        return ["integrity evidence missing or malformed"], []
    if (
        not isinstance(gate2.adequacy, AdequacyEvidence)
        or gate2.adequacy.matched_model_present is not True
    ):
        return [
            "Gate-2 recovery witness has no matched model/interface attestation"
        ], []

    # These attestations bind the claim, target, verifier, and prospective
    # score-test budget.  Whole-ledger and all-candidate checks are
    # intentionally absent because they are not prerequisites for one local
    # positive witness.
    for name in (
        "registration_frozen",
        "claim_frozen",
        "iterative_lineage_eligible",
        "lineage_dataflow_audit_pass",
        "symmetric_verifier_pass",
        "familywise_budget_audit_pass",
    ):
        _required_true(getattr(integrity, name), name, errors)

    required_hashes = (
        "astar_hash",
        "baseline_hash",
        "verifier_hash",
        "astar_results_hash",
        "baseline_results_hash",
        "private_unit_manifest_hash",
        "private_results_manifest_hash",
        "p_hash",
        "resource_contract_hash",
        "selection_rule_hash",
        "k_manifest_hash",
        "e0_manifest_hash",
        "lineage_manifest_hash",
        "observed_web_manifest_hash",
        "challenger_policy_hash",
        "opportunity_contract_hash",
        "gate2_recovery_ledger_manifest_hash",
        "claim_family_manifest_hash",
        "alpha_ledger_receipt_hash",
        "audit_slot_registry_entry_hash",
    )
    for name in required_hashes:
        if not _explicit(getattr(integrity, name)):
            errors.append(f"Gate-2 recovery witness {name} missing")
    if (
        _explicit(integrity.alpha_ledger_receipt_hash)
        and integrity.alpha_ledger_receipt_hash
        != reg.audit_slot_reservation_receipt_hash
    ):
        errors.append(
            "Gate-2 recovery witness audit-slot receipt differs from registration"
        )

    _bool(integrity.web_access_used, "web_access_used", errors)
    if integrity.web_access_used is True:
        if integrity.web_replay_scope not in {
            "observed_bytes_frozen",
            "observed_request_response_frozen",
        }:
            errors.append("Gate-2 recovery witness has no frozen Web replay scope")
    elif integrity.web_access_used is False:
        if integrity.web_replay_scope != "not_used":
            errors.append("Gate-2 recovery witness Web scope is inconsistent")

    astar = _validate_artifact(gate1.astar, "A*", errors)
    baseline = _validate_artifact(gate1.baseline, "baseline", errors)
    if astar is not None and baseline is not None:
        if astar.artifact_hash != integrity.astar_hash:
            errors.append("Gate-2 recovery witness A* hash mismatch")
        if baseline.artifact_hash != integrity.baseline_hash:
            errors.append("Gate-2 recovery witness baseline hash mismatch")
        if tuple(baseline.unit_ids) != tuple(astar.unit_ids):
            errors.append("Gate-2 recovery witness target manifests differ")
        try:
            if unit_manifest_hash(astar.unit_ids) != integrity.private_unit_manifest_hash:
                errors.append("Gate-2 recovery witness private-unit hash mismatch")
            if artifact_results_hash(astar) != integrity.astar_results_hash:
                errors.append("Gate-2 recovery witness A* result hash mismatch")
            if artifact_results_hash(baseline) != integrity.baseline_results_hash:
                errors.append("Gate-2 recovery witness baseline result hash mismatch")
            if (
                private_results_manifest_hash(
                    astar, baseline, integrity.verifier_hash
                )
                != integrity.private_results_manifest_hash
            ):
                errors.append("Gate-2 recovery witness result manifest mismatch")
        except (TypeError, ValueError, AttributeError, OverflowError):
            errors.append("Gate-2 recovery witness target hashes could not be recomputed")

    if errors:
        return errors, []
    if not _sequence(gate2.controls):
        return ["gate2.controls must be a JSON array"], []
    try:
        if (
            recovery_ledger_manifest_hash(gate2.controls)
            != integrity.gate2_recovery_ledger_manifest_hash
        ):
            return [
                "Gate-2 recovery witness ledger is not bound by integrity"
            ], []
    except (TypeError, ValueError, AttributeError, OverflowError):
        return ["Gate-2 recovery witness ledger hash could not be recomputed"], []
    if isinstance(reg.m_max, int) and len(gate2.controls) > reg.m_max:
        return [
            "Gate-2 recovery witness ledger exceeds the registered candidate cap"
        ], []

    candidate_indices: list[int] = []
    attempt_id_counts: dict[str, int] = {}
    prestart_counts: dict[str, int] = {}
    draw_counts: dict[str, int] = {}
    for item in gate2.controls:
        if not isinstance(item, ControlAttempt):
            continue
        attempt_id_counts[item.attempt_id] = attempt_id_counts.get(item.attempt_id, 0) + 1
        prestart_counts[item.prestart_contract_receipt_hash] = (
            prestart_counts.get(item.prestart_contract_receipt_hash, 0) + 1
        )
        draw_counts[item.independent_draw_receipt_hash] = (
            draw_counts.get(item.independent_draw_receipt_hash, 0) + 1
        )
    for index, item in enumerate(gate2.controls):
        # Non-artifacts and invalid artifacts cannot be positive witnesses and
        # therefore do not need a local witness envelope.
        if not isinstance(item, ControlAttempt):
            continue
        if (
            item.outcome != RawAttemptOutcome.ARTIFACT
            or item.validity != Validity.VALID
            or item.per_unit is None
        ):
            continue
        local: list[str] = []
        control = _validate_control(item, f"gate2.controls[{index}]", local)
        if control is None:
            continue
        if attempt_id_counts.get(control.attempt_id, 0) != 1:
            local.append("candidate-local attempt id is duplicated")
        if prestart_counts.get(control.prestart_contract_receipt_hash, 0) != 1:
            local.append("candidate-local prestart receipt is duplicated")
        if draw_counts.get(control.independent_draw_receipt_hash, 0) != 1:
            local.append("candidate-local draw receipt is duplicated")
        if control.stratum != reg.recovery_stratum:
            local.append("candidate-local stratum differs from registration")
        if control.scope_contract_hash != reg.gate2_control_contract_hash:
            local.append("candidate-local execution contract differs from registration")
        if control.challenge_distribution_hash != reg.challenge_distribution_hash:
            local.append("candidate-local draw distribution differs from registration")
        if tuple(control.unit_ids) != tuple(gate1.astar.unit_ids):
            local.append("candidate-local private-unit manifest differs from A*")
        if not local:
            candidate_indices.append(index)
    return [], candidate_indices


def _validate_branch(
    branch: object,
    label: str,
    errors: list[str],
    *,
    require_private_scores: bool,
    expected_unit_manifest_hash: str = "",
    expected_execution_contract_hash: str = "",
) -> Optional[BranchOutcome]:
    if not isinstance(branch, BranchOutcome):
        errors.append(f"{label} must be a BranchOutcome record")
        return None
    if not isinstance(branch.outcome, RawAttemptOutcome):
        errors.append(f"{label}.outcome has an unknown enum tag")
    if not isinstance(branch.validity, Validity):
        errors.append(f"{label}.validity has an unknown enum tag")
    _bool(
        branch.infrastructure_outcome_independent,
        f"{label}.infrastructure_outcome_independent",
        errors,
    )
    if not _canonical_id(branch.branch_id):
        errors.append(f"{label}.branch_id missing or non-canonical")
    if not _explicit(branch.execution_contract_hash):
        errors.append(f"{label}.execution_contract_hash missing")
    elif (
        expected_execution_contract_hash
        and branch.execution_contract_hash != expected_execution_contract_hash
    ):
        errors.append(f"{label}.execution_contract_hash differs from registration")
    if not _canonical_id(branch.prestart_contract_receipt_hash):
        errors.append(f"{label}.prestart_contract_receipt_hash missing")
    if branch.utility is not None and not _finite_number(branch.utility):
        errors.append(f"{label}.utility must be a finite JSON number or null")
    if not _sequence(branch.unit_ids):
        errors.append(f"{label}.unit_ids must be a JSON string array")
    elif any(not _canonical_id(x) for x in branch.unit_ids):
        errors.append(f"{label}.unit_ids contains a non-canonical id")
    if branch.per_unit is not None and (
        not _sequence(branch.per_unit)
        or not all(_finite_number(x) for x in branch.per_unit)
    ):
        errors.append(f"{label}.per_unit must contain finite JSON numbers")

    if not _explicit(branch.verifier_result_hash):
        errors.append(f"{label}.verifier_result_hash missing")
    if branch.outcome == RawAttemptOutcome.ARTIFACT:
        if not _explicit(branch.artifact_hash):
            errors.append(f"{label}.artifact_hash missing for artifact outcome")
        if require_private_scores and (branch.per_unit is None or not branch.unit_ids):
            errors.append(f"{label} lacks private verifier scores")
        elif require_private_scores and branch.per_unit is not None:
            if len(branch.per_unit) != len(branch.unit_ids):
                errors.append(f"{label} private-unit ids/scores are misaligned")
            elif not all(0.0 <= float(x) <= 1.0 for x in branch.per_unit):
                errors.append(f"{label} normalized private scores must be in [0,1]")
            elif len(set(branch.unit_ids)) != len(branch.unit_ids) or any(
                not _canonical_id(x) for x in branch.unit_ids
            ):
                errors.append(f"{label} private-unit ids are missing or duplicated")
            elif (
                expected_unit_manifest_hash
                and unit_manifest_hash(branch.unit_ids) != expected_unit_manifest_hash
            ):
                errors.append(f"{label} private-unit manifest mismatch")
    else:
        has_scores = branch.per_unit is not None
        has_units = bool(branch.unit_ids)
        has_artifact = _explicit(branch.artifact_hash)
        if branch.outcome == RawAttemptOutcome.MODEL_FAILURE:
            if (
                branch.utility is not None
                or has_scores
                or has_units
                or has_artifact
                or branch.validity == Validity.VALID
            ):
                errors.append(f"{label} model failure conflicts with artifact data")
            if branch.infrastructure_outcome_independent is not False:
                errors.append(f"{label} model failure has an infrastructure-only flag")
        elif branch.outcome == RawAttemptOutcome.EXECUTION_CONTRACT_VIOLATION:
            if (
                branch.utility is not None
                or has_scores
                or has_units
                or has_artifact
                or branch.validity == Validity.VALID
            ):
                errors.append(
                    f"{label} execution-contract violation conflicts with artifact data"
                )
            if branch.infrastructure_outcome_independent is not False:
                errors.append(
                    f"{label} execution-contract violation has an infrastructure-only flag"
                )
        elif branch.outcome == RawAttemptOutcome.INFRASTRUCTURE_INVALID:
            if (
                branch.utility is not None
                or has_scores
                or has_units
                or has_artifact
                or branch.validity != Validity.UNRESOLVED
            ):
                errors.append(
                    f"{label} infrastructure failure conflicts with artifact data"
                )
        elif branch.outcome == RawAttemptOutcome.UNRESOLVED and (
            branch.utility is not None
            or has_scores
            or has_units
            or has_artifact
            or branch.validity != Validity.UNRESOLVED
            or branch.infrastructure_outcome_independent is not False
        ):
            errors.append(f"{label} unresolved outcome contains contradictory data")
    try:
        if _explicit(branch.verifier_result_hash) and (
            branch_result_hash(branch) != branch.verifier_result_hash
        ):
            errors.append(f"{label}.verifier_result_hash mismatch")
    except (TypeError, ValueError, AttributeError, OverflowError):
        errors.append(f"{label} verifier-result hash could not be recomputed")
    return branch


def _validate_pair_common(
    pair: object,
    label: str,
    errors: list[str],
    *,
    expected_distribution_hash: str,
) -> None:
    if not _canonical_id(getattr(pair, "pair_id", None)):
        errors.append(f"{label}.pair_id missing or non-canonical")
    if not _canonical_id(getattr(pair, "block_id", None)):
        errors.append(f"{label}.block_id missing or non-canonical")
    if not _explicit(getattr(pair, "randomization_distribution_hash", None)):
        errors.append(f"{label}.randomization_distribution_hash missing")
    elif pair.randomization_distribution_hash != expected_distribution_hash:
        errors.append(
            f"{label}.randomization_distribution_hash differs from registration"
        )
    if not _canonical_id(getattr(pair, "randomization_draw_receipt_hash", None)):
        errors.append(f"{label}.randomization_draw_receipt_hash missing")
    replacement_of = getattr(pair, "replacement_of", None)
    if not isinstance(replacement_of, str) or (
        replacement_of and not _canonical_id(replacement_of)
    ):
        errors.append(f"{label}.replacement_of is malformed")
    _bool(
        getattr(pair, "assignment_frozen", None), f"{label}.assignment_frozen", errors
    )
    _bool(getattr(pair, "independence_ok", None), f"{label}.independence_ok", errors)


def paired_contract_matches(
    reg: Registration, integrity: IntegrityEvidence, gate3: Gate3Evidence
) -> bool:
    return bool(
        gate3.checkpoint_scope == reg.gate3_checkpoint_scope
        and reg.gate3_checkpoint_selection_rule_hash == integrity.selection_rule_hash
        and gate3.paired_contract_audit_pass is True
        and gate3.truthful_channel_audit_pass is True
        and gate3.neutral_channel_audit_pass is True
        and gate3.paired_arm_contract_hash == reg.gate3_paired_arm_contract_hash
        and gate3.truthful_arm_contract_hash == reg.gate3_truthful_arm_contract_hash
        and gate3.neutral_arm_contract_hash == reg.gate3_neutral_arm_contract_hash
        and gate3.neutral_recovery_contract_hash
        == reg.gate3_neutral_recovery_contract_hash
        and gate3.truthful_feedback_generator_hash
        == reg.truthful_feedback_generator_hash
        and gate3.neutral_sham_generator_hash == reg.neutral_sham_generator_hash
        and gate3.contract_sealed_before_branches_pass is True
        and gate3.contract_preseal_receipt_hash
        == integrity.gate3_contract_preseal_receipt_hash
        and isinstance(gate3.contract_sealed_event_index, int)
        and not isinstance(gate3.contract_sealed_event_index, bool)
        and isinstance(gate3.first_branch_started_event_index, int)
        and not isinstance(gate3.first_branch_started_event_index, bool)
        and gate3.contract_sealed_event_index < gate3.first_branch_started_event_index
        and gate3.neutral_model_id == reg.model_id
        and gate3.neutral_interface_hash == reg.interface_hash
        and gate3.neutral_resource_contract_hash == reg.gate3_resource_contract_hash
        and gate3.neutral_k_manifest_hash == integrity.k_manifest_hash
        and gate3.neutral_e0_manifest_hash == integrity.e0_manifest_hash
        and gate3.neutral_web_manifest_hash == integrity.observed_web_manifest_hash
        and gate3.neutral_opportunity_contract_hash
        == reg.gate3_opportunity_contract_hash
        and gate3.neutral_challenger_policy_hash == reg.gate3_branch_policy_hash
    )


def _neutral_contract_audit_pass(gate3: Gate3Evidence) -> object:
    """Return the explicit neutral audit, or the exact legacy fallback.

    Bundles written before the neutral-specific attestation existed do not
    carry the field.  For those records, the historical paired audit remains
    authoritative so replay and saved verdicts do not change.
    """

    if gate3.neutral_contract_audit_pass is None:
        return gate3.paired_contract_audit_pass
    return gate3.neutral_contract_audit_pass


def neutral_contract_matches(
    reg: Registration, integrity: IntegrityEvidence, gate3: Gate3Evidence
) -> bool:
    """Check the contract needed by a positive neutral recovery witness.

    This deliberately does not inspect the truthful arm or the sham
    calibration.  Those are required for the causal effect estimate, not for
    the simpler fact that a registered neutral branch produced a valid hit.
    """
    return bool(
        gate3.checkpoint_scope == reg.gate3_checkpoint_scope
        and reg.gate3_checkpoint_selection_rule_hash == integrity.selection_rule_hash
        and _neutral_contract_audit_pass(gate3) is True
        and gate3.neutral_channel_audit_pass is True
        and gate3.paired_arm_contract_hash == reg.gate3_paired_arm_contract_hash
        and gate3.neutral_arm_contract_hash == reg.gate3_neutral_arm_contract_hash
        and gate3.neutral_recovery_contract_hash
        == reg.gate3_neutral_recovery_contract_hash
        and gate3.neutral_sham_generator_hash == reg.neutral_sham_generator_hash
        and gate3.contract_sealed_before_branches_pass is True
        and gate3.contract_preseal_receipt_hash
        == integrity.gate3_contract_preseal_receipt_hash
        and isinstance(gate3.contract_sealed_event_index, int)
        and not isinstance(gate3.contract_sealed_event_index, bool)
        and isinstance(gate3.first_branch_started_event_index, int)
        and not isinstance(gate3.first_branch_started_event_index, bool)
        and gate3.contract_sealed_event_index < gate3.first_branch_started_event_index
        and gate3.neutral_model_id == reg.model_id
        and gate3.neutral_interface_hash == reg.interface_hash
        and gate3.neutral_resource_contract_hash == reg.gate3_resource_contract_hash
        and gate3.neutral_k_manifest_hash == integrity.k_manifest_hash
        and gate3.neutral_e0_manifest_hash == integrity.e0_manifest_hash
        and gate3.neutral_web_manifest_hash == integrity.observed_web_manifest_hash
        and gate3.neutral_opportunity_contract_hash
        == reg.gate3_opportunity_contract_hash
        and gate3.neutral_challenger_policy_hash == reg.gate3_branch_policy_hash
    )


def neutral_scope_matches(
    reg: Registration, integrity: IntegrityEvidence, gate3: Gate3Evidence
) -> bool:
    return bool(
        neutral_contract_matches(reg, integrity, gate3)
        and gate3.checkpoint_scope == "lineage_empty"
        and gate3.neutral_recovery_contract_hash == reg.gate2_control_contract_hash
        and reg.gate3_pair_randomization_distribution_hash
        == reg.challenge_distribution_hash
        and gate3.neutral_resource_contract_hash == integrity.resource_contract_hash
        and gate3.neutral_opportunity_contract_hash
        == integrity.opportunity_contract_hash
        and gate3.neutral_challenger_policy_hash == integrity.challenger_policy_hash
    )


def validate_neutral_hit_integrity(
    reg: Registration,
    integrity: IntegrityEvidence,
    gate2: Gate2Evidence,
    gate3: Gate3Evidence,
) -> tuple[list[str], list[int]]:
    """Validate positive neutral witnesses independently of the effect test.

    The returned indices are the neutral branches that may be classified
    against ``P``.  Truthful-arm, sham, fixed-N, adequacy, and independence
    failures are intentionally outside this validator: they can block an
    effect or a zero-hit bound, but cannot erase a concrete valid hit.
    """
    global_errors: list[str] = []
    pair_errors: dict[int, list[str]] = {}
    if not isinstance(gate3, Gate3Evidence):
        return ["gate3 evidence must be a Gate3Evidence record"], []
    if not isinstance(integrity, IntegrityEvidence):
        return ["integrity evidence missing or malformed"], []

    for name in ("neutral_channel_audit_pass", "contract_sealed_before_branches_pass"):
        _bool(getattr(gate3, name), f"gate3.{name}", global_errors)
    if gate3.neutral_contract_audit_pass is None:
        _bool(
            gate3.paired_contract_audit_pass,
            "gate3.paired_contract_audit_pass",
            global_errors,
        )
    else:
        _bool(
            gate3.neutral_contract_audit_pass,
            "gate3.neutral_contract_audit_pass",
            global_errors,
        )
    if _neutral_contract_audit_pass(gate3) is not True:
        if gate3.neutral_contract_audit_pass is None:
            # Preserve the exact legacy error text for byte-for-byte verdict
            # replay of bundles that predate the neutral-specific field.
            global_errors.append("neutral witness paired-contract audit failed")
        else:
            global_errors.append("neutral witness neutral-contract audit failed")
    if gate3.neutral_channel_audit_pass is not True:
        global_errors.append("neutral witness channel audit failed")
    if gate3.contract_sealed_before_branches_pass is not True:
        global_errors.append("neutral witness contract was not presealed")
    if gate3.checkpoint_scope not in {"lineage_empty", "lineage_prefix"}:
        global_errors.append("neutral witness checkpoint_scope is invalid")
    elif gate3.checkpoint_scope != reg.gate3_checkpoint_scope:
        global_errors.append(
            "neutral witness checkpoint_scope differs from registration"
        )
    if reg.gate3_checkpoint_selection_rule_hash != integrity.selection_rule_hash:
        global_errors.append("neutral witness selection rule differs from registration")

    for name in (
        "checkpoint_hash",
        "window_hash",
        "paired_arm_contract_hash",
        "neutral_arm_contract_hash",
        "neutral_recovery_contract_hash",
        "neutral_sham_generator_hash",
        "contract_preseal_receipt_hash",
        "neutral_scope_audit_manifest_hash",
        "neutral_model_id",
        "neutral_interface_hash",
        "neutral_resource_contract_hash",
        "neutral_k_manifest_hash",
        "neutral_e0_manifest_hash",
        "neutral_web_manifest_hash",
        "neutral_opportunity_contract_hash",
        "neutral_challenger_policy_hash",
    ):
        if not _explicit(getattr(gate3, name)):
            global_errors.append(f"neutral witness {name} missing")

    if not _explicit(integrity.gate3_contract_preseal_receipt_hash):
        global_errors.append("neutral witness frozen preseal receipt missing")
    elif (
        gate3.contract_preseal_receipt_hash
        != integrity.gate3_contract_preseal_receipt_hash
    ):
        global_errors.append("neutral witness preseal receipt differs from integrity")
    for name in ("contract_sealed_event_index", "first_branch_started_event_index"):
        value = getattr(gate3, name)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            global_errors.append(
                f"neutral witness {name} must be a non-negative integer"
            )
    if (
        isinstance(gate3.contract_sealed_event_index, int)
        and not isinstance(gate3.contract_sealed_event_index, bool)
        and isinstance(gate3.first_branch_started_event_index, int)
        and not isinstance(gate3.first_branch_started_event_index, bool)
        and gate3.contract_sealed_event_index >= gate3.first_branch_started_event_index
    ):
        global_errors.append("neutral witness contract was not sealed before branches")
    if not neutral_contract_matches(reg, integrity, gate3):
        global_errors.append(
            "neutral witness contract differs from frozen registration"
        )

    try:
        scope_hash = gate3_neutral_scope_manifest_hash(
            gate3, integrity.selection_rule_hash
        )
        if gate3.neutral_scope_audit_manifest_hash != scope_hash:
            global_errors.append("neutral witness scope manifest hash mismatch")
        if integrity.gate3_neutral_scope_manifest_hash != scope_hash:
            global_errors.append("neutral witness scope is not bound by integrity")
    except (TypeError, ValueError, AttributeError, OverflowError):
        global_errors.append("neutral witness scope hash could not be recomputed")

    if not _sequence(gate3.pairs):
        global_errors.append("neutral witness pairs must be a JSON array")
        pairs: list[FeedbackPair] = []
    else:
        pairs = []
        for index, item in enumerate(gate3.pairs):
            local: list[str] = []
            if not isinstance(item, FeedbackPair):
                local.append(f"neutral witness pair[{index}] is malformed")
                pair_errors[index] = local
                continue
            pairs.append(item)
            _validate_pair_common(
                item,
                f"neutral witness pair[{index}]",
                local,
                expected_distribution_hash=reg.gate3_pair_randomization_distribution_hash,
            )
            if item.assignment_frozen is not True:
                local.append(f"neutral witness pair[{index}] assignment was not frozen")
            _validate_branch(
                item.neutral,
                f"neutral witness pair[{index}].neutral",
                local,
                require_private_scores=True,
                expected_unit_manifest_hash=integrity.private_unit_manifest_hash,
                expected_execution_contract_hash=reg.gate3_neutral_arm_contract_hash,
            )
            if local:
                pair_errors[index] = local

    # A positive witness does not need independent replicates, but it must be
    # one genuinely preallocated candidate and stay inside the score-test FWER.
    def mark_duplicates(values: list[object], label: str) -> None:
        counts = {value: values.count(value) for value in values}
        for index, value in enumerate(values):
            if counts[value] > 1:
                pair_errors.setdefault(index, []).append(
                    f"neutral witness {label} is duplicated"
                )

    if pairs and len(pairs) == len(gate3.pairs):
        mark_duplicates([p.pair_id for p in pairs], "pair id")
        mark_duplicates([p.block_id for p in pairs], "block id")
        mark_duplicates(
            [p.randomization_draw_receipt_hash for p in pairs], "draw receipt"
        )
        mark_duplicates([p.neutral.branch_id for p in pairs], "branch id")
        mark_duplicates(
            [p.neutral.prestart_contract_receipt_hash for p in pairs],
            "prestart contract receipt",
        )

    main_slots = len(gate2.controls) if _sequence(gate2.controls) else 0
    candidate_slots = main_slots + 2 * len(pairs)
    if not isinstance(reg.m_max, int) or isinstance(reg.m_max, bool):
        global_errors.append("neutral witness M_max is malformed")
    elif candidate_slots > reg.m_max:
        global_errors.append(
            f"neutral witness candidate slots {candidate_slots} exceed M_max={reg.m_max}"
        )

    try:
        ledger_hash = gate3_neutral_recovery_ledger_manifest_hash(gate3)
        if integrity.gate3_neutral_recovery_ledger_manifest_hash != ledger_hash:
            global_errors.append("neutral witness ledger is not bound by integrity")
    except (TypeError, ValueError, AttributeError, OverflowError):
        global_errors.append("neutral witness ledger hash could not be recomputed")

    all_errors = list(global_errors)
    for index in sorted(pair_errors):
        all_errors.extend(pair_errors[index])
    eligible = (
        []
        if global_errors
        else [index for index in range(len(gate3.pairs)) if index not in pair_errors]
    )
    return all_errors, eligible


def validate_neutral_recovery_ledger_integrity(
    reg: Registration,
    gate3: Gate3Evidence,
    neutral_candidate_errors: Sequence[str],
) -> list[str]:
    """Check that a supplied neutral ledger cannot hide a recovery witness.

    Candidate-level errors are inherited.  This adds only disclosure and
    started-ledger requirements; truthful/sham/effect-estimation fields remain
    outside the Core recovery audit.
    """
    errors = list(neutral_candidate_errors)
    if not isinstance(gate3, Gate3Evidence):
        return errors or ["gate3 evidence must be a Gate3Evidence record"]
    for name in ("all_started_pairs_disclosed", "no_pair_replacements"):
        _bool(getattr(gate3, name), f"neutral ledger {name}", errors)
    if gate3.all_started_pairs_disclosed is not True:
        errors.append("neutral recovery started-pair ledger is not complete")
    if not _sequence(gate3.pairs):
        errors.append("neutral recovery pairs must be a JSON array")
        pair_count = 0
    else:
        pair_count = len(gate3.pairs)
    if (
        not isinstance(gate3.started_pair_count, int)
        or isinstance(gate3.started_pair_count, bool)
        or gate3.started_pair_count != pair_count
    ):
        errors.append("neutral recovery started_pair_count does not match disclosure")
    ledger = feedback_replacement_ledger(
        gate3.pairs if _sequence(gate3.pairs) else (),
        registered_n=reg.registered_n_feedback_pairs,
        max_replacements=reg.max_feedback_pair_replacements,
        policy=reg.gate3_pair_replacement_policy,
    )
    errors.extend(ledger.errors)
    if gate3.no_pair_replacements is not (ledger.replacement_count == 0):
        errors.append(
            "neutral recovery no_pair_replacements disagrees with disclosed ledger"
        )
    return errors


def validate_gate3_integrity(
    reg: Registration,
    integrity: IntegrityEvidence,
    gate2: Gate2Evidence,
    gate3: Gate3Evidence,
) -> list[str]:
    """Validate Gate-3 pairs, fixed sample sizes, binding, and global slots."""
    errors: list[str] = []
    if not isinstance(gate3, Gate3Evidence):
        return ["gate3 evidence must be a Gate3Evidence record"]
    _required_true(
        integrity.feedback_inference_assumptions_pass,
        "feedback_inference_assumptions_pass",
        errors,
    )
    _required_true(
        integrity.sham_inference_assumptions_pass,
        "sham_inference_assumptions_pass",
        errors,
    )
    for name in (
        "design_checks_pass",
        "stopping_rule_pass",
        "registered_pairs_complete",
        "all_started_pairs_disclosed",
        "no_pair_replacements",
        "paired_contract_audit_pass",
        "truthful_channel_audit_pass",
        "neutral_channel_audit_pass",
        "contract_sealed_before_branches_pass",
    ):
        _bool(getattr(gate3, name), f"gate3.{name}", errors)
    if gate3.neutral_contract_audit_pass is not None:
        _bool(
            gate3.neutral_contract_audit_pass,
            "gate3.neutral_contract_audit_pass",
            errors,
        )
        if gate3.neutral_contract_audit_pass is not True:
            errors.append("Gate 3 neutral contract audit failed")
    if gate3.all_started_pairs_disclosed is not True:
        errors.append("Gate 3 started-pair ledger is not complete")
    if gate3.contract_sealed_before_branches_pass is not True:
        errors.append("Gate 3 paired contract was not presealed")
    if gate3.checkpoint_scope not in {"lineage_empty", "lineage_prefix"}:
        errors.append("Gate 3 checkpoint_scope must be lineage_empty|lineage_prefix")
    elif gate3.checkpoint_scope != reg.gate3_checkpoint_scope:
        errors.append("Gate 3 checkpoint_scope differs from frozen registration")
    if reg.gate3_checkpoint_selection_rule_hash != integrity.selection_rule_hash:
        errors.append("Gate 3 checkpoint selection rule differs from frozen integrity")
    for name in (
        "checkpoint_hash",
        "window_hash",
        "feedback_pairs_manifest_hash",
        "paired_arm_contract_hash",
        "truthful_arm_contract_hash",
        "neutral_arm_contract_hash",
        "neutral_recovery_contract_hash",
        "truthful_feedback_generator_hash",
        "neutral_sham_generator_hash",
        "contract_preseal_receipt_hash",
        "neutral_scope_audit_manifest_hash",
    ):
        if not _explicit(getattr(gate3, name)):
            errors.append(f"Gate 3 {name} missing")

    if not _explicit(integrity.gate3_contract_preseal_receipt_hash):
        errors.append("Gate 3 frozen preseal receipt missing from integrity envelope")
    elif (
        gate3.contract_preseal_receipt_hash
        != integrity.gate3_contract_preseal_receipt_hash
    ):
        errors.append("Gate 3 preseal receipt differs from integrity envelope")
    for name in ("contract_sealed_event_index", "first_branch_started_event_index"):
        value = getattr(gate3, name)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            errors.append(f"Gate 3 {name} must be a non-negative integer")
    if (
        isinstance(gate3.contract_sealed_event_index, int)
        and not isinstance(gate3.contract_sealed_event_index, bool)
        and isinstance(gate3.first_branch_started_event_index, int)
        and not isinstance(gate3.first_branch_started_event_index, bool)
        and gate3.contract_sealed_event_index >= gate3.first_branch_started_event_index
    ):
        errors.append("Gate 3 contract was not sealed before the first branch")

    if gate3.paired_contract_audit_pass is not True:
        errors.append("Gate 3 paired contract audit failed")
    if gate3.truthful_channel_audit_pass is not True:
        errors.append("Gate 3 truthful channel audit failed")
    if gate3.neutral_channel_audit_pass is not True:
        errors.append("Gate 3 neutral channel audit failed")
    if not paired_contract_matches(reg, integrity, gate3):
        errors.append("Gate 3 paired contract differs from frozen registration")
    for name in (
        "neutral_model_id",
        "neutral_interface_hash",
        "neutral_resource_contract_hash",
        "neutral_k_manifest_hash",
        "neutral_e0_manifest_hash",
        "neutral_web_manifest_hash",
        "neutral_opportunity_contract_hash",
        "neutral_challenger_policy_hash",
    ):
        if not _explicit(getattr(gate3, name)):
            errors.append(f"Gate 3 {name} missing")

    if gate3.neutral_adequacy is not None:
        neutral_ad = _validate_adequacy(
            gate3.neutral_adequacy, "gate3.neutral_adequacy", errors
        )
        main_ad = gate2.adequacy
        if neutral_ad is not None and isinstance(main_ad, AdequacyEvidence):
            if (
                neutral_ad.calibration_id != main_ad.calibration_id
                or neutral_ad.checks_manifest_hash != main_ad.checks_manifest_hash
            ):
                errors.append(
                    "main/neutral adequacy must reuse the registered calibration or allocate separate alpha"
                )

    if not _sequence(gate3.pairs):
        errors.append("gate3.pairs must be a JSON array")
        pairs: list[FeedbackPair] = []
    else:
        pairs = []
        for index, item in enumerate(gate3.pairs):
            label = f"gate3.pairs[{index}]"
            if not isinstance(item, FeedbackPair):
                errors.append(f"{label} must be a FeedbackPair record")
                continue
            pairs.append(item)
            _validate_pair_common(
                item,
                label,
                errors,
                expected_distribution_hash=reg.gate3_pair_randomization_distribution_hash,
            )
            if item.assignment_frozen is not True:
                errors.append(f"{label}.assignment_frozen must be true")
            if item.independence_ok is not True:
                errors.append(
                    f"{label}.independence_ok must be true for effect inference"
                )
            _validate_branch(
                item.truthful,
                f"{label}.truthful",
                errors,
                require_private_scores=True,
                expected_unit_manifest_hash=integrity.private_unit_manifest_hash,
                expected_execution_contract_hash=reg.gate3_truthful_arm_contract_hash,
            )
            _validate_branch(
                item.neutral,
                f"{label}.neutral",
                errors,
                require_private_scores=True,
                expected_unit_manifest_hash=integrity.private_unit_manifest_hash,
                expected_execution_contract_hash=reg.gate3_neutral_arm_contract_hash,
            )
            if reg.feedback_estimand == "binary" and (
                item.truthful.utility is not None or item.neutral.utility is not None
            ):
                errors.append(
                    f"{label} binary utilities must be derived by the canonical P wrapper"
                )
    feedback_ledger = feedback_replacement_ledger(
        pairs,
        registered_n=reg.registered_n_feedback_pairs,
        max_replacements=reg.max_feedback_pair_replacements,
        policy=reg.gate3_pair_replacement_policy,
    )
    errors.extend(feedback_ledger.errors)
    if gate3.no_pair_replacements is not (
        feedback_ledger.replacement_count == 0
    ):
        errors.append("Gate 3 no_pair_replacements disagrees with disclosed ledger")
    if (
        not isinstance(gate3.started_pair_count, int)
        or isinstance(gate3.started_pair_count, bool)
        or gate3.started_pair_count != len(pairs)
    ):
        errors.append("Gate 3 started_pair_count does not match disclosed pairs")
    pair_ids = [p.pair_id for p in pairs]
    block_ids = [p.block_id for p in pairs]
    branch_ids = [b.branch_id for p in pairs for b in (p.truthful, p.neutral)]
    branch_receipts = [
        b.prestart_contract_receipt_hash for p in pairs for b in (p.truthful, p.neutral)
    ]
    draw_receipts = [p.randomization_draw_receipt_hash for p in pairs]
    if len(set(pair_ids)) != len(pair_ids):
        errors.append("feedback pair ids are duplicated")
    if len(set(block_ids)) != len(block_ids):
        errors.append(
            "feedback block ids are duplicated; clustered estimator unsupported"
        )
    if len(set(branch_ids)) != len(branch_ids):
        errors.append("feedback branch ids are duplicated")
    if len(set(branch_receipts)) != len(branch_receipts):
        errors.append("feedback branch prestart receipts are duplicated")
    if len(set(draw_receipts)) != len(draw_receipts):
        errors.append("feedback randomization draw receipts are duplicated")
    try:
        if feedback_pairs_manifest_hash(pairs) != gate3.feedback_pairs_manifest_hash:
            errors.append("feedback-pairs manifest hash mismatch")
    except (TypeError, ValueError, AttributeError, OverflowError):
        errors.append("feedback-pairs manifest hash could not be recomputed")

    sham = gate3.sham
    if not isinstance(sham, ShamCalibration):
        errors.append("gate3.sham must be a ShamCalibration record")
        sham_pairs: list[ShamPair] = []
    elif not _sequence(sham.pairs):
        errors.append("gate3.sham.pairs must be a JSON array")
        sham_pairs = []
    else:
        for name in (
            "channel_checks_pass",
            "freshness_pass",
            "operator_frozen_before_confirmatory",
            "development_confirmatory_disjoint",
            "all_started_pairs_disclosed",
            "no_pair_replacements",
            "contract_sealed_before_branches_pass",
        ):
            _bool(getattr(sham, name), f"gate3.sham.{name}", errors)
        if sham.all_started_pairs_disclosed is not True:
            errors.append("sham started-pair ledger is not complete")
        if sham.contract_sealed_before_branches_pass is not True:
            errors.append("sham contract was not presealed")
        for name in (
            "calibration_id",
            "development_manifest_hash",
            "confirmatory_manifest_hash",
            "task_family_profile",
            "model_id",
            "interface_hash",
            "scaffold_hash",
            "feedback_schema_hash",
            "operator_hash",
            "reference_null_generator_hash",
            "utility_scale_id",
            "paired_arm_contract_hash",
            "reference_arm_contract_hash",
            "proposed_arm_contract_hash",
            "contract_preseal_receipt_hash",
        ):
            if not _explicit(getattr(sham, name)):
                errors.append(f"gate3.sham.{name} missing")
        if sham.paired_arm_contract_hash != reg.sham_paired_arm_contract_hash:
            errors.append("sham paired-arm contract differs from registration")
        if sham.reference_arm_contract_hash != reg.sham_reference_arm_contract_hash:
            errors.append("sham reference-arm contract differs from registration")
        if sham.proposed_arm_contract_hash != reg.sham_proposed_arm_contract_hash:
            errors.append("sham proposed-arm contract differs from registration")
        if sham.reference_null_generator_hash != reg.reference_null_generator_hash:
            errors.append("sham reference-null generator differs from registration")
        if not _explicit(integrity.sham_contract_preseal_receipt_hash):
            errors.append("sham frozen preseal receipt missing from integrity envelope")
        elif (
            sham.contract_preseal_receipt_hash
            != integrity.sham_contract_preseal_receipt_hash
        ):
            errors.append("sham preseal receipt differs from integrity envelope")
        for name in (
            "contract_sealed_event_index",
            "first_branch_started_event_index",
        ):
            value = getattr(sham, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                errors.append(f"gate3.sham.{name} must be a non-negative integer")
        if (
            isinstance(sham.contract_sealed_event_index, int)
            and not isinstance(sham.contract_sealed_event_index, bool)
            and isinstance(sham.first_branch_started_event_index, int)
            and not isinstance(sham.first_branch_started_event_index, bool)
            and sham.contract_sealed_event_index
            >= sham.first_branch_started_event_index
        ):
            errors.append("sham contract was not sealed before the first branch")
        sham_pairs = []
        for index, item in enumerate(sham.pairs):
            label = f"gate3.sham.pairs[{index}]"
            if not isinstance(item, ShamPair):
                errors.append(f"{label} must be a ShamPair record")
                continue
            sham_pairs.append(item)
            _validate_pair_common(
                item,
                label,
                errors,
                expected_distribution_hash=reg.sham_randomization_distribution_hash,
            )
            if item.assignment_frozen is not True:
                errors.append(f"{label}.assignment_frozen must be true")
            if item.independence_ok is not True:
                errors.append(f"{label}.independence_ok must be true")
            _validate_branch(
                item.reference_null,
                f"{label}.reference_null",
                errors,
                require_private_scores=False,
                expected_execution_contract_hash=reg.sham_reference_arm_contract_hash,
            )
            _validate_branch(
                item.proposed_sham,
                f"{label}.proposed_sham",
                errors,
                require_private_scores=False,
                expected_execution_contract_hash=reg.sham_proposed_arm_contract_hash,
            )
    sham_ledger = sham_replacement_ledger(
        sham_pairs,
        registered_n=reg.registered_n_sham_pairs,
        max_replacements=reg.max_sham_pair_replacements,
        policy=reg.gate3_pair_replacement_policy,
    )
    errors.extend(sham_ledger.errors)
    if isinstance(sham, ShamCalibration) and sham.no_pair_replacements is not (
        sham_ledger.replacement_count == 0
    ):
        errors.append("sham no_pair_replacements disagrees with disclosed ledger")
    if (
        not isinstance(getattr(sham, "started_pair_count", None), int)
        or isinstance(getattr(sham, "started_pair_count", None), bool)
        or getattr(sham, "started_pair_count", None) != len(sham_pairs)
    ):
        errors.append("sham started_pair_count does not match disclosed pairs")
    sham_pair_ids = [p.pair_id for p in sham_pairs]
    sham_block_ids = [p.block_id for p in sham_pairs]
    sham_branch_ids = [
        b.branch_id for p in sham_pairs for b in (p.reference_null, p.proposed_sham)
    ]
    sham_branch_receipts = [
        b.prestart_contract_receipt_hash
        for p in sham_pairs
        for b in (p.reference_null, p.proposed_sham)
    ]
    sham_draw_receipts = [p.randomization_draw_receipt_hash for p in sham_pairs]
    if len(set(sham_pair_ids)) != len(sham_pair_ids):
        errors.append("sham pair ids are duplicated")
    if len(set(sham_block_ids)) != len(sham_block_ids):
        errors.append("sham block ids are duplicated; clustered estimator unsupported")
    if len(set(sham_branch_ids)) != len(sham_branch_ids):
        errors.append("sham branch ids are duplicated")
    if len(set(sham_branch_receipts)) != len(sham_branch_receipts):
        errors.append("sham branch prestart receipts are duplicated")
    if len(set(sham_draw_receipts)) != len(sham_draw_receipts):
        errors.append("sham randomization draw receipts are duplicated")
    if isinstance(sham, ShamCalibration):
        try:
            if sham_pairs_manifest_hash(sham_pairs) != sham.confirmatory_manifest_hash:
                errors.append("sham confirmatory manifest hash mismatch")
        except (TypeError, ValueError, AttributeError, OverflowError):
            errors.append("sham confirmatory manifest hash could not be recomputed")

    main_slots = len(gate2.controls) if _sequence(gate2.controls) else 0
    candidate_slots = main_slots + 2 * len(pairs)
    if isinstance(reg.m_max, int) and candidate_slots > reg.m_max:
        errors.append(
            f"total scored candidate slots {candidate_slots} exceed registered M_max={reg.m_max}"
        )
    try:
        neutral_scope_hash = gate3_neutral_scope_manifest_hash(
            gate3, integrity.selection_rule_hash
        )
        if neutral_scope_hash != gate3.neutral_scope_audit_manifest_hash:
            errors.append("Gate-3 neutral-scope manifest hash mismatch")
        if integrity.gate3_neutral_scope_manifest_hash != neutral_scope_hash:
            errors.append("Gate-3 neutral scope is not bound by integrity")
        if (
            gate3_neutral_recovery_ledger_manifest_hash(gate3)
            != integrity.gate3_neutral_recovery_ledger_manifest_hash
        ):
            errors.append("Gate-3 neutral recovery ledger is not bound by integrity")
        if (
            recovery_ledger_manifest_hash(gate2.controls, gate3)
            != integrity.recovery_ledger_manifest_hash
        ):
            errors.append("global recovery-ledger manifest hash mismatch")
    except (TypeError, ValueError, AttributeError, OverflowError):
        errors.append("Gate-3 scope/global-ledger hash could not be recomputed")
    return errors
