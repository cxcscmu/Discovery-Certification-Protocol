"""Mechanical conversion from a frozen run ledger to DCP kernel evidence."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from dcp import (
    IntegrityEvidence,
    adequacy_evidence_hash,
    artifact_results_hash,
    branch_result_hash,
    feedback_pairs_manifest_hash,
    gate3_neutral_recovery_ledger_manifest_hash,
    gate3_neutral_scope_manifest_hash,
    private_results_manifest_hash,
    recovery_ledger_manifest_hash,
    sham_pairs_manifest_hash,
    unit_manifest_hash,
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
    RawAttemptOutcome,
    ShamCalibration,
    ShamPair,
    Validity,
)

from dcp_harness.adapter import EvidencePackage, Phase, RunView
from dcp_harness.util import HarnessError, hash_json, load_json_object


@dataclass(frozen=True)
class AuditAttestations:
    """Task-specific judgments that a generic recorder cannot infer.

    Defaults fail closed. Setting a field to true is an auditor attestation,
    not a request to bypass a check. The kernel and harness still verify every
    mechanical hash, count, contract, and score binding.
    """

    iterative_lineage_eligible: bool = False
    lineage_dataflow_audit_pass: bool = False
    symmetric_verifier_pass: bool = False
    inference_assumptions_pass: bool = False
    feedback_inference_assumptions_pass: bool = False
    sham_inference_assumptions_pass: bool = False
    materials_readable: bool = False
    opportunity_floor_met: bool = False
    paired_contract_audit_pass: bool = False
    truthful_channel_audit_pass: bool = False
    neutral_channel_audit_pass: bool = False
    sham_channel_checks_pass: bool = False
    sham_freshness_pass: bool = False
    sham_operator_frozen_before_confirmatory: bool = False
    sham_development_confirmatory_disjoint: bool = False
    sham_development_manifest_hash: str = ""
    positive_control_calibration_id: str = "dcp-task-neutral-channel-v1"
    human_assistance: str = "none"
    attribution_subject: str = "autonomous_agent"


def _require_artifact(evaluation: dict[str, Any], label: str) -> None:
    if (
        evaluation.get("outcome") != RawAttemptOutcome.ARTIFACT.value
        or evaluation.get("validity") not in {Validity.VALID.value, Validity.INVALID.value}
        or not evaluation.get("artifact_hash")
        or not evaluation.get("per_unit")
        or not evaluation.get("unit_ids")
    ):
        raise HarnessError(f"{label} is not a privately scored artifact")


def _artifact(evaluation: dict[str, Any], name: str) -> ArtifactScores:
    _require_artifact(evaluation, name)
    return ArtifactScores(
        name=name,
        per_unit=tuple(float(value) for value in evaluation["per_unit"]),
        validity=Validity(evaluation["validity"]),
        artifact_hash=str(evaluation["artifact_hash"]),
        unit_ids=tuple(str(value) for value in evaluation["unit_ids"]),
    )


def _turn_receipt_ok(turn: object) -> bool:
    if not isinstance(turn, dict) or not isinstance(turn.get("agent"), dict):
        return False
    agent = turn["agent"]
    receipt_present = bool(
        agent.get("provider_receipt_hash")
        and agent.get("stdout_hash")
        and agent.get("stderr_hash")
    )
    if agent.get("infrastructure_invalid_preaction") is True:
        return bool(
            receipt_present
            and agent.get("model_action_started") is False
            and agent.get("identity_complete") is False
        )
    return bool(
        receipt_present
        and agent.get("identity_complete") is True
        and agent.get("identity_ok") is True
        and agent.get("interface_ok") is True
        and agent.get("provider_session_id")
        and agent.get("assistant_message_ids")
        and agent.get("result_event_uuid")
    )


def _agent_receipts_ok(record: dict[str, Any]) -> bool:
    turns = record.get("turns")
    return bool(isinstance(turns, list) and turns and all(map(_turn_receipt_ok, turns)))


def _matched_model_observed(records: tuple[dict[str, Any], ...]) -> bool:
    matched = 0
    for record in records:
        for turn in record.get("turns", []):
            if not _turn_receipt_ok(turn):
                return False
            agent = turn["agent"]
            if agent.get("infrastructure_invalid_preaction") is not True:
                matched += 1
    return matched > 0


def _control(record: dict[str, Any], run: RunView) -> ControlAttempt:
    evaluation = record["evaluation"]
    outcome = RawAttemptOutcome(evaluation["outcome"])
    return ControlAttempt(
        attempt_id=record["episode_id"],
        outcome=outcome,
        per_unit=(
            tuple(float(value) for value in evaluation["per_unit"])
            if outcome == RawAttemptOutcome.ARTIFACT
            else None
        ),
        validity=Validity(evaluation["validity"]),
        artifact_hash=str(evaluation["artifact_hash"]),
        unit_ids=tuple(str(value) for value in evaluation["unit_ids"]),
        stratum=run.registration.recovery_stratum,
        scope_contract_hash=record["execution_contract_hash"],
        prestart_contract_receipt_hash=record["prestart_contract_receipt_hash"],
        challenge_distribution_hash=run.registration.challenge_distribution_hash,
        independent_draw_receipt_hash=record["independent_draw_receipt_hash"],
        independent_unit_id=record["episode_id"],
        independence_ok=True,
        infrastructure_outcome_independent=bool(
            record["infrastructure_invalid_preaction"]
        ),
    )


def _branch_from_record(record: dict[str, Any]) -> BranchOutcome:
    evaluation = record["evaluation"]
    outcome = RawAttemptOutcome(evaluation["outcome"])
    branch = BranchOutcome(
        outcome=outcome,
        utility=evaluation["utility"],
        validity=Validity(evaluation["validity"]),
        branch_id=record["episode_id"],
        artifact_hash=str(evaluation["artifact_hash"]),
        execution_contract_hash=record["execution_contract_hash"],
        prestart_contract_receipt_hash=record[
            "prestart_contract_receipt_hash"
        ],
        per_unit=(
            tuple(float(value) for value in evaluation["per_unit"])
            if evaluation["per_unit"]
            else None
        ),
        unit_ids=tuple(str(value) for value in evaluation["unit_ids"]),
        infrastructure_outcome_independent=bool(
            record["infrastructure_invalid_preaction"]
        ),
    )
    branch.verifier_result_hash = branch_result_hash(branch)
    return branch


def _unstarted_infrastructure_branch(
    run: RunView, row: dict[str, Any], phase: Phase
) -> BranchOutcome:
    prestart = row.get("branch_prestarts", {}).get(phase.value)
    if not isinstance(prestart, dict) or not prestart.get("receipt_hash"):
        raise HarnessError(
            f"unstarted Gate-3 branch has no sealed receipt: {row.get('pair_id')}"
        )
    contract_key = {
        Phase.FEEDBACK_TRUTHFUL: "gate3_truthful_arm_contract_hash",
        Phase.FEEDBACK_NEUTRAL: "gate3_neutral_arm_contract_hash",
        Phase.SHAM_REFERENCE: "sham_reference_arm_contract_hash",
        Phase.SHAM_PROPOSED: "sham_proposed_arm_contract_hash",
    }[phase]
    branch = BranchOutcome(
        outcome=RawAttemptOutcome.INFRASTRUCTURE_INVALID,
        validity=Validity.UNRESOLVED,
        branch_id=f"{row['pair_id']}-{phase.value}",
        execution_contract_hash=run.contracts[contract_key],
        prestart_contract_receipt_hash=prestart["receipt_hash"],
        infrastructure_outcome_independent=True,
    )
    branch.verifier_result_hash = branch_result_hash(branch)
    return branch


def _branch(
    run: RunView,
    row: dict[str, Any],
    phase: Phase,
    episodes: dict[str, dict[str, Any]],
) -> BranchOutcome:
    episode_id = row.get("branches", {}).get(phase.value)
    if episode_id is None:
        return _unstarted_infrastructure_branch(run, row, phase)
    record = episodes.get(str(episode_id))
    if record is None:
        raise HarnessError(f"Gate-3 episode is absent: {episode_id}")
    return _branch_from_record(record)


def _gate3(
    run: RunView,
    adequacy: AdequacyEvidence,
    attestations: AuditAttestations,
) -> Gate3Evidence:
    summary = load_json_object(run.root / "gate3/summary.json")
    episodes = {row["episode_id"]: row for row in run.episodes}
    feedback_pairs: list[FeedbackPair] = []
    for row in run.state["gate3_feedback_pairs"]:
        feedback_pairs.append(
            FeedbackPair(
                pair_id=row["pair_id"],
                truthful=_branch(
                    run, row, Phase.FEEDBACK_TRUTHFUL, episodes
                ),
                neutral=_branch(run, row, Phase.FEEDBACK_NEUTRAL, episodes),
                block_id=f"feedback-block-{row['pair_id']}",
                randomization_distribution_hash=run.registration.gate3_pair_randomization_distribution_hash,
                randomization_draw_receipt_hash=row[
                    "randomization_draw_receipt_hash"
                ],
                assignment_frozen=True,
                independence_ok=True,
                replacement_of=row["replacement_of"],
            )
        )
    sham_pairs: list[ShamPair] = []
    for row in run.state["gate3_sham_pairs"]:
        sham_pairs.append(
            ShamPair(
                pair_id=row["pair_id"],
                reference_null=_branch(
                    run, row, Phase.SHAM_REFERENCE, episodes
                ),
                proposed_sham=_branch(
                    run, row, Phase.SHAM_PROPOSED, episodes
                ),
                block_id=f"sham-block-{row['pair_id']}",
                randomization_distribution_hash=run.registration.sham_randomization_distribution_hash,
                randomization_draw_receipt_hash=row[
                    "randomization_draw_receipt_hash"
                ],
                assignment_frozen=True,
                independence_ok=True,
                replacement_of=row["replacement_of"],
            )
        )
    development_hash = attestations.sham_development_manifest_hash or hash_json(
        {"status": "sham_development_manifest_not_attested"}
    )
    sham = ShamCalibration(
        pairs=tuple(sham_pairs),
        calibration_id=run.registration.sham_calibration_id,
        development_manifest_hash=development_hash,
        confirmatory_manifest_hash=sham_pairs_manifest_hash(sham_pairs),
        task_family_profile=run.registration.task_family_profile,
        model_id=run.registration.model_id,
        interface_hash=run.registration.interface_hash,
        scaffold_hash=run.registration.scaffold_hash,
        feedback_schema_hash=run.registration.feedback_schema_hash,
        operator_hash=run.registration.sham_operator_hash,
        reference_null_generator_hash=run.registration.reference_null_generator_hash,
        utility_scale_id=run.registration.utility_scale_id,
        paired_arm_contract_hash=run.registration.sham_paired_arm_contract_hash,
        reference_arm_contract_hash=run.registration.sham_reference_arm_contract_hash,
        proposed_arm_contract_hash=run.registration.sham_proposed_arm_contract_hash,
        contract_preseal_receipt_hash=summary[
            "contract_preseal_receipt_hash"
        ],
        contract_sealed_before_branches_pass=True,
        contract_sealed_event_index=summary["contract_preseal_event_index"],
        first_branch_started_event_index=summary[
            "first_branch_started_event_index"
        ],
        channel_checks_pass=attestations.sham_channel_checks_pass,
        freshness_pass=attestations.sham_freshness_pass,
        operator_frozen_before_confirmatory=attestations.sham_operator_frozen_before_confirmatory,
        development_confirmatory_disjoint=attestations.sham_development_confirmatory_disjoint,
        all_started_pairs_disclosed=True,
        no_pair_replacements=not any(pair.replacement_of for pair in sham_pairs),
        started_pair_count=len(sham_pairs),
    )
    main = run.by_phase(Phase.MAIN)[0]
    main_summary = load_json_object(run.root / "main/summary.json")
    gate3 = Gate3Evidence(
        pairs=tuple(feedback_pairs),
        sham=sham,
        neutral_adequacy=adequacy,
        design_checks_pass=True,
        stopping_rule_pass=True,
        registered_pairs_complete=True,
        all_started_pairs_disclosed=True,
        no_pair_replacements=not any(pair.replacement_of for pair in feedback_pairs),
        paired_contract_audit_pass=attestations.paired_contract_audit_pass,
        truthful_channel_audit_pass=attestations.truthful_channel_audit_pass,
        neutral_channel_audit_pass=attestations.neutral_channel_audit_pass,
        started_pair_count=len(feedback_pairs),
        checkpoint_scope=run.registration.gate3_checkpoint_scope,
        checkpoint_hash=main_summary["selected_checkpoint_hash"],
        window_hash=run.contracts["gate3_resource_contract_hash"],
        feedback_pairs_manifest_hash=feedback_pairs_manifest_hash(feedback_pairs),
        paired_arm_contract_hash=run.registration.gate3_paired_arm_contract_hash,
        truthful_arm_contract_hash=run.registration.gate3_truthful_arm_contract_hash,
        neutral_arm_contract_hash=run.registration.gate3_neutral_arm_contract_hash,
        neutral_recovery_contract_hash=run.registration.gate3_neutral_recovery_contract_hash,
        truthful_feedback_generator_hash=run.registration.truthful_feedback_generator_hash,
        neutral_sham_generator_hash=run.registration.neutral_sham_generator_hash,
        contract_preseal_receipt_hash=summary[
            "contract_preseal_receipt_hash"
        ],
        contract_sealed_before_branches_pass=True,
        contract_sealed_event_index=summary["contract_preseal_event_index"],
        first_branch_started_event_index=summary[
            "first_branch_started_event_index"
        ],
        neutral_model_id=run.registration.model_id,
        neutral_interface_hash=run.registration.interface_hash,
        neutral_resource_contract_hash=run.registration.gate3_resource_contract_hash,
        neutral_k_manifest_hash=run.contracts["k_manifest_hash"],
        neutral_e0_manifest_hash=run.contracts["e0_manifest_hash"],
        neutral_web_manifest_hash=run.web_manifest["snapshot_id"],
        neutral_opportunity_contract_hash=run.registration.gate3_opportunity_contract_hash,
        neutral_challenger_policy_hash=run.registration.gate3_branch_policy_hash,
        neutral_scope_audit_manifest_hash="pending",
        neutral_contract_audit_pass=attestations.neutral_channel_audit_pass,
    )
    del main
    gate3.neutral_scope_audit_manifest_hash = gate3_neutral_scope_manifest_hash(
        gate3, run.contracts["selection_rule_hash"]
    )
    return gate3


def assemble_evidence(
    run: RunView,
    attestations: AuditAttestations,
) -> EvidencePackage:
    """Build kernel records without allowing an adapter to rewrite receipts."""

    if not isinstance(attestations, AuditAttestations):
        raise HarnessError("assemble_evidence requires AuditAttestations")
    main_rows = run.by_phase(Phase.MAIN)
    if len(main_rows) != 1:
        raise HarnessError("run must contain exactly one main episode")
    main = main_rows[0]
    baseline_evaluation = load_json_object(run.root / "main/baseline.json")
    astar = _artifact(main["evaluation"], "A*")
    baseline = _artifact(baseline_evaluation, "baseline")
    gate1 = Gate1Evidence(astar=astar, baseline=baseline)

    challenge_rows = run.by_phase(Phase.CHALLENGE)
    controls = tuple(_control(row, run) for row in challenge_rows)
    challenge_summary = load_json_object(run.root / "challenge/summary.json")
    positive_successes = int(challenge_summary["positive_control_successes"])
    positive_trials = int(challenge_summary["positive_control_episodes"])
    receipts_ok = _matched_model_observed(challenge_rows)
    adequacy = AdequacyEvidence(
        matched_model_present=receipts_ok,
        materials_readable=attestations.materials_readable,
        opportunity_floor_met=attestations.opportunity_floor_met,
        health_audit_pass=positive_successes == positive_trials,
        positive_control_successes=positive_successes,
        positive_control_trials=positive_trials,
        calibration_id=attestations.positive_control_calibration_id,
    )
    adequacy.checks_manifest_hash = adequacy_evidence_hash(adequacy)
    gate2 = Gate2Evidence(controls=controls, adequacy=adequacy)

    gate3 = (
        _gate3(run, adequacy, attestations)
        if run.registration.requests_evidence
        else None
    )
    web_used = int(run.web_manifest["request_count"]) > 0
    all_records = run.episodes
    provenance_ok = bool(all_records) and all(
        _agent_receipts_ok(row) for row in all_records
    )
    challenge_contract_ok = all(
        row["evaluation"]["outcome"]
        != RawAttemptOutcome.EXECUTION_CONTRACT_VIOLATION.value
        for row in challenge_rows
    )
    private_manifest = tuple(astar.unit_ids)
    integrity = IntegrityEvidence(
        registration_frozen=True,
        claim_frozen=True,
        provenance_pass=provenance_ok,
        iterative_lineage_eligible=attestations.iterative_lineage_eligible,
        lineage_dataflow_audit_pass=attestations.lineage_dataflow_audit_pass,
        challenger_contract_pass=challenge_contract_ok,
        private_isolation_pass=bool(run.contracts["private_isolation_pass"]),
        symmetric_verifier_pass=attestations.symmetric_verifier_pass,
        inference_assumptions_pass=attestations.inference_assumptions_pass,
        feedback_inference_assumptions_pass=attestations.feedback_inference_assumptions_pass,
        sham_inference_assumptions_pass=attestations.sham_inference_assumptions_pass,
        familywise_budget_audit_pass=run.registration.family_max_audits == 1,
        astar_hash=astar.artifact_hash,
        baseline_hash=baseline.artifact_hash,
        verifier_hash=run.contracts["verifier_hash"],
        astar_results_hash=artifact_results_hash(astar),
        baseline_results_hash=artifact_results_hash(baseline),
        private_unit_manifest_hash=unit_manifest_hash(private_manifest),
        private_results_manifest_hash=private_results_manifest_hash(
            astar, baseline, run.contracts["verifier_hash"]
        ),
        p_hash=run.contracts["p_hash"],
        resource_contract_hash=run.contracts["resource_contract_hash"],
        selection_rule_hash=run.contracts["selection_rule_hash"],
        k_manifest_hash=run.contracts["k_manifest_hash"],
        e0_manifest_hash=run.contracts["e0_manifest_hash"],
        lineage_manifest_hash=main["episode_record_hash"],
        observed_web_manifest_hash=run.web_manifest["snapshot_id"],
        challenger_policy_hash=run.contracts["challenger_policy_hash"],
        opportunity_contract_hash=run.contracts["opportunity_contract_hash"],
        recovery_ledger_complete=True,
        recovery_ledger_manifest_hash=recovery_ledger_manifest_hash(
            controls, gate3
        ),
        gate2_recovery_ledger_manifest_hash=recovery_ledger_manifest_hash(
            controls
        ),
        gate3_neutral_scope_manifest_hash=(
            gate3.neutral_scope_audit_manifest_hash if gate3 else ""
        ),
        gate3_neutral_recovery_ledger_manifest_hash=(
            gate3_neutral_recovery_ledger_manifest_hash(gate3) if gate3 else ""
        ),
        gate3_contract_preseal_receipt_hash=(
            gate3.contract_preseal_receipt_hash if gate3 else ""
        ),
        sham_contract_preseal_receipt_hash=(
            gate3.sham.contract_preseal_receipt_hash if gate3 else ""
        ),
        claim_family_manifest_hash=run.contracts["claim_family_manifest_hash"],
        alpha_ledger_receipt_hash=run.contracts[
            "audit_slot_reservation_receipt_hash"
        ],
        audit_slot_registry_entry_hash=run.contracts[
            "audit_slot_registry_entry_hash"
        ],
        human_assistance=attestations.human_assistance,
        attribution_subject=attestations.attribution_subject,
        web_access_used=web_used,
        web_replay_scope=(
            "observed_request_response_frozen" if web_used else "not_used"
        ),
    )
    return EvidencePackage(
        registration=run.registration,
        integrity=integrity,
        gate1=gate1,
        gate2=gate2,
        gate3=gate3,
    )
