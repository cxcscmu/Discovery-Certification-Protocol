from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import json

import pytest

from dcp import (
    IntegrityEvidence,
    Registration,
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
from dcp.api import verify_bundle
from dcp.registration import PAIR_REPLACEMENT_POLICY_TRANSPORT
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

from dcp_harness.adapter import (
    AuditMaterials,
    BaseTaskAdapter,
    EpisodeContext,
    EpisodeEvaluation,
    EvidencePackage,
    Phase,
    RunView,
)
from dcp_harness.backend import AgentRunResult
from dcp_harness.cli import _init
from dcp_harness.config import load_config
from dcp_harness.evidence import AuditAttestations, assemble_evidence
from dcp_harness.ledger import EventLedger
from dcp_harness.runtime import Harness
from dcp_harness.util import (
    HarnessError,
    hash_file,
    hash_json,
    load_json_object,
    write_json,
)
from dcp_harness.web import FixtureFetcher, ReplayGateway, validate_snapshot


PRIVATE_UNITS = tuple(f"held-out-{index:03d}" for index in range(20))


class FakeBackend:
    def __init__(self) -> None:
        self.calls = 0
        self._identity = {
            "schema": "fake_agent_interface_v1",
            "model": "fake-model-v1",
            "tools": ["Read", "Write", "Edit", "Glob", "Grep"],
            "private_isolation_pass": True,
        }

    @property
    def interface_identity(self):
        return dict(self._identity)

    @property
    def interface_hash(self):
        return hash_json(self._identity)

    def doctor(self):
        return {"ok": True, "interface_hash": self.interface_hash}

    def run(self, *, workspace, prompt, record_dir, episode_id):
        del prompt
        self.calls += 1
        record_dir.mkdir(parents=True, exist_ok=True)
        stdout = record_dir / "claude_stream.jsonl"
        stderr = record_dir / "claude_stderr.log"
        stdout.write_text("{}\n", encoding="utf-8")
        stderr.write_text("", encoding="utf-8")

        if episode_id.startswith("positive-control-"):
            marker = (workspace / "CANARY.txt").read_text(encoding="utf-8")
            (workspace / "CANARY_RESPONSE.txt").write_text(marker, encoding="utf-8")
            action = {"schema": "dcp_action_v1", "action": "finish", "payload": {}}
        elif not (workspace / ".dcp/observation.json").exists():
            if episode_id == "main":
                action = {
                    "schema": "dcp_action_v1",
                    "action": "web_fetch",
                    "payload": {
                        "schema": "dcp_web_request_v1",
                        "requests": [
                            {
                                "request_id": "known-doc",
                                "query": "public optimization manual",
                                "url": "https://docs.example/manual",
                            }
                        ],
                    },
                }
            else:
                action = {
                    "schema": "dcp_action_v1",
                    "action": "experiment",
                    "payload": {"candidate": 1},
                }
        else:
            phase = (workspace / "PHASE.txt").read_text(encoding="utf-8").strip()
            score = 0.95 if phase in {"main", "feedback_truthful"} else 0.20
            if phase in {"sham_reference", "sham_proposed"}:
                score = 0.70
            (workspace / "artifact.txt").write_text(f"score={score}\n", encoding="utf-8")
            action = {"schema": "dcp_action_v1", "action": "finish", "payload": {}}
        write_json(workspace / ".dcp/action.json", action)
        base = {
            "run_id": f"fake-{self.calls}",
            "returncode": 0,
            "timed_out": False,
            "started_at": "2026-01-01T00:00:00Z",
            "finished_at": "2026-01-01T00:00:01Z",
            "elapsed_seconds": 1.0,
            "requested_model": "fake-model-v1",
            "init_models": ("fake-model-v1",),
            "assistant_models": ("fake-model-v1",),
            "usage_models": ("fake-model-v1",),
            "declared_tools": ("Read", "Write", "Edit", "Glob", "Grep"),
            "used_tools": ("Read", "Write"),
            "event_count": 3,
            "assistant_event_count": 1,
            "result_event_count": 1,
            "result_text": "done",
            "reported_cost_usd": 0.0,
            "provider_session_id": f"session-{self.calls}",
            "assistant_message_ids": (f"message-{self.calls}",),
            "result_event_uuid": f"result-{self.calls}",
            "stdout_hash": hash_file(stdout),
            "stderr_hash": hash_file(stderr),
            "provider_receipt_hash": f"sha256:fake-receipt-{self.calls}",
            "identity_complete": True,
            "identity_ok": True,
            "interface_ok": True,
            "model_action_started": True,
            "infrastructure_invalid_preaction": False,
            "stdout_path": str(stdout),
            "stderr_path": str(stderr),
        }
        return AgentRunResult(**base)


class OneTransportFailureBackend(FakeBackend):
    def __init__(self) -> None:
        super().__init__()
        self.failed_once = False

    def run(self, *, workspace, prompt, record_dir, episode_id):
        if (
            not self.failed_once
            and episode_id.startswith("feedback-pair-0001-attempt-01-")
        ):
            del workspace, prompt
            self.failed_once = True
            self.calls += 1
            record_dir.mkdir(parents=True, exist_ok=True)
            stdout = record_dir / "claude_stream.jsonl"
            stderr = record_dir / "claude_stderr.log"
            stdout.write_text("", encoding="utf-8")
            stderr.write_text("transport unavailable\n", encoding="utf-8")
            return AgentRunResult(
                run_id=f"failed-{self.calls}",
                returncode=1,
                timed_out=False,
                started_at="2026-01-01T00:00:00Z",
                finished_at="2026-01-01T00:00:01Z",
                elapsed_seconds=1.0,
                requested_model="fake-model-v1",
                init_models=(),
                assistant_models=(),
                usage_models=(),
                declared_tools=(),
                used_tools=(),
                event_count=0,
                assistant_event_count=0,
                result_event_count=0,
                result_text="",
                reported_cost_usd=None,
                provider_session_id="",
                assistant_message_ids=(),
                result_event_uuid="",
                stdout_hash=hash_file(stdout),
                stderr_hash=hash_file(stderr),
                provider_receipt_hash=f"sha256:transport-{self.calls}",
                identity_complete=False,
                identity_ok=False,
                interface_ok=False,
                model_action_started=False,
                infrastructure_invalid_preaction=True,
                stdout_path=str(stdout),
                stderr_path=str(stderr),
            )
        return super().run(
            workspace=workspace,
            prompt=prompt,
            record_dir=record_dir,
            episode_id=episode_id,
        )


class SyntheticAdapter(BaseTaskAdapter):
    def audit_materials(self):
        return AuditMaterials(
            private_verifier_hash=hash_json(
                {"verifier": "synthetic-private-verifier-v1"}
            ),
            private_unit_manifest_hash=unit_manifest_hash(PRIVATE_UNITS),
            baseline_policy_hash=hash_json(
                {"baseline": "constant-0.20-v1"}
            ),
            truthful_feedback_policy_hash=hash_json(
                {"feedback": "truthful-scalar-v1"}
            ),
            neutral_feedback_policy_hash=hash_json(
                {"feedback": "neutral-placeholder-v1"}
            ),
            sham_reference_policy_hash=hash_json(
                {"feedback": "reference-null-v1"}
            ),
        )

    def registration(self, context):
        c = context.contracts
        return Registration(
            claim_id=context.config.claim_id,
            audit_family_id="synthetic-harness-calibration-family-v1",
            model_id="fake-model-v1",
            interface_hash=c["interface_hash"],
            task_family_profile="transparent-scalar-optimizer-v1",
            grade_requested="evidence",
            inference_scope="exhaustive_finite_set",
            ci_method="finite_set_exact",
            feedback_inference_scope="sampled_population",
            feedback_ci_method="paired_binary_exact",
            sham_inference_scope="sampled_population",
            sham_ci_method="paired_binary_exact",
            delta_min=0.10,
            kappa=0.5,
            m_max=200,
            min_n_ind=60,
            gate2_control_contract_hash=c["gate2_control_contract_hash"],
            challenge_distribution_hash=c["challenge_distribution_hash"],
            alpha_main=0.00001,
            alpha_score=0.00001,
            alpha_recovery=0.0475,
            alpha_adequacy=0.00005,
            alpha_evidence=0.0007,
            alpha_sham=0.0017,
            alpha_neutral=0.00001,
            alpha_total=0.05,
            delta_evidence=0.34,
            delta_sham=0.17,
            feedback_estimand="binary",
            feedback_utility_mapping="canonical_p_wrapper_v1",
            registered_n_feedback_pairs=context.config.audit.feedback_pairs,
            registered_n_sham_pairs=context.config.audit.sham_pairs,
            scaffold_hash=c["scaffold_hash"],
            feedback_schema_hash=c["feedback_schema_hash"],
            sham_operator_hash=c["sham_operator_hash"],
            utility_scale_id="utility:binary:v1",
            sham_calibration_id="synthetic-null-calibration-v1",
            gate3_checkpoint_scope="lineage_prefix",
            gate3_paired_arm_contract_hash=c["gate3_paired_arm_contract_hash"],
            gate3_truthful_arm_contract_hash=c[
                "gate3_truthful_arm_contract_hash"
            ],
            gate3_neutral_arm_contract_hash=c["gate3_neutral_arm_contract_hash"],
            gate3_neutral_recovery_contract_hash=c[
                "gate3_neutral_recovery_contract_hash"
            ],
            gate3_checkpoint_selection_rule_hash=c["selection_rule_hash"],
            gate3_resource_contract_hash=c["gate3_resource_contract_hash"],
            gate3_opportunity_contract_hash=c["gate3_opportunity_contract_hash"],
            gate3_branch_policy_hash=c["gate3_branch_policy_hash"],
            truthful_feedback_generator_hash=c[
                "truthful_feedback_generator_hash"
            ],
            neutral_sham_generator_hash=c["neutral_sham_generator_hash"],
            gate3_pair_randomization_distribution_hash=c[
                "gate3_pair_randomization_distribution_hash"
            ],
            sham_randomization_distribution_hash=c[
                "sham_randomization_distribution_hash"
            ],
            sham_paired_arm_contract_hash=c["sham_paired_arm_contract_hash"],
            sham_reference_arm_contract_hash=c[
                "sham_reference_arm_contract_hash"
            ],
            sham_proposed_arm_contract_hash=c["sham_proposed_arm_contract_hash"],
            reference_null_generator_hash=c["reference_null_generator_hash"],
            audit_slot_id=c["audit_slot_id"],
            audit_slot_reservation_receipt_hash=c[
                "audit_slot_reservation_receipt_hash"
            ],
        )

    def prepare_episode(self, context: EpisodeContext) -> None:
        (context.workspace / "PHASE.txt").write_text(
            context.phase.value + "\n", encoding="utf-8"
        )

    def prompt(self, context: EpisodeContext) -> str:
        return f"Optimize the transparent scalar objective for phase {context.phase.value}."

    def handle_experiment(self, context, payload):
        del payload
        if context.phase in {Phase.MAIN, Phase.FEEDBACK_TRUTHFUL}:
            return {"experiment_completed": True, "signal": "use score=0.95"}
        if context.phase in {Phase.SHAM_REFERENCE, Phase.SHAM_PROPOSED}:
            return {"experiment_completed": True, "signal": "null-calibration"}
        return {"experiment_completed": True, "signal": "neutral-placeholder"}

    @staticmethod
    def _score(context: EpisodeContext) -> float:
        text = (context.workspace / "artifact.txt").read_text(encoding="utf-8")
        return float(text.split("=", 1)[1])

    def evaluate(self, context):
        if context.phase == Phase.CHALLENGE:
            expected = int(context.task_options.get("challenger_episodes", 0))
            committed = list(
                (context.run_root / "episodes/challenge").glob(
                    "*/generation_record.json"
                )
            )
            assert len(committed) == expected
        if context.phase in {
            Phase.FEEDBACK_TRUTHFUL,
            Phase.FEEDBACK_NEUTRAL,
            Phase.SHAM_REFERENCE,
            Phase.SHAM_PROPOSED,
        }:
            expected = 2 * (
                int(context.task_options.get("feedback_pairs", 0))
                + int(context.task_options.get("sham_pairs", 0))
            )
            committed = list(
                (context.run_root / "episodes/gate3").glob(
                    "*/generation_record.json"
                )
            )
            max_extra = int(
                context.task_options.get("max_gate3_extra_branches", 0)
            )
            assert expected <= len(committed) <= expected + max_extra
        score = self._score(context)
        if context.is_sham_branch:
            return EpisodeEvaluation(
                outcome="artifact",
                validity="valid",
                artifact_path="artifact.txt",
                utility=1.0,
            )
        return EpisodeEvaluation(
            outcome="artifact",
            validity="valid",
            artifact_path="artifact.txt",
            per_unit=(score,) * len(PRIVATE_UNITS),
            unit_ids=PRIVATE_UNITS,
        )

    def baseline(self, main_context):
        path = main_context.workspace / "baseline.txt"
        path.write_text("score=0.20\n", encoding="utf-8")
        return EpisodeEvaluation(
            outcome="artifact",
            validity="valid",
            artifact_path="baseline.txt",
            per_unit=(0.20,) * len(PRIVATE_UNITS),
            unit_ids=PRIVATE_UNITS,
        )

    def select_checkpoint(self, main_episode):
        return 0

    def build_evidence(self, run: RunView) -> EvidencePackage:
        return assemble_evidence(
            run,
            AuditAttestations(
                iterative_lineage_eligible=True,
                lineage_dataflow_audit_pass=True,
                symmetric_verifier_pass=True,
                inference_assumptions_pass=True,
                feedback_inference_assumptions_pass=True,
                sham_inference_assumptions_pass=True,
                materials_readable=True,
                opportunity_floor_met=True,
                paired_contract_audit_pass=True,
                truthful_channel_audit_pass=True,
                neutral_channel_audit_pass=True,
                sham_channel_checks_pass=True,
                sham_freshness_pass=True,
                sham_operator_frozen_before_confirmatory=True,
                sham_development_confirmatory_disjoint=True,
                sham_development_manifest_hash=hash_json(
                    {"seeds": "development"}
                ),
            ),
        )

    @staticmethod
    def _branch(run: RunView, record, contract_key):
        ev = record["evaluation"]
        branch = BranchOutcome(
            outcome=RawAttemptOutcome(ev["outcome"]),
            utility=ev["utility"],
            validity=Validity(ev["validity"]),
            branch_id=record["episode_id"],
            artifact_hash=ev["artifact_hash"],
            execution_contract_hash=run.contracts[contract_key],
            prestart_contract_receipt_hash=record[
                "prestart_contract_receipt_hash"
            ],
            per_unit=ev["per_unit"] or None,
            unit_ids=ev["unit_ids"],
            infrastructure_outcome_independent=record[
                "infrastructure_invalid_preaction"
            ],
        )
        branch.verifier_result_hash = branch_result_hash(branch)
        return branch

    def _manual_evidence_oracle(self, run: RunView) -> EvidencePackage:
        c = run.contracts
        main = run.by_phase(Phase.MAIN)[0]
        main_ev = main["evaluation"]
        baseline_ev = json.loads((run.root / "main/baseline.json").read_text())
        astar = ArtifactScores(
            name="A*",
            per_unit=main_ev["per_unit"],
            validity=Validity(main_ev["validity"]),
            artifact_hash=main_ev["artifact_hash"],
            unit_ids=main_ev["unit_ids"],
        )
        baseline = ArtifactScores(
            name="baseline",
            per_unit=baseline_ev["per_unit"],
            validity=Validity(baseline_ev["validity"]),
            artifact_hash=baseline_ev["artifact_hash"],
            unit_ids=baseline_ev["unit_ids"],
        )
        gate1 = Gate1Evidence(astar=astar, baseline=baseline)
        controls = []
        for record in run.by_phase(Phase.CHALLENGE):
            ev = record["evaluation"]
            controls.append(
                ControlAttempt(
                    attempt_id=record["episode_id"],
                    outcome=RawAttemptOutcome(ev["outcome"]),
                    per_unit=ev["per_unit"],
                    validity=Validity(ev["validity"]),
                    artifact_hash=ev["artifact_hash"],
                    unit_ids=ev["unit_ids"],
                    stratum="matched",
                    scope_contract_hash=c["gate2_control_contract_hash"],
                    prestart_contract_receipt_hash=record[
                        "prestart_contract_receipt_hash"
                    ],
                    challenge_distribution_hash=c["challenge_distribution_hash"],
                    independent_draw_receipt_hash=record[
                        "independent_draw_receipt_hash"
                    ],
                    independent_unit_id=record["episode_id"],
                    independence_ok=True,
                    infrastructure_outcome_independent=False,
                )
            )
        challenge_summary = json.loads(
            (run.root / "challenge/summary.json").read_text()
        )
        adequacy = AdequacyEvidence(
            matched_model_present=True,
            materials_readable=True,
            opportunity_floor_met=True,
            health_audit_pass=True,
            positive_control_successes=challenge_summary[
                "positive_control_successes"
            ],
            positive_control_trials=challenge_summary[
                "positive_control_episodes"
            ],
            calibration_id="task-neutral-file-channel-v1",
        )
        adequacy.checks_manifest_hash = adequacy_evidence_hash(adequacy)
        gate2 = Gate2Evidence(controls=tuple(controls), adequacy=adequacy)

        feedback_records = {
            row["episode_id"]: row
            for row in run.episodes
            if row["phase"] in {
                Phase.FEEDBACK_TRUTHFUL.value,
                Phase.FEEDBACK_NEUTRAL.value,
            }
        }
        feedback_pairs = []
        for row in run.state["gate3_feedback_pairs"]:
            truthful = self._branch(
                run,
                feedback_records[row["branches"][Phase.FEEDBACK_TRUTHFUL.value]],
                "gate3_truthful_arm_contract_hash",
            )
            neutral = self._branch(
                run,
                feedback_records[row["branches"][Phase.FEEDBACK_NEUTRAL.value]],
                "gate3_neutral_arm_contract_hash",
            )
            feedback_pairs.append(
                FeedbackPair(
                    pair_id=row["pair_id"],
                    truthful=truthful,
                    neutral=neutral,
                    block_id=f"feedback-block-{row['slot']:04d}",
                    randomization_distribution_hash=c[
                        "gate3_pair_randomization_distribution_hash"
                    ],
                    randomization_draw_receipt_hash=row[
                        "randomization_draw_receipt_hash"
                    ],
                    assignment_frozen=True,
                    independence_ok=True,
                    replacement_of=row["replacement_of"],
                )
            )
        sham_records = {
            row["episode_id"]: row
            for row in run.episodes
            if row["phase"]
            in {Phase.SHAM_REFERENCE.value, Phase.SHAM_PROPOSED.value}
        }
        sham_pairs = []
        for row in run.state["gate3_sham_pairs"]:
            reference = self._branch(
                run,
                sham_records[row["branches"][Phase.SHAM_REFERENCE.value]],
                "sham_reference_arm_contract_hash",
            )
            proposed = self._branch(
                run,
                sham_records[row["branches"][Phase.SHAM_PROPOSED.value]],
                "sham_proposed_arm_contract_hash",
            )
            sham_pairs.append(
                ShamPair(
                    pair_id=row["pair_id"],
                    reference_null=reference,
                    proposed_sham=proposed,
                    block_id=f"sham-block-{row['slot']:04d}",
                    randomization_distribution_hash=c[
                        "sham_randomization_distribution_hash"
                    ],
                    randomization_draw_receipt_hash=row[
                        "randomization_draw_receipt_hash"
                    ],
                    assignment_frozen=True,
                    independence_ok=True,
                    replacement_of=row["replacement_of"],
                )
            )
        gate3_summary = json.loads((run.root / "gate3/summary.json").read_text())
        sham = ShamCalibration(
            pairs=tuple(sham_pairs),
            calibration_id="synthetic-null-calibration-v1",
            development_manifest_hash=hash_json({"seeds": "development"}),
            confirmatory_manifest_hash=sham_pairs_manifest_hash(sham_pairs),
            task_family_profile="transparent-scalar-optimizer-v1",
            model_id="fake-model-v1",
            interface_hash=run.contracts["interface_hash"],
            scaffold_hash=c["scaffold_hash"],
            feedback_schema_hash=c["feedback_schema_hash"],
            operator_hash=c["sham_operator_hash"],
            reference_null_generator_hash=c["reference_null_generator_hash"],
            utility_scale_id="utility:binary:v1",
            paired_arm_contract_hash=c["sham_paired_arm_contract_hash"],
            reference_arm_contract_hash=c["sham_reference_arm_contract_hash"],
            proposed_arm_contract_hash=c["sham_proposed_arm_contract_hash"],
            contract_preseal_receipt_hash=gate3_summary[
                "contract_preseal_receipt_hash"
            ],
            contract_sealed_before_branches_pass=True,
            contract_sealed_event_index=gate3_summary[
                "contract_preseal_event_index"
            ],
            first_branch_started_event_index=gate3_summary[
                "first_branch_started_event_index"
            ],
            channel_checks_pass=True,
            freshness_pass=True,
            operator_frozen_before_confirmatory=True,
            development_confirmatory_disjoint=True,
            all_started_pairs_disclosed=True,
            no_pair_replacements=True,
            started_pair_count=len(sham_pairs),
        )
        gate3 = Gate3Evidence(
            pairs=tuple(feedback_pairs),
            sham=sham,
            neutral_adequacy=adequacy,
            design_checks_pass=True,
            stopping_rule_pass=True,
            registered_pairs_complete=True,
            all_started_pairs_disclosed=True,
            no_pair_replacements=True,
            paired_contract_audit_pass=True,
            truthful_channel_audit_pass=True,
            neutral_channel_audit_pass=True,
            started_pair_count=len(feedback_pairs),
            checkpoint_scope="lineage_prefix",
            checkpoint_hash=json.loads((run.root / "main/summary.json").read_text())[
                "selected_checkpoint_hash"
            ],
            window_hash=c["gate3_resource_contract_hash"],
            feedback_pairs_manifest_hash=feedback_pairs_manifest_hash(feedback_pairs),
            paired_arm_contract_hash=c["gate3_paired_arm_contract_hash"],
            truthful_arm_contract_hash=c["gate3_truthful_arm_contract_hash"],
            neutral_arm_contract_hash=c["gate3_neutral_arm_contract_hash"],
            neutral_recovery_contract_hash=c[
                "gate3_neutral_recovery_contract_hash"
            ],
            truthful_feedback_generator_hash=c[
                "truthful_feedback_generator_hash"
            ],
            neutral_sham_generator_hash=c["neutral_sham_generator_hash"],
            contract_preseal_receipt_hash=gate3_summary[
                "contract_preseal_receipt_hash"
            ],
            contract_sealed_before_branches_pass=True,
            contract_sealed_event_index=gate3_summary[
                "contract_preseal_event_index"
            ],
            first_branch_started_event_index=gate3_summary[
                "first_branch_started_event_index"
            ],
            neutral_model_id="fake-model-v1",
            neutral_interface_hash=c["interface_hash"],
            neutral_resource_contract_hash=c["gate3_resource_contract_hash"],
            neutral_k_manifest_hash=c["k_manifest_hash"],
            neutral_e0_manifest_hash=c["e0_manifest_hash"],
            neutral_web_manifest_hash=run.web_manifest["snapshot_id"],
            neutral_opportunity_contract_hash=c[
                "gate3_opportunity_contract_hash"
            ],
            neutral_challenger_policy_hash=c["gate3_branch_policy_hash"],
            neutral_scope_audit_manifest_hash="pending",
            neutral_contract_audit_pass=True,
        )

        reg = run.registration
        gate3.neutral_scope_audit_manifest_hash = gate3_neutral_scope_manifest_hash(
            gate3, c["selection_rule_hash"]
        )
        integrity = IntegrityEvidence(
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
            astar_hash=astar.artifact_hash,
            baseline_hash=baseline.artifact_hash,
            verifier_hash=c["verifier_hash"],
            astar_results_hash=artifact_results_hash(astar),
            baseline_results_hash=artifact_results_hash(baseline),
            private_unit_manifest_hash=unit_manifest_hash(PRIVATE_UNITS),
            private_results_manifest_hash=private_results_manifest_hash(
                astar, baseline, c["verifier_hash"]
            ),
            p_hash=c["p_hash"],
            resource_contract_hash=c["resource_contract_hash"],
            selection_rule_hash=c["selection_rule_hash"],
            k_manifest_hash=c["k_manifest_hash"],
            e0_manifest_hash=c["e0_manifest_hash"],
            lineage_manifest_hash=main["episode_record_hash"],
            observed_web_manifest_hash=run.web_manifest["snapshot_id"],
            challenger_policy_hash=c["challenger_policy_hash"],
            opportunity_contract_hash=c["opportunity_contract_hash"],
            recovery_ledger_complete=True,
            recovery_ledger_manifest_hash=recovery_ledger_manifest_hash(
                controls, gate3
            ),
            gate2_recovery_ledger_manifest_hash=recovery_ledger_manifest_hash(
                controls
            ),
            gate3_neutral_scope_manifest_hash=gate3.neutral_scope_audit_manifest_hash,
            gate3_neutral_recovery_ledger_manifest_hash=(
                gate3_neutral_recovery_ledger_manifest_hash(gate3)
            ),
            gate3_contract_preseal_receipt_hash=gate3_summary[
                "contract_preseal_receipt_hash"
            ],
            sham_contract_preseal_receipt_hash=gate3_summary[
                "contract_preseal_receipt_hash"
            ],
            claim_family_manifest_hash=c["claim_family_manifest_hash"],
            alpha_ledger_receipt_hash=c["audit_slot_reservation_receipt_hash"],
            audit_slot_registry_entry_hash=c["audit_slot_registry_entry_hash"],
            human_assistance="none",
            attribution_subject="autonomous_agent",
            web_access_used=True,
            web_replay_scope="observed_request_response_frozen",
        )
        return EvidencePackage(reg, integrity, gate1, gate2, gate3)


class ReplacementAdapter(SyntheticAdapter):
    def registration(self, context):
        registration = super().registration(context)
        return replace(
            registration,
            m_max=72,
            min_n_ind=60,
            gate3_pair_replacement_policy=PAIR_REPLACEMENT_POLICY_TRANSPORT,
            max_feedback_pair_replacements=1,
            max_sham_pair_replacements=0,
            max_feedback_pair_infrastructure_rate=0.20,
        )


@pytest.fixture
def audit(tmp_path: Path):
    project = tmp_path / "project"
    workspace = project / "workspace"
    workspace.mkdir(parents=True)
    (workspace / "TASK.txt").write_text("Optimize a scalar.\n", encoding="utf-8")
    adapter_file = project / "placeholder.py"
    adapter_file.write_text("# injected adapter\n", encoding="utf-8")
    config_document = {
        "schema": "dcp_harness_config_v1",
        "claim_id": "synthetic-harness-e2e-v1",
        "source_workspace": "workspace",
        "task_adapter": "placeholder.py:unused",
        "task_options": {
            "challenger_episodes": 60,
            "feedback_pairs": 31,
            "sham_pairs": 42,
        },
        "agent": {
            "execution": "docker",
            "model": "fake-model-v1",
            "accepted_model_ids": ["fake-model-v1"],
            "container_image": "fake@sha256:test",
            "max_turns": 3,
        },
        "web": {
            "enabled": True,
            "allowed_hosts": ["docs.example"],
            "max_requests": 4,
        },
        "audit": {
            "grade": "evidence",
            "challenger_episodes": 60,
            "positive_control_episodes": 45,
            "feedback_pairs": 31,
            "sham_pairs": 42,
            "checkpoint_scope": "lineage_prefix",
        },
    }
    config_path = project / "dcp-harness.json"
    write_json(config_path, config_document)
    config = load_config(config_path)
    backend = FakeBackend()
    fetcher = FixtureFetcher(
        {
            "https://docs.example/manual": (
                "text/html; charset=utf-8",
                b"<html><script>ignore</script><body><h1>Public manual</h1><p>Known generic method.</p></body></html>",
            )
        }
    )
    harness = Harness(
        config,
        project / "run",
        backend=backend,
        adapter=SyntheticAdapter(),
        web_fetcher=fetcher,
    )
    return harness, backend


def test_full_three_gate_run_is_certified_and_replayable(audit):
    harness, backend = audit
    harness.capture()
    harness.challenge()
    harness.gate3()
    challenge_path = harness.root / "challenge/summary.json"
    challenge_summary = load_json_object(challenge_path)
    tampered = dict(challenge_summary)
    tampered["positive_control_successes"] -= 1
    write_json(challenge_path, tampered)
    with pytest.raises(HarnessError, match="challenge summary"):
        harness.finalize()
    write_json(challenge_path, challenge_summary)
    report = harness.finalize()
    assert report["verdict"]["core"] == "certified"
    assert report["verdict"]["evidence"] == "certified"
    assert report["kernel_replay_matches"] is True
    replay = verify_bundle(harness.root / "bundle")
    assert replay["ok"] is True
    assert replay["saved_verdict"] == replay["replayed_verdict"]
    assert backend.calls == 2 + 60 * 2 + 45 + 31 * 2 * 2 + 42 * 2 * 2
    # Every non-positive-control research episode uses one action plus finish.
    assert len(harness._episodes()) == 1 + 60 + 31 * 2 + 42 * 2
    assert harness.status()["ledger_valid"] is True
    second = harness.run_all()
    assert second == report
    assert backend.calls == 2 + 60 * 2 + 45 + 31 * 2 * 2 + 42 * 2 * 2


def test_gate3_resumes_from_receipts_and_completed_branches(audit, monkeypatch):
    harness, backend = audit
    harness.capture()
    harness.challenge()

    append = harness.ledger.append

    def stop_after_preseal(event_type, payload):
        event = append(event_type, payload)
        if event_type == "gate3_contracts_presealed":
            raise KeyboardInterrupt("stopped before the state file was updated")
        return event

    with monkeypatch.context() as patch:
        patch.setattr(harness.ledger, "append", stop_after_preseal)
        with pytest.raises(KeyboardInterrupt):
            harness.gate3()
    preseal = harness.ledger.events()[-1]
    assert preseal["event_type"] == "gate3_contracts_presealed"

    run_episode = harness._run_episode

    def stop_after_branch(**kwargs):
        run_episode(**kwargs)
        raise KeyboardInterrupt("stopped after a committed branch")

    with monkeypatch.context() as patch:
        patch.setattr(harness, "_run_episode", stop_after_branch)
        with pytest.raises(KeyboardInterrupt):
            harness.gate3()

    run_pair_family = harness._run_pair_family

    def stop_between_families(**kwargs):
        if kwargs["family"] == "sham":
            raise KeyboardInterrupt("stopped between pair families")
        return run_pair_family(**kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(harness, "_run_pair_family", stop_between_families)
        with pytest.raises(KeyboardInterrupt):
            harness.gate3()

    summary = harness.gate3()
    assert summary["contract_preseal_event_index"] == preseal["event_index"]
    assert summary["contract_preseal_receipt_hash"] == preseal["event_hash"]
    assert (
        summary["contract_preseal_event_index"]
        < summary["first_branch_started_event_index"]
    )
    gate3_events = [
        event for event in harness.ledger.events()
        if event["event_type"].startswith("gate3_")
    ]
    identities = [
        (event["event_type"], event["payload"].get("pair_id"),
         event["payload"].get("phase"))
        for event in gate3_events
    ]
    assert len(identities) == len(set(identities))
    report = harness.finalize()
    assert report["verdict"]["core"] == "certified"
    assert report["verdict"]["evidence"] == "certified"
    assert verify_bundle(harness.root / "bundle")["ok"] is True
    assert backend.calls == 2 + 60 * 2 + 45 + 31 * 2 * 2 + 42 * 2 * 2


def test_resumed_gate3_receipt_cannot_change_its_payload(audit):
    harness, _backend = audit
    payload = {"pair_id": "pair-1", "phase": "truthful", "slot": 0}
    event = harness._gate3_event("gate3_branch_prestarted", payload)
    assert harness._gate3_event("gate3_branch_prestarted", payload) == event
    count = len(harness.ledger.events())
    with pytest.raises(HarnessError, match="conflicting Gate-3 receipt"):
        harness._gate3_event(
            "gate3_branch_prestarted", {**payload, "slot": 1}
        )
    assert len(harness.ledger.events()) == count


def test_web_snapshot_replay_and_tamper_detection(audit):
    harness, _backend = audit
    harness.capture()
    valid, errors = validate_snapshot(harness.root / "web_snapshot")
    assert valid, errors
    replay = ReplayGateway(harness.root / "web_snapshot").replay(
        {
            "schema": "dcp_web_request_v1",
            "requests": [
                {
                    "request_id": "again",
                    "query": "different search phrasing",
                    "url": "https://docs.example/manual",
                }
            ],
        },
        batch_id="test-replay",
    )
    assert replay["live_network_used"] is False
    assert "Public manual" in replay["results"][0]["content_text"]
    object_path = next((harness.root / "web_snapshot/objects").glob("*.txt"))
    object_path.write_text("tampered\n", encoding="utf-8")
    valid, errors = validate_snapshot(harness.root / "web_snapshot")
    assert valid is False
    assert any("hash mismatch" in error for error in errors)


def test_event_chain_tamper_is_fail_closed(audit):
    harness, _backend = audit
    harness.capture()
    lines = (harness.root / "events.jsonl").read_text(encoding="utf-8").splitlines()
    item = json.loads(lines[1])
    item["payload"]["phase"] = "tampered"
    lines[1] = json.dumps(item, sort_keys=True)
    (harness.root / "events.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok, errors = EventLedger(harness.root / "events.jsonl").verify()
    assert ok is False
    assert errors
    with pytest.raises(HarnessError, match="ledger is invalid"):
        harness.challenge()


def test_privileged_web_packet_tamper_stops_before_challenge(audit):
    harness, backend = audit
    harness.capture()
    calls_after_capture = backend.calls
    path = harness.root / "web_snapshot/privileged_packet.json"
    packet = load_json_object(path)
    packet["documents"][0]["content_text"] = "injected lineage\n"
    body = dict(packet)
    body.pop("packet_hash")
    packet["packet_hash"] = hash_json(body)
    write_json(path, packet)
    with pytest.raises(HarnessError, match="captured run is invalid"):
        harness.challenge()
    assert backend.calls == calls_after_capture


def test_unknown_config_key_is_rejected(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    adapter = tmp_path / "adapter.py"
    adapter.write_text("# test\n", encoding="utf-8")
    path = tmp_path / "config.json"
    write_json(
        path,
        {
            "schema": "dcp_harness_config_v1",
            "claim_id": "claim",
            "source_workspace": "workspace",
            "task_adapter": "adapter.py:adapter",
            "silent_unknown": True,
        },
    )
    with pytest.raises(HarnessError, match="unknown keys"):
        load_config(path)


def test_init_template_stops_until_private_materials_are_sealed(tmp_path: Path):
    project = tmp_path / "generated"
    _init(project, force=False)
    config = load_config(project / "dcp-harness.json")
    with pytest.raises(HarnessError, match="seal task-specific audit materials"):
        Harness(config, project / "run", backend=FakeBackend())


def test_init_force_preserves_user_files_and_adds_missing_files(tmp_path: Path):
    project = tmp_path / "generated"
    _init(project, force=False)
    saved = {}
    for name in ("dcp-harness.json", "task_adapter.py", "workspace/README.txt"):
        content = f"user-owned {name}\n".encode()
        (project / name).write_bytes(content)
        saved[name] = content
    with pytest.raises(HarnessError, match="add missing files"):
        _init(project, force=False)
    _init(project, force=True)
    assert all((project / name).read_bytes() == data for name, data in saved.items())
    (project / "task_adapter.py").unlink()
    _init(project, force=True)
    assert "class TaskAdapter" in (project / "task_adapter.py").read_text()
    for name in ("dcp-harness.json", "workspace/README.txt"):
        assert (project / name).read_bytes() == saved[name]


def test_frozen_registration_tamper_stops_before_agent_call(audit):
    harness, backend = audit
    path = harness.root / "registration/kernel_registration.json"
    document = load_json_object(path)
    document["delta_min"] = 0.01
    write_json(path, document)
    with pytest.raises(HarnessError, match="registration was modified"):
        harness.capture()
    assert backend.calls == 0


def test_frozen_source_tamper_stops_before_agent_call(audit):
    harness, backend = audit
    path = harness.source_snapshot / "TASK.txt"
    path.chmod(0o600)
    path.write_text("changed after registration\n", encoding="utf-8")
    with pytest.raises(HarnessError, match="source workspace was modified"):
        harness.capture()
    assert backend.calls == 0


def test_preaction_transport_failure_replaces_whole_gate3_pair(tmp_path: Path):
    project = tmp_path / "replacement"
    workspace = project / "workspace"
    workspace.mkdir(parents=True)
    (workspace / "TASK.txt").write_text("Optimize a scalar.\n", encoding="utf-8")
    adapter_file = project / "placeholder.py"
    adapter_file.write_text("# injected adapter\n", encoding="utf-8")
    config_path = project / "dcp-harness.json"
    write_json(
        config_path,
        {
            "schema": "dcp_harness_config_v1",
            "claim_id": "replacement-calibration-v1",
            "source_workspace": "workspace",
            "task_adapter": "placeholder.py:unused",
            "task_options": {
                "challenger_episodes": 60,
                "feedback_pairs": 5,
                "sham_pairs": 5,
                "max_gate3_extra_branches": 1,
            },
            "agent": {
                "execution": "docker",
                "model": "fake-model-v1",
                "accepted_model_ids": ["fake-model-v1"],
                "container_image": "fake@sha256:test",
                "max_turns": 3,
            },
            "web": {
                "enabled": True,
                "allowed_hosts": ["docs.example"],
                "max_requests": 4,
            },
            "audit": {
                "grade": "evidence",
                "challenger_episodes": 60,
                "positive_control_episodes": 45,
                "feedback_pairs": 5,
                "sham_pairs": 5,
                "max_feedback_pair_replacements": 1,
                "max_sham_pair_replacements": 0,
                "checkpoint_scope": "lineage_prefix",
            },
        },
    )
    backend = OneTransportFailureBackend()
    harness = Harness(
        load_config(config_path),
        project / "run",
        backend=backend,
        adapter=ReplacementAdapter(),
        web_fetcher=FixtureFetcher(
            {
                "https://docs.example/manual": (
                    "text/plain; charset=utf-8",
                    b"Public generic method.\n",
                )
            }
        ),
    )
    report = harness.run_all()
    assert report["kernel_replay_matches"] is True
    pairs = load_json_object(harness.root / "gate3/summary.json")[
        "feedback_pairs"
    ]
    assert len(pairs) == 6
    failed, replacement = pairs[:2]
    assert failed["infrastructure_invalid_preaction"] is True
    assert failed["replacement_required"] is True
    assert replacement["replacement_of"] == failed["pair_id"]
    assert replacement["infrastructure_invalid_preaction"] is False
    assert report["verdict"]["core"] == "certified"
    assert report["verdict"]["evidence"] == "inconclusive"
    assert (
        report["verdict"]["evidence_inconclusive_class"]
        == "statistical_uncertainty"
    )
    assert verify_bundle(harness.root / "bundle")["ok"] is True
