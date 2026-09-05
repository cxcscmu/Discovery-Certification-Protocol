"""Resumable orchestration for capture, challenge, Gate 3, and finalization."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict
import fcntl
import hashlib
import hmac
import math
from pathlib import Path
import secrets
from typing import Any, Iterator

from dcp import evaluate
from dcp.bundle import verify_bundle, write_core_bundle, write_full_audit_bundle
from dcp.registration import (
    PAIR_REPLACEMENT_POLICY_NONE,
    PAIR_REPLACEMENT_POLICY_TRANSPORT,
    Registration,
    validate_registration,
)
from dcp.types import (
    ControlAttempt,
    RawAttemptOutcome,
)

from dcp_harness.actions import ACTION_PATH, OBSERVATION_PATH, instructions, read_action
from dcp_harness.adapter import (
    AuditMaterials,
    BaseTaskAdapter,
    EpisodeContext,
    EpisodeEvaluation,
    EvidencePackage,
    LoadedAdapter,
    Phase,
    RegistrationContext,
    RunView,
    load_adapter,
)
from dcp_harness.backend import AgentBackend, ClaudeCodeBackend
from dcp_harness.config import HarnessConfig
from dcp_harness.ledger import EventLedger
from dcp_harness.util import (
    HarnessError,
    hash_file,
    hash_json,
    load_json,
    load_json_object,
    safe_child,
    utc_now,
    write_json,
)
from dcp_harness.web import (
    CaptureGateway,
    Fetcher,
    ReplayGateway,
    WebPolicy,
    privileged_packet,
    validate_snapshot,
)
from dcp_harness.workspace import checkpoint, clone_workspace, diff_manifests, manifest


STATE_SCHEMA = "dcp_harness_state_v1"
EPISODE_SCHEMA = "dcp_harness_episode_v1"


class Harness:
    """One prospective DCP audit rooted in a content-addressed run directory."""

    def __init__(
        self,
        config: HarnessConfig,
        run_root: str | Path,
        *,
        backend: AgentBackend | None = None,
        adapter: BaseTaskAdapter | None = None,
        web_fetcher: Fetcher | None = None,
    ) -> None:
        self.config = config
        self.root = Path(run_root).expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.state_path = self.root / "state.json"
        self.ledger = EventLedger(self.root / "events.jsonl")
        self.web_fetcher = web_fetcher
        if adapter is None:
            self.loaded_adapter = load_adapter(config)
        else:
            try:
                materials = adapter.audit_materials()
            except Exception as exc:
                raise HarnessError(
                    "task adapter could not seal its audit materials: "
                    f"{type(exc).__name__}: {exc}"
                ) from exc
            if not isinstance(materials, AuditMaterials):
                raise HarnessError(
                    "task adapter audit_materials() must return AuditMaterials"
                )
            materials_document = asdict(materials)
            identity = adapter.adapter_identity()
            identity_document = {
                "schema": "dcp_task_adapter_identity_v1",
                "source_hash": hash_json(identity),
                "audit_materials": materials_document,
                "audit_materials_hash": hash_json(materials_document),
                **identity,
            }
            self.loaded_adapter = LoadedAdapter(
                adapter=adapter,
                locator="injected:test-or-embedded",
                source_path="injected",
                source_hash=hash_json(identity),
                identity_hash=hash_json(identity_document),
                audit_materials=materials,
                audit_materials_hash=hash_json(materials_document),
            )
        self.adapter = self.loaded_adapter.adapter
        self.backend = backend or ClaudeCodeBackend(config, run_root=self.root)
        self._initialize_or_validate()

    @contextmanager
    def _lock(self) -> Iterator[None]:
        path = self.root / "run.lock"
        with path.open("a+", encoding="utf-8") as handle:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise HarnessError("another dcp-harness process owns this run") from exc
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def _initialize_or_validate(self) -> None:
        if self.state_path.exists():
            state = self._state()
            expected = {
                "config_hash": self.config.config_hash,
                "adapter_identity_hash": self.loaded_adapter.identity_hash,
                "interface_hash": self.backend.interface_hash,
            }
            for key, value in expected.items():
                if state.get(key) != value:
                    raise HarnessError(f"existing run has a different {key}")
            ok, errors = self.ledger.verify()
            if not ok:
                raise HarnessError("run ledger is invalid: " + "; ".join(errors))
            self._assert_frozen_registration()
            return

        registration_dir = self.root / "registration"
        registration_dir.mkdir(exist_ok=True)
        source = self.config.resolve(self.config.source_workspace)
        if (
            source == self.root
            or source in self.root.parents
            or self.root in source.parents
        ):
            raise HarnessError(
                "source_workspace and run directory must be disjoint"
            )
        if (source / ".dcp").exists():
            raise HarnessError("source_workspace may not contain the reserved .dcp path")
        source_manifest = manifest(source)
        frozen_source = registration_dir / "source_workspace"
        checkpoint(source, frozen_source)
        write_json(registration_dir / "source_workspace.json", source_manifest)
        write_json(registration_dir / "config.json", self.config.public_dict())
        write_json(registration_dir / "agent_interface.json", self.backend.interface_identity)
        adapter_identity = {
            "schema": "dcp_task_adapter_identity_v1",
            "locator": self.loaded_adapter.locator,
            "source_path": self.loaded_adapter.source_path,
            "source_hash": self.loaded_adapter.source_hash,
            "identity_hash": self.loaded_adapter.identity_hash,
            "audit_materials": asdict(self.loaded_adapter.audit_materials),
            "audit_materials_hash": self.loaded_adapter.audit_materials_hash,
            **self.adapter.adapter_identity(),
        }
        write_json(registration_dir / "task_adapter.json", adapter_identity)
        nonce = secrets.token_hex(32)
        contracts = self._make_contracts(nonce, source_manifest)
        write_json(registration_dir / "contracts.json", contracts)
        registration_context = RegistrationContext(
            config=self.config,
            contracts=contracts,
            source_manifest=source_manifest,
            interface_hash=self.backend.interface_hash,
            adapter_identity_hash=self.loaded_adapter.identity_hash,
            audit_materials=self.loaded_adapter.audit_materials,
        )
        kernel_registration = self.adapter.registration(registration_context)
        if not isinstance(kernel_registration, Registration):
            raise HarnessError("task adapter registration() did not return Registration")
        binding_errors = self._registration_binding_errors(
            kernel_registration, contracts
        )
        registration_errors = validate_registration(kernel_registration)
        if binding_errors or registration_errors:
            raise HarnessError(
                "prospective kernel registration is invalid: "
                + "; ".join([*binding_errors, *registration_errors])
            )
        write_json(
            registration_dir / "kernel_registration.json",
            asdict(kernel_registration),
        )
        kernel_registration_hash = hash_json(asdict(kernel_registration))
        state = {
            "schema": STATE_SCHEMA,
            "run_id": "dcp-run-" + secrets.token_hex(10),
            "created_at": utc_now(),
            "claim_id": self.config.claim_id,
            "config_hash": self.config.config_hash,
            "adapter_identity_hash": self.loaded_adapter.identity_hash,
            "interface_hash": self.backend.interface_hash,
            "run_nonce": nonce,
            "kernel_registration_hash": kernel_registration_hash,
            "phases": {
                "capture": "pending",
                "challenge": "pending",
                "gate3": "pending" if self.config.audit.grade == "evidence" else "not_requested",
                "finalize": "pending",
            },
            "selected_checkpoint": None,
            "gate3_feedback_pairs": [],
            "gate3_sham_pairs": [],
        }
        write_json(self.state_path, state)
        registered = self.ledger.append(
            "audit_registered",
            {
                "run_id": state["run_id"],
                "claim_id": self.config.claim_id,
                "config_hash": self.config.config_hash,
                "source_manifest_hash": source_manifest["manifest_hash"],
                "adapter_identity_hash": self.loaded_adapter.identity_hash,
                "interface_hash": self.backend.interface_hash,
                "audit_slot_reservation_receipt_hash": contracts[
                    "audit_slot_reservation_receipt_hash"
                ],
                "kernel_registration_hash": kernel_registration_hash,
            },
        )
        state["registration_event_hash"] = registered["event_hash"]
        self._write_state(state)

    def _make_contracts(
        self, nonce: str, source_manifest: dict[str, Any]
    ) -> dict[str, Any]:
        def seal(label: str, value: object) -> str:
            return hash_json({"contract": label, "value": value})

        interface_hash = self.backend.interface_hash
        materials = self.loaded_adapter.audit_materials
        common = {
            "claim_id": self.config.claim_id,
            "model": self.config.agent.model,
            "interface_hash": interface_hash,
            "source_manifest_hash": source_manifest["manifest_hash"],
            "adapter_identity_hash": self.loaded_adapter.identity_hash,
        }
        resource = {
            **common,
            "max_budget_usd_per_session": self.config.agent.max_budget_usd,
            "timeout_seconds": self.config.agent.timeout_seconds,
            "memory_mb": self.config.agent.memory_mb,
            "cpus": self.config.agent.cpus,
        }
        opportunity = {
            "max_turns": self.config.agent.max_turns,
            "file_tools": ["Read", "Write", "Edit", "Glob", "Grep"],
            "action_channel": "dcp_action_v1",
        }
        challenger = {
            **common,
            "lineage": "withheld",
            "private_scores": "withheld_until_all_candidates_commit",
            "observed_web": "privileged_packet_plus_exact_replay",
            "episodes": self.config.audit.challenger_episodes,
            "opportunity": opportunity,
        }
        feedback_common = {
            **common,
            "checkpoint_scope": self.config.audit.checkpoint_scope,
            "web": "frozen_observed_url_replay",
            "opportunity": opportunity,
        }
        reservation = {
            "schema": "dcp_local_audit_slot_reservation_v1",
            "claim_id": self.config.claim_id,
            "run_nonce_commitment": hash_json({"nonce": nonce}),
            "grade": self.config.audit.grade,
            "counts": {
                "challenge": self.config.audit.challenger_episodes,
                "positive_control": self.config.audit.positive_control_episodes,
                "feedback_pairs": self.config.audit.feedback_pairs,
                "sham_pairs": self.config.audit.sham_pairs,
            },
        }
        contracts = {
            "schema": "dcp_harness_contract_set_v1",
            "model_id": self.config.agent.model,
            "interface_hash": interface_hash,
            "source_manifest_hash": source_manifest["manifest_hash"],
            "private_isolation_pass": bool(
                self.config.agent.execution == "docker"
                and self.backend.interface_identity.get(
                    "private_isolation_pass"
                )
                is True
            ),
            "k_manifest_hash": seal("K", source_manifest),
            "e0_manifest_hash": seal(
                "E0", {"source": source_manifest, "adapter": self.loaded_adapter.identity_hash}
            ),
            "p_hash": seal(
                "outcome",
                {
                    "adapter": self.loaded_adapter.identity_hash,
                    "private_units": materials.private_unit_manifest_hash,
                },
            ),
            "verifier_hash": materials.private_verifier_hash,
            "private_unit_manifest_hash": materials.private_unit_manifest_hash,
            "baseline_policy_hash": materials.baseline_policy_hash,
            "resource_contract_hash": seal("resource", resource),
            "opportunity_contract_hash": seal("opportunity", opportunity),
            "selection_rule_hash": seal(
                "checkpoint_selection",
                {
                    "adapter": self.loaded_adapter.identity_hash,
                    "scope": self.config.audit.checkpoint_scope,
                },
            ),
            "challenger_policy_hash": seal("challenger_policy", challenger),
            "gate2_control_contract_hash": seal("gate2_control", challenger),
            "challenge_distribution_hash": seal(
                "challenge_distribution",
                {"policy": challenger, "draws": "hmac_sha256_without_replacement_v1"},
            ),
            "scaffold_hash": seal("scaffold", common),
            "feedback_schema_hash": seal("feedback_schema", "dcp_observation_v1"),
            "neutral_sham_generator_hash": materials.neutral_feedback_policy_hash,
            "sham_operator_hash": materials.neutral_feedback_policy_hash,
            "truthful_feedback_generator_hash": materials.truthful_feedback_policy_hash,
            "reference_null_generator_hash": materials.sham_reference_policy_hash,
            "gate3_paired_arm_contract_hash": seal("gate3_common", feedback_common),
            "gate3_truthful_arm_contract_hash": seal(
                "gate3_truthful", {**feedback_common, "feedback": "truthful"}
            ),
            "gate3_neutral_arm_contract_hash": seal(
                "gate3_neutral", {**feedback_common, "feedback": "neutral_sham"}
            ),
            "gate3_neutral_recovery_contract_hash": seal(
                "gate3_neutral_recovery", feedback_common
            ),
            "gate3_resource_contract_hash": seal("gate3_resource", resource),
            "gate3_opportunity_contract_hash": seal("gate3_opportunity", opportunity),
            "gate3_branch_policy_hash": seal("gate3_policy", feedback_common),
            "gate3_pair_randomization_distribution_hash": seal(
                "feedback_pair_randomization", "hmac_sha256_order_v1"
            ),
            "sham_randomization_distribution_hash": seal(
                "sham_pair_randomization", "hmac_sha256_order_v1"
            ),
            "sham_paired_arm_contract_hash": seal("sham_common", feedback_common),
            "sham_reference_arm_contract_hash": seal(
                "sham_reference", {**feedback_common, "feedback": "reference_null"}
            ),
            "sham_proposed_arm_contract_hash": seal(
                "sham_proposed", {**feedback_common, "feedback": "neutral_sham"}
            ),
            "claim_family_manifest_hash": seal(
                "claim_family", {"claim_id": self.config.claim_id}
            ),
            "audit_slot_id": "slot-" + hash_json(reservation).split(":", 1)[1][:20],
            "audit_slot_reservation_receipt_hash": hash_json(reservation),
        }
        contracts["audit_slot_registry_entry_hash"] = seal(
            "local_registry_entry",
            {
                "slot": contracts["audit_slot_id"],
                "receipt": contracts["audit_slot_reservation_receipt_hash"],
            },
        )
        contracts["contract_set_hash"] = hash_json(contracts)
        return contracts

    @property
    def frozen_registration(self) -> Registration:
        document = load_json_object(
            self.root / "registration/kernel_registration.json"
        )
        try:
            return Registration(**document)
        except TypeError as exc:
            raise HarnessError("frozen kernel registration is malformed") from exc

    def _registration_binding_errors(
        self, reg: Registration, contracts: dict[str, Any]
    ) -> list[str]:
        errors: list[str] = []
        expected = {
            "claim_id": self.config.claim_id,
            "model_id": self.config.agent.model,
            "interface_hash": self.backend.interface_hash,
            "grade_requested": self.config.audit.grade,
            "gate2_control_contract_hash": contracts[
                "gate2_control_contract_hash"
            ],
            "challenge_distribution_hash": contracts[
                "challenge_distribution_hash"
            ],
            "audit_slot_id": contracts["audit_slot_id"],
            "audit_slot_reservation_receipt_hash": contracts[
                "audit_slot_reservation_receipt_hash"
            ],
        }
        if self.config.audit.grade == "evidence":
            expected.update(
                registered_n_feedback_pairs=self.config.audit.feedback_pairs,
                registered_n_sham_pairs=self.config.audit.sham_pairs,
                max_feedback_pair_replacements=self.config.audit.max_feedback_pair_replacements,
                max_sham_pair_replacements=self.config.audit.max_sham_pair_replacements,
                gate3_checkpoint_scope=self.config.audit.checkpoint_scope,
            )
            for field in (
                "scaffold_hash",
                "feedback_schema_hash",
                "sham_operator_hash",
                "neutral_sham_generator_hash",
                "truthful_feedback_generator_hash",
                "reference_null_generator_hash",
                "gate3_paired_arm_contract_hash",
                "gate3_truthful_arm_contract_hash",
                "gate3_neutral_arm_contract_hash",
                "gate3_neutral_recovery_contract_hash",
                "gate3_resource_contract_hash",
                "gate3_opportunity_contract_hash",
                "gate3_branch_policy_hash",
                "gate3_pair_randomization_distribution_hash",
                "sham_randomization_distribution_hash",
                "sham_paired_arm_contract_hash",
                "sham_reference_arm_contract_hash",
                "sham_proposed_arm_contract_hash",
            ):
                expected[field] = contracts[field]
            expected["gate3_checkpoint_selection_rule_hash"] = contracts[
                "selection_rule_hash"
            ]
            replacement_requested = bool(
                self.config.audit.max_feedback_pair_replacements
                or self.config.audit.max_sham_pair_replacements
            )
            expected["gate3_pair_replacement_policy"] = (
                PAIR_REPLACEMENT_POLICY_TRANSPORT
                if replacement_requested
                else PAIR_REPLACEMENT_POLICY_NONE
            )
        for field, expected_value in expected.items():
            if getattr(reg, field) != expected_value:
                errors.append(f"registration.{field} differs from the frozen harness")
        minimum_m_max = self.config.audit.challenger_episodes
        if self.config.audit.grade == "evidence":
            minimum_m_max += 2 * (
                self.config.audit.feedback_pairs
                + self.config.audit.max_feedback_pair_replacements
            )
        if reg.m_max < minimum_m_max:
            errors.append(
                f"registration.m_max={reg.m_max} is below the scheduled candidate cap "
                f"{minimum_m_max}"
            )
        if reg.min_n_ind > self.config.audit.challenger_episodes:
            errors.append(
                "registration.min_n_ind exceeds scheduled challenger episodes"
            )
        return errors

    def _state(self) -> dict[str, Any]:
        value = load_json_object(self.state_path)
        if value.get("schema") != STATE_SCHEMA:
            raise HarnessError("run state schema mismatch")
        return value

    def _write_state(self, state: dict[str, Any]) -> None:
        write_json(self.state_path, state)

    @property
    def contracts(self) -> dict[str, Any]:
        return load_json_object(self.root / "registration/contracts.json")

    @property
    def source_snapshot(self) -> Path:
        return self.root / "registration/source_workspace"

    def status(self) -> dict[str, Any]:
        state = self._state()
        ok, errors = self.ledger.verify()
        return {
            "run_id": state["run_id"],
            "claim_id": state["claim_id"],
            "phases": state["phases"],
            "selected_checkpoint": state.get("selected_checkpoint"),
            "event_count": len(self.ledger.events()),
            "event_head": self.ledger.head,
            "ledger_valid": ok,
            "ledger_errors": errors,
            "bundle": str(self.root / "bundle") if (self.root / "bundle").exists() else None,
        }

    def _assert_ledger_valid(self) -> None:
        ok, errors = self.ledger.verify()
        if not ok:
            raise HarnessError("run ledger is invalid: " + "; ".join(errors))
        self._assert_frozen_registration()

    def _assert_frozen_registration(self) -> None:
        config_document = load_json_object(self.root / "registration/config.json")
        if hash_json(config_document) != self.config.config_hash:
            raise HarnessError("frozen harness config was modified")
        interface_document = load_json_object(
            self.root / "registration/agent_interface.json"
        )
        if hash_json(interface_document) != self.backend.interface_hash:
            raise HarnessError("frozen agent interface was modified")
        adapter_document = load_json_object(
            self.root / "registration/task_adapter.json"
        )
        try:
            current_materials = self.adapter.audit_materials()
        except Exception as exc:
            raise HarnessError(
                "task adapter audit materials can no longer be sealed"
            ) from exc
        if not isinstance(current_materials, AuditMaterials):
            raise HarnessError("task adapter audit materials are malformed")
        current_materials_hash = hash_json(asdict(current_materials))
        if self.loaded_adapter.source_path != "injected":
            if hash_file(Path(self.loaded_adapter.source_path)) != self.loaded_adapter.source_hash:
                raise HarnessError("frozen task adapter source was modified")
        if (
            adapter_document.get("identity_hash")
            != self.loaded_adapter.identity_hash
            or adapter_document.get("source_hash") != self.loaded_adapter.source_hash
            or adapter_document.get("audit_materials_hash")
            != self.loaded_adapter.audit_materials_hash
            or adapter_document.get("audit_materials")
            != asdict(self.loaded_adapter.audit_materials)
            or current_materials_hash != self.loaded_adapter.audit_materials_hash
        ):
            raise HarnessError("frozen task adapter identity was modified")
        contracts = load_json_object(self.root / "registration/contracts.json")
        claimed_contract_hash = contracts.get("contract_set_hash")
        contract_body = dict(contracts)
        contract_body.pop("contract_set_hash", None)
        if claimed_contract_hash != hash_json(contract_body):
            raise HarnessError("frozen contract set was modified")
        source = load_json_object(self.root / "registration/source_workspace.json")
        if manifest(self.source_snapshot) != source:
            raise HarnessError("frozen source workspace was modified")
        kernel_registration_document = load_json_object(
            self.root / "registration/kernel_registration.json"
        )
        kernel_registration_hash = hash_json(kernel_registration_document)
        state = self._state()
        if state.get("kernel_registration_hash") != kernel_registration_hash:
            raise HarnessError("frozen kernel registration was modified")
        try:
            frozen_reg = Registration(**kernel_registration_document)
        except TypeError as exc:
            raise HarnessError("frozen kernel registration is malformed") from exc
        registration_errors = [
            *self._registration_binding_errors(frozen_reg, contracts),
            *validate_registration(frozen_reg),
        ]
        if registration_errors:
            raise HarnessError(
                "frozen kernel registration is invalid: "
                + "; ".join(registration_errors)
            )
        events = self.ledger.events()
        if not events or events[0].get("event_type") != "audit_registered":
            raise HarnessError("audit registration event is missing")
        payload = events[0].get("payload")
        if not isinstance(payload, dict):
            raise HarnessError("audit registration event is malformed")
        expected = {
            "config_hash": self.config.config_hash,
            "source_manifest_hash": source.get("manifest_hash"),
            "adapter_identity_hash": self.loaded_adapter.identity_hash,
            "interface_hash": self.backend.interface_hash,
            "audit_slot_reservation_receipt_hash": contracts.get(
                "audit_slot_reservation_receipt_hash"
            ),
            "kernel_registration_hash": kernel_registration_hash,
        }
        for key, value in expected.items():
            if payload.get(key) != value:
                raise HarnessError(f"registration event does not bind {key}")

    def run_all(self) -> dict[str, Any]:
        self.capture()
        self.challenge()
        if self.config.audit.grade == "evidence":
            self.gate3()
        return self.finalize()

    def capture(self) -> dict[str, Any]:
        with self._lock():
            self._assert_ledger_valid()
            state = self._state()
            if state["phases"]["capture"] == "complete":
                self._assert_capture_sealed()
                return load_json_object(self.root / "main/summary.json")
            if state["phases"]["capture"] not in {"pending", "running"}:
                raise HarnessError("capture phase is not runnable")
            state["phases"]["capture"] = "running"
            self._write_state(state)
            self.ledger.append("phase_started", {"phase": "capture"})
            gateway = CaptureGateway(
                self.root / "web_snapshot",
                WebPolicy.from_config(self.config.web),
                self.web_fetcher,
            )
            main = self._run_episode(
                phase=Phase.MAIN,
                episode_id="main",
                ordinal=0,
                base_workspace=self.source_snapshot,
                web_capture=gateway,
            )
            main_context = self._context(
                Phase.MAIN, "main", 0, self.root / "episodes/main/main"
            )
            baseline = self._normalize_evaluation(
                self.adapter.baseline(main_context), main_context.workspace, "baseline"
            )
            write_json(self.root / "main/baseline.json", baseline)
            web_manifest = gateway.finalize()
            packet = privileged_packet(self.root / "web_snapshot")
            write_json(self.root / "web_snapshot/privileged_packet.json", packet)
            selected = self.adapter.select_checkpoint(main)
            checkpoints = main.get("checkpoints", [])
            if not isinstance(selected, int) or isinstance(selected, bool):
                raise HarnessError("task adapter returned a non-integer checkpoint")
            if selected < 0 or selected >= len(checkpoints):
                raise HarnessError("task adapter selected a checkpoint outside the main run")
            selected_row = checkpoints[selected]
            summary = {
                "schema": "dcp_main_capture_summary_v1",
                "episode_id": "main",
                "episode_record_hash": main["episode_record_hash"],
                "baseline": baseline,
                "baseline_evaluation_hash": hash_json(baseline),
                "selected_checkpoint": selected,
                "selected_checkpoint_hash": selected_row["manifest_hash"],
                "selected_checkpoint_path": selected_row["path"],
                "web_snapshot_id": web_manifest["snapshot_id"],
                "web_privileged_packet_hash": packet["packet_hash"],
            }
            write_json(self.root / "main/summary.json", summary)
            state = self._state()
            state["selected_checkpoint"] = selected
            state["phases"]["capture"] = "complete"
            self._write_state(state)
            self.ledger.append(
                "phase_completed",
                {
                    "phase": "capture",
                    "main_record_hash": main["episode_record_hash"],
                    "baseline_evaluation_hash": hash_json(baseline),
                    "selected_checkpoint_hash": selected_row["manifest_hash"],
                    "web_snapshot_id": web_manifest["snapshot_id"],
                    "web_privileged_packet_hash": packet["packet_hash"],
                },
            )
            return summary

    def challenge(self) -> dict[str, Any]:
        with self._lock():
            self._assert_ledger_valid()
            state = self._state()
            if state["phases"]["capture"] != "complete":
                raise HarnessError("capture must complete before challenge")
            self._assert_capture_sealed()
            summary_path = self.root / "challenge/summary.json"
            if state["phases"]["challenge"] == "complete":
                return load_json_object(summary_path)
            state["phases"]["challenge"] = "running"
            self._write_state(state)
            self.ledger.append("phase_started", {"phase": "challenge"})
            packet = load_json_object(self.root / "web_snapshot/privileged_packet.json")
            challenge_records: list[dict[str, Any]] = []
            for index in range(self.config.audit.challenger_episodes):
                episode_id = f"challenge-{index + 1:04d}"
                challenge_records.append(
                    self._run_episode(
                        phase=Phase.CHALLENGE,
                        episode_id=episode_id,
                        ordinal=index,
                        base_workspace=self.source_snapshot,
                        privileged_web=packet,
                        web_replay=ReplayGateway(self.root / "web_snapshot"),
                        defer_evaluation=True,
                    )
                )
            # Freeze every candidate before opening the private verifier. The
            # adapter therefore cannot use an earlier private score to alter a
            # later challenger prompt or candidate-selection opportunity.
            challenge_records = [
                self._score_deferred_episode(row["episode_id"])
                for row in challenge_records
            ]
            positive_records = [
                self._run_positive_control(index)
                for index in range(self.config.audit.positive_control_episodes)
            ]
            summary = {
                "schema": "dcp_challenge_summary_v1",
                "challenger_episodes": len(challenge_records),
                "challenger_record_hashes": [
                    row["episode_record_hash"] for row in challenge_records
                ],
                "positive_control_episodes": len(positive_records),
                "positive_control_successes": sum(
                    bool(row["success"]) for row in positive_records
                ),
                "positive_control_record_hashes": [
                    row["record_hash"] for row in positive_records
                ],
            }
            write_json(summary_path, summary)
            state = self._state()
            state["phases"]["challenge"] = "complete"
            self._write_state(state)
            self.ledger.append(
                "phase_completed",
                {"phase": "challenge", "summary_hash": hash_json(summary)},
            )
            return summary

    def gate3(self) -> dict[str, Any]:
        with self._lock():
            self._assert_ledger_valid()
            if self.config.audit.grade != "evidence":
                raise HarnessError("Gate 3 was not requested")
            state = self._state()
            if state["phases"]["challenge"] != "complete":
                raise HarnessError("challenge must complete before Gate 3")
            self._assert_capture_sealed()
            summary_path = self.root / "gate3/summary.json"
            if state["phases"]["gate3"] == "complete":
                return load_json_object(summary_path)
            state["phases"]["gate3"] = "running"
            self._write_state(state)
            main = load_json_object(self.root / "main/summary.json")
            preseal = self._gate3_event(
                "gate3_contracts_presealed",
                {
                    "checkpoint_hash": main["selected_checkpoint_hash"],
                    "paired_contract_hash": self.contracts[
                        "gate3_paired_arm_contract_hash"
                    ],
                    "sham_contract_hash": self.contracts[
                        "sham_paired_arm_contract_hash"
                    ],
                },
            )
            state = self._state()
            state["gate3_contract_preseal_event_index"] = preseal["event_index"]
            state["gate3_contract_preseal_receipt_hash"] = preseal["event_hash"]
            state["sham_contract_preseal_event_index"] = preseal["event_index"]
            state["sham_contract_preseal_receipt_hash"] = preseal["event_hash"]
            self._write_state(state)
            self.ledger.append("phase_started", {"phase": "gate3"})
            checkpoint_root = safe_child(self.root, main["selected_checkpoint_path"])
            feedback_pairs = self._run_pair_family(
                family="feedback",
                slots=self.config.audit.feedback_pairs,
                phases=(Phase.FEEDBACK_TRUTHFUL, Phase.FEEDBACK_NEUTRAL),
                max_replacements=self.config.audit.max_feedback_pair_replacements,
                base_workspace=checkpoint_root,
            )
            sham_pairs = self._run_pair_family(
                family="sham",
                slots=self.config.audit.sham_pairs,
                phases=(Phase.SHAM_REFERENCE, Phase.SHAM_PROPOSED),
                max_replacements=self.config.audit.max_sham_pair_replacements,
                base_workspace=checkpoint_root,
            )
            # Fixed-N Gate-3 branches are all committed before any private
            # outcome is opened. Infrastructure replacement decisions above
            # use only pre-action transport receipts, never task scores.
            self._score_all_pending_gate3()
            summary = {
                "schema": "dcp_gate3_summary_v1",
                "contract_preseal_event_index": preseal["event_index"],
                "contract_preseal_receipt_hash": preseal["event_hash"],
                "first_branch_started_event_index": min(
                    row["first_branch_started_event_index"]
                    for row in [*feedback_pairs, *sham_pairs]
                ),
                "feedback_pairs": feedback_pairs,
                "sham_pairs": sham_pairs,
            }
            write_json(summary_path, summary)
            state = self._state()
            state["gate3_feedback_pairs"] = feedback_pairs
            state["gate3_sham_pairs"] = sham_pairs
            state["phases"]["gate3"] = "complete"
            self._write_state(state)
            self.ledger.append(
                "phase_completed", {"phase": "gate3", "summary_hash": hash_json(summary)}
            )
            return summary

    def _gate3_event(
        self, event_type: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Reuse an existing receipt when resuming the same Gate-3 step."""

        matches = [
            event
            for event in self.ledger.events()
            if event["event_type"] == event_type
            and all(
                event["payload"].get(key) == payload.get(key)
                for key in ("pair_id", "phase")
            )
        ]
        if matches:
            if len(matches) != 1 or matches[0]["payload"] != payload:
                raise HarnessError(f"conflicting Gate-3 receipt: {event_type}")
            return matches[0]
        return self.ledger.append(event_type, payload)

    def _run_pair_family(
        self,
        *,
        family: str,
        slots: int,
        phases: tuple[Phase, Phase],
        max_replacements: int,
        base_workspace: Path,
    ) -> list[dict[str, Any]]:
        existing_path = self.root / f"gate3/{family}_pairs.json"
        existing: list[dict[str, Any]] = []
        if existing_path.exists():
            loaded = load_json(existing_path)
            if not isinstance(loaded, list):
                raise HarnessError(f"{family} pair ledger is malformed")
            existing = loaded
        by_slot: dict[int, list[dict[str, Any]]] = {}
        for row in existing:
            by_slot.setdefault(int(row["slot"]), []).append(row)
        for slot in range(slots):
            attempts = by_slot.setdefault(slot, [])
            if attempts and not attempts[-1].get("replacement_required"):
                continue
            replacement_of = attempts[-1]["pair_id"] if attempts else ""
            while True:
                attempt = len(attempts)
                pair_id = f"{family}-pair-{slot + 1:04d}-attempt-{attempt + 1:02d}"
                order = list(phases)
                if self._draw_bit(f"{pair_id}:order"):
                    order.reverse()
                draw_receipt = self._draw_receipt(f"{pair_id}:order")
                randomized_event = self._gate3_event(
                    "gate3_pair_randomized",
                    {
                        "family": family,
                        "slot": slot,
                        "pair_id": pair_id,
                        "replacement_of": replacement_of,
                        "branch_order": [phase.value for phase in order],
                        "randomization_draw_receipt_hash": draw_receipt,
                    },
                )
                branch_prestarts: dict[str, dict[str, Any]] = {}
                for phase in phases:
                    sealed = self._gate3_event(
                        "gate3_branch_prestarted",
                        {
                            "family": family,
                            "slot": slot,
                            "pair_id": pair_id,
                            "phase": phase.value,
                            "replacement_of": replacement_of,
                            "execution_contract_hash": self._phase_contract_hash(
                                phase
                            ),
                            "randomization_event_hash": randomized_event[
                                "event_hash"
                            ],
                            "randomization_draw_receipt_hash": draw_receipt,
                        },
                    )
                    branch_prestarts[phase.value] = {
                        "event_index": sealed["event_index"],
                        "receipt_hash": sealed["event_hash"],
                        "independent_draw_receipt_hash": draw_receipt,
                    }
                branch_records: dict[str, str | None] = {phase.value: None for phase in phases}
                infrastructure_preaction = False
                first_execution_event_index: int | None = None
                for phase in order:
                    episode_id = f"{pair_id}-{phase.value}"
                    execution_started = self._gate3_event(
                        "gate3_branch_execution_started",
                        {
                            "family": family,
                            "pair_id": pair_id,
                            "phase": phase.value,
                            "branch_prestart_receipt_hash": branch_prestarts[
                                phase.value
                            ]["receipt_hash"],
                        },
                    )
                    if first_execution_event_index is None:
                        first_execution_event_index = execution_started[
                            "event_index"
                        ]
                    record = self._run_episode(
                        phase=phase,
                        episode_id=episode_id,
                        ordinal=slot,
                        pair_id=pair_id,
                        replacement_of=replacement_of,
                        base_workspace=base_workspace,
                        web_replay=ReplayGateway(self.root / "web_snapshot"),
                        defer_evaluation=True,
                        prestart_override=branch_prestarts[phase.value],
                    )
                    branch_records[phase.value] = record["episode_id"]
                    if record.get("infrastructure_invalid_preaction") is True:
                        infrastructure_preaction = True
                        break
                replacement_allowed = infrastructure_preaction and attempt < max_replacements
                pair_record = {
                    "schema": "dcp_gate3_pair_record_v1",
                    "family": family,
                    "slot": slot,
                    "pair_id": pair_id,
                    "replacement_of": replacement_of,
                    "branch_order": [phase.value for phase in order],
                    "branches": branch_records,
                    "branch_prestarts": branch_prestarts,
                    "randomization_draw_receipt_hash": draw_receipt,
                    "first_branch_started_event_index": first_execution_event_index,
                    "infrastructure_invalid_preaction": infrastructure_preaction,
                    "replacement_required": replacement_allowed,
                }
                pair_record["pair_record_hash"] = hash_json(pair_record)
                attempts.append(pair_record)
                existing.append(pair_record)
                write_json(existing_path, existing)
                if replacement_allowed:
                    replacement_of = pair_id
                    continue
                break
        return existing

    def _draw_receipt(self, label: str) -> str:
        key = bytes.fromhex(self._state()["run_nonce"])
        return "sha256:" + hmac.new(key, label.encode("utf-8"), hashlib.sha256).hexdigest()

    def _draw_bit(self, label: str) -> int:
        return int(self._draw_receipt(label)[-1], 16) & 1

    def _context(
        self,
        phase: Phase,
        episode_id: str,
        ordinal: int,
        episode_dir: Path,
        *,
        pair_id: str = "",
        replacement_of: str = "",
    ) -> EpisodeContext:
        return EpisodeContext(
            claim_id=self.config.claim_id,
            episode_id=episode_id,
            phase=phase,
            workspace=episode_dir / "workspace",
            record_dir=episode_dir,
            run_root=self.root,
            ordinal=ordinal,
            pair_id=pair_id,
            replacement_of=replacement_of,
            task_options=self.config.task_options,
        )

    def _phase_contract_hash(self, phase: Phase) -> str:
        key = {
            Phase.MAIN: "resource_contract_hash",
            Phase.CHALLENGE: "gate2_control_contract_hash",
            Phase.FEEDBACK_TRUTHFUL: "gate3_truthful_arm_contract_hash",
            Phase.FEEDBACK_NEUTRAL: "gate3_neutral_arm_contract_hash",
            Phase.SHAM_REFERENCE: "sham_reference_arm_contract_hash",
            Phase.SHAM_PROPOSED: "sham_proposed_arm_contract_hash",
            Phase.POSITIVE_CONTROL: "resource_contract_hash",
        }[phase]
        return str(self.contracts[key])

    def _episode_dir(self, phase: Phase, episode_id: str) -> Path:
        group = (
            "main"
            if phase == Phase.MAIN
            else "challenge"
            if phase == Phase.CHALLENGE
            else "gate3"
        )
        return self.root / "episodes" / group / episode_id

    def _run_episode(
        self,
        *,
        phase: Phase,
        episode_id: str,
        ordinal: int,
        base_workspace: Path,
        pair_id: str = "",
        replacement_of: str = "",
        privileged_web: dict[str, Any] | None = None,
        web_capture: CaptureGateway | None = None,
        web_replay: ReplayGateway | None = None,
        defer_evaluation: bool = False,
        prestart_override: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        episode_dir = self._episode_dir(phase, episode_id)
        record_path = episode_dir / "record.json"
        if record_path.exists():
            return load_json_object(record_path)
        generation_path = episode_dir / "generation_record.json"
        if generation_path.exists():
            return load_json_object(generation_path)
        workspace = episode_dir / "workspace"
        context = self._context(
            phase,
            episode_id,
            ordinal,
            episode_dir,
            pair_id=pair_id,
            replacement_of=replacement_of,
        )
        if not workspace.exists():
            clone_workspace(base_workspace, workspace)
            (workspace / ".dcp").mkdir(exist_ok=True)
            self.adapter.prepare_episode(context)
            if privileged_web is not None:
                write_json(workspace / "WEB_PRIVILEGED.json", privileged_web)
            initial_manifest = manifest(workspace)
            write_json(episode_dir / "initial_manifest.json", initial_manifest)
            checkpoint_zero = episode_dir / "checkpoints/000"
            cp_manifest = checkpoint(workspace, checkpoint_zero)
            write_json(episode_dir / "checkpoints/000.json", cp_manifest)
        else:
            initial_manifest = load_json_object(episode_dir / "initial_manifest.json")
        instruction_text = instructions(
            live_web=web_capture is not None and self.config.web.enabled,
            replay_web=web_replay is not None,
        )
        (workspace / ".dcp/instructions.md").write_text(
            instruction_text, encoding="utf-8"
        )
        prestart_path = episode_dir / "prestart.json"
        if prestart_path.exists():
            prestart = load_json_object(prestart_path)
            if prestart_override is not None and prestart != prestart_override:
                raise HarnessError(
                    f"episode {episode_id} prestart receipt differs from its pair seal"
                )
        elif prestart_override is not None:
            prestart = dict(prestart_override)
            required = {
                "event_index",
                "receipt_hash",
                "independent_draw_receipt_hash",
            }
            if set(prestart) != required:
                raise HarnessError("Gate-3 branch prestart override is malformed")
            write_json(prestart_path, prestart)
        else:
            event = self.ledger.append(
                "episode_prestarted",
                {
                    "episode_id": episode_id,
                    "phase": phase.value,
                    "ordinal": ordinal,
                    "pair_id": pair_id,
                    "replacement_of": replacement_of,
                    "execution_contract_hash": self._phase_contract_hash(phase),
                    "independent_draw_receipt_hash": self._draw_receipt(
                        f"episode:{episode_id}"
                    ),
                    "initial_manifest_hash": initial_manifest["manifest_hash"],
                },
            )
            prestart = {
                "event_index": event["event_index"],
                "receipt_hash": event["event_hash"],
                "independent_draw_receipt_hash": self._draw_receipt(
                    f"episode:{episode_id}"
                ),
            }
            write_json(prestart_path, prestart)

        turns: list[dict[str, Any]] = []
        turns_path = episode_dir / "turns.json"
        if turns_path.exists():
            loaded_turns = load_json(turns_path)
            if not isinstance(loaded_turns, list):
                raise HarnessError(f"episode {episode_id} turns ledger is malformed")
            turns = loaded_turns
        finished = bool(turns and turns[-1].get("action") == "finish")
        forced_outcome: str | None = None
        infrastructure_preaction = False
        while not finished and len(turns) < self.config.agent.max_turns:
            turn_index = len(turns)
            turn_dir = episode_dir / "turns" / f"{turn_index + 1:03d}"
            if turn_dir.exists() and not (turn_dir / "turn.json").exists():
                forced_outcome = "unresolved"
                break
            turn_dir.mkdir(parents=True, exist_ok=True)
            action_path = workspace / ACTION_PATH
            action_path.unlink(missing_ok=True)
            protected_channel = self._channel_manifest(workspace)
            before = manifest(workspace)
            task_prompt = self.adapter.prompt(context)
            prompt = (
                instruction_text
                + "\n\n# Registered task\n\n"
                + task_prompt
                + (
                    "\n\nContinue from the latest `.dcp/observation.json` and commit exactly one next action."
                    if turns
                    else "\n\nCommit exactly one first action."
                )
            )
            write_json(
                turn_dir / "prompt_receipt.json",
                {"prompt_hash": hash_json({"prompt": prompt}), "turn": turn_index + 1},
            )
            (turn_dir / "prompt.txt").write_text(prompt, encoding="utf-8")
            agent_result = self.backend.run(
                workspace=workspace,
                prompt=prompt,
                record_dir=turn_dir,
                episode_id=episode_id,
            )
            after = manifest(workspace)
            difference = diff_manifests(before, after)
            turn: dict[str, Any] = {
                "turn": turn_index + 1,
                "prompt_hash": hash_json({"prompt": prompt}),
                "agent": asdict(agent_result),
                "workspace_before": before["manifest_hash"],
                "workspace_after": after["manifest_hash"],
                "workspace_diff": difference,
                "action": None,
                "action_hash": None,
                "observation_hash": None,
            }
            channel_ok, channel_errors = self._validate_channel_after_agent(
                workspace, protected_channel
            )
            if not channel_ok:
                forced_outcome = "execution_contract_violation"
                turn["channel_errors"] = channel_errors
            elif agent_result.infrastructure_invalid_preaction:
                forced_outcome = "infrastructure_invalid"
                infrastructure_preaction = True
            elif not agent_result.identity_ok or not agent_result.interface_ok:
                forced_outcome = "execution_contract_violation"
            elif agent_result.returncode != 0 or agent_result.timed_out:
                forced_outcome = "model_failure"
            else:
                try:
                    action = read_action(workspace)
                    turn["action"] = action.kind
                    turn["action_hash"] = hash_json(action.raw)
                    write_json(turn_dir / "action.json", action.raw)
                    if action.kind == "finish":
                        finished = True
                    else:
                        observation = self._handle_action(
                            context,
                            action.kind,
                            action.payload,
                            turn_index,
                            web_capture=web_capture,
                            web_replay=web_replay,
                        )
                        observation_document = {
                            "schema": "dcp_observation_v1",
                            "episode_id": episode_id,
                            "turn": turn_index + 1,
                            "action_hash": turn["action_hash"],
                            "observation": observation,
                        }
                        observation_document["observation_hash"] = hash_json(
                            observation_document
                        )
                        write_json(workspace / OBSERVATION_PATH, observation_document)
                        write_json(turn_dir / "observation.json", observation_document)
                        turn["observation_hash"] = observation_document[
                            "observation_hash"
                        ]
                except HarnessError as exc:
                    forced_outcome = "execution_contract_violation"
                    turn["action_error"] = f"HarnessError: {exc}"
                except Exception as exc:
                    forced_outcome = "unresolved"
                    turn["action_error"] = f"{type(exc).__name__}: {exc}"
            turn["turn_record_hash"] = hash_json(turn)
            write_json(turn_dir / "turn.json", turn)
            turns.append(turn)
            write_json(turns_path, turns)
            action_path.unlink(missing_ok=True)
            checkpoint_path = episode_dir / "checkpoints" / f"{turn_index + 1:03d}"
            cp_manifest = checkpoint(workspace, checkpoint_path)
            write_json(
                episode_dir / "checkpoints" / f"{turn_index + 1:03d}.json",
                cp_manifest,
            )
            if forced_outcome is not None:
                break
        if not finished and forced_outcome is None:
            forced_outcome = "model_failure"

        if defer_evaluation:
            evaluation = None
        elif forced_outcome is None:
            try:
                evaluation = self._normalize_evaluation(
                    self.adapter.evaluate(context), workspace, episode_id
                )
            except Exception as exc:
                evaluation = self._empty_evaluation(
                    "unresolved", f"private verifier failed: {type(exc).__name__}: {exc}"
                )
        else:
            evaluation = self._empty_evaluation(
                forced_outcome, "episode did not reach a privately evaluable commit"
            )
        checkpoints: list[dict[str, Any]] = []
        checkpoint_dir = episode_dir / "checkpoints"
        for manifest_path in sorted(checkpoint_dir.glob("*.json")):
            cp = load_json_object(manifest_path)
            checkpoints.append(
                {
                    "ordinal": int(manifest_path.stem),
                    "path": (checkpoint_dir / manifest_path.stem).relative_to(
                        self.root
                    ).as_posix(),
                    "manifest_hash": cp["manifest_hash"],
                }
            )
        record: dict[str, Any] = {
            "schema": (
                "dcp_harness_generation_v1" if defer_evaluation else EPISODE_SCHEMA
            ),
            "episode_id": episode_id,
            "phase": phase.value,
            "ordinal": ordinal,
            "pair_id": pair_id,
            "replacement_of": replacement_of,
            "execution_contract_hash": self._phase_contract_hash(phase),
            "prestart_contract_receipt_hash": prestart["receipt_hash"],
            "prestart_event_index": prestart["event_index"],
            "independent_draw_receipt_hash": prestart[
                "independent_draw_receipt_hash"
            ],
            "interface_hash": self.backend.interface_hash,
            "initial_manifest_hash": initial_manifest["manifest_hash"],
            "turns": turns,
            "checkpoints": checkpoints,
            "evaluation": evaluation,
            "forced_outcome": forced_outcome,
            "infrastructure_invalid_preaction": infrastructure_preaction,
            "committed_at": utc_now(),
        }
        if defer_evaluation:
            record["generation_record_hash"] = hash_json(record)
            write_json(generation_path, record)
            self.ledger.append(
                "episode_candidate_committed",
                {
                    "episode_id": episode_id,
                    "phase": phase.value,
                    "generation_record_hash": record["generation_record_hash"],
                    "private_score_opened": False,
                },
            )
            return record
        record["completed_at"] = utc_now()
        record["episode_record_hash"] = hash_json(record)
        write_json(record_path, record)
        self._record_episode_completion(record)
        return record

    @staticmethod
    def _channel_manifest(workspace: Path) -> dict[str, str]:
        channel = workspace / ".dcp"
        allowed = {"instructions.md", "observation.json"}
        rows: dict[str, str] = {}
        for path in channel.iterdir():
            if path.name not in allowed:
                continue
            if not path.is_file() or path.is_symlink():
                raise HarnessError(f"reserved channel entry is not a regular file: {path}")
            rows[path.name] = hash_file(path)
        return rows

    @staticmethod
    def _validate_channel_after_agent(
        workspace: Path, protected: dict[str, str]
    ) -> tuple[bool, list[str]]:
        errors: list[str] = []
        channel = workspace / ".dcp"
        allowed = {"instructions.md", "observation.json", "action.json"}
        if not channel.is_dir() or channel.is_symlink():
            return False, ["reserved .dcp channel was removed or replaced"]
        for path in channel.iterdir():
            if path.name not in allowed:
                errors.append(f"unregistered reserved-channel entry: {path.name}")
                continue
            if not path.is_file() or path.is_symlink():
                errors.append(f"reserved-channel entry is not a regular file: {path.name}")
        for name, expected_hash in protected.items():
            path = channel / name
            try:
                observed = hash_file(path)
            except HarnessError:
                errors.append(f"protected reserved-channel file disappeared: {name}")
                continue
            if observed != expected_hash:
                errors.append(f"protected reserved-channel file changed: {name}")
        return not errors, errors

    def _record_episode_completion(self, record: dict[str, Any]) -> None:
        self.ledger.append(
            "episode_completed",
            {
                "episode_id": record["episode_id"],
                "phase": record["phase"],
                "episode_record_hash": record["episode_record_hash"],
                "outcome": record["evaluation"]["outcome"],
            },
        )

    def _score_deferred_episode(self, episode_id: str) -> dict[str, Any]:
        matches = list((self.root / "episodes").glob(f"**/{episode_id}"))
        matches = [path for path in matches if path.is_dir()]
        if len(matches) != 1:
            raise HarnessError(f"cannot locate deferred episode {episode_id!r}")
        episode_dir = matches[0]
        record_path = episode_dir / "record.json"
        if record_path.exists():
            return load_json_object(record_path)
        generation = load_json_object(episode_dir / "generation_record.json")
        if generation.get("schema") != "dcp_harness_generation_v1":
            raise HarnessError(f"deferred episode {episode_id!r} is malformed")
        body = dict(generation)
        claimed = body.pop("generation_record_hash", None)
        if claimed != hash_json(body):
            raise HarnessError(f"deferred episode {episode_id!r} was modified")
        phase = Phase(generation["phase"])
        context = self._context(
            phase,
            episode_id,
            int(generation["ordinal"]),
            episode_dir,
            pair_id=str(generation.get("pair_id", "")),
            replacement_of=str(generation.get("replacement_of", "")),
        )
        forced_outcome = generation.get("forced_outcome")
        if forced_outcome is None:
            try:
                evaluation = self._normalize_evaluation(
                    self.adapter.evaluate(context), context.workspace, episode_id
                )
            except Exception as exc:
                evaluation = self._empty_evaluation(
                    "unresolved",
                    f"private verifier failed: {type(exc).__name__}: {exc}",
                )
        else:
            evaluation = self._empty_evaluation(
                str(forced_outcome),
                "episode did not reach a privately evaluable commit",
            )
        record = dict(generation)
        record.pop("generation_record_hash", None)
        record["schema"] = EPISODE_SCHEMA
        record["evaluation"] = evaluation
        record["completed_at"] = utc_now()
        record["episode_record_hash"] = hash_json(record)
        write_json(record_path, record)
        self._record_episode_completion(record)
        return record

    def _score_all_pending_gate3(self) -> None:
        pending = sorted(
            (self.root / "episodes/gate3").glob("*/generation_record.json")
        )
        for path in pending:
            if not (path.parent / "record.json").exists():
                self._score_deferred_episode(path.parent.name)

    def _handle_action(
        self,
        context: EpisodeContext,
        kind: str,
        payload: dict[str, Any],
        turn_index: int,
        *,
        web_capture: CaptureGateway | None,
        web_replay: ReplayGateway | None,
    ) -> dict[str, Any]:
        if kind == "web_fetch":
            batch_id = f"{context.episode_id}-turn-{turn_index + 1:03d}"
            if web_capture is not None:
                return web_capture.capture(payload, batch_id=batch_id)
            if web_replay is not None:
                return web_replay.replay(payload, batch_id=batch_id)
            raise HarnessError("Web is unavailable in this episode")
        if kind == "experiment":
            if context.phase == Phase.CHALLENGE:
                return {
                    "schema": "dcp_no_feedback_observation_v1",
                    "experiment_completed": True,
                    "scientific_feedback_withheld": True,
                    "message": "No task-specific score, label, or directional feedback is available.",
                }
            self.adapter.validate_action(context, payload)
            result = self.adapter.handle_experiment(context, payload)
            if not isinstance(result, dict):
                raise HarnessError("task adapter returned a non-object observation")
            return result
        raise HarnessError(f"cannot handle action {kind!r}")

    def _empty_evaluation(self, outcome: str, reason: str) -> dict[str, Any]:
        value = {
            "outcome": outcome,
            "validity": "unresolved",
            "artifact_path": "",
            "artifact_hash": "",
            "per_unit": [],
            "unit_ids": [],
            "utility": None,
            "reason": reason,
        }
        value["verifier_result_hash"] = hash_json(value)
        return value

    def _normalize_evaluation(
        self, evaluation: EpisodeEvaluation, workspace: Path, label: str
    ) -> dict[str, Any]:
        if not isinstance(evaluation, EpisodeEvaluation):
            raise HarnessError(f"{label} evaluator did not return EpisodeEvaluation")
        for score in evaluation.per_unit:
            if (
                not isinstance(score, (int, float))
                or isinstance(score, bool)
                or not math.isfinite(float(score))
                or not 0.0 <= float(score) <= 1.0
            ):
                raise HarnessError(f"{label} score is outside [0,1]")
        if evaluation.utility is not None and (
            not isinstance(evaluation.utility, (int, float))
            or isinstance(evaluation.utility, bool)
            or not math.isfinite(float(evaluation.utility))
            or not 0.0 <= float(evaluation.utility) <= 1.0
        ):
            raise HarnessError(f"{label} utility is outside [0,1]")
        if any(
            not isinstance(unit_id, str) or not unit_id
            for unit_id in evaluation.unit_ids
        ) or len(set(evaluation.unit_ids)) != len(evaluation.unit_ids):
            raise HarnessError(f"{label} private unit IDs are invalid or duplicated")
        artifact_hash = ""
        if evaluation.outcome == "artifact":
            artifact = safe_child(workspace, evaluation.artifact_path)
            if not artifact.is_file() or artifact.is_symlink():
                raise HarnessError(f"{label} artifact is not a regular workspace file")
            artifact_hash = hash_file(artifact)
        value = {
            "outcome": evaluation.outcome,
            "validity": evaluation.validity,
            "artifact_path": evaluation.artifact_path,
            "artifact_hash": artifact_hash,
            "per_unit": [float(score) for score in evaluation.per_unit],
            "unit_ids": list(evaluation.unit_ids),
            "utility": (
                float(evaluation.utility)
                if evaluation.utility is not None
                else None
            ),
            "reason": evaluation.reason,
        }
        value["verifier_result_hash"] = hash_json(value)
        return value

    def _run_positive_control(self, index: int) -> dict[str, Any]:
        episode_id = f"positive-control-{index + 1:04d}"
        root = self.root / "episodes/positive_control" / episode_id
        record_path = root / "record.json"
        if record_path.exists():
            return load_json_object(record_path)
        workspace = root / "workspace"
        workspace.mkdir(parents=True, exist_ok=True)
        (workspace / ".dcp").mkdir(exist_ok=True)
        marker = self._draw_receipt(episode_id).split(":", 1)[1][:32]
        (workspace / "CANARY.txt").write_text(marker + "\n", encoding="utf-8")
        prompt = instructions(live_web=False, replay_web=False) + """

# Task-neutral channel check

Read `CANARY.txt`. Write its exact single line to `CANARY_RESPONSE.txt`, then
commit a finish action. Do not infer or transform the line.
"""
        event = self.ledger.append(
            "positive_control_prestarted",
            {"episode_id": episode_id, "marker_hash": hash_json({"marker": marker})},
        )
        result = self.backend.run(
            workspace=workspace,
            prompt=prompt,
            record_dir=root,
            episode_id=episode_id,
        )
        success = False
        try:
            action = read_action(workspace)
            response = workspace / "CANARY_RESPONSE.txt"
            success = bool(
                result.execution_ok
                and action.kind == "finish"
                and response.is_file()
                and not response.is_symlink()
                and response.read_text(encoding="utf-8").strip() == marker
            )
        except (HarnessError, OSError, UnicodeError):
            success = False
        record: dict[str, Any] = {
            "schema": "dcp_positive_control_record_v1",
            "episode_id": episode_id,
            "phase": Phase.POSITIVE_CONTROL.value,
            "prestart_event_index": event["event_index"],
            "prestart_receipt_hash": event["event_hash"],
            "agent": asdict(result),
            "success": success,
        }
        record["record_hash"] = hash_json(record)
        write_json(record_path, record)
        self.ledger.append(
            "positive_control_completed",
            {"episode_id": episode_id, "success": success, "record_hash": record["record_hash"]},
        )
        return record

    def _episodes(self) -> tuple[dict[str, Any], ...]:
        rows: list[dict[str, Any]] = []
        for path in sorted((self.root / "episodes").glob("**/record.json")):
            value = load_json_object(path)
            if value.get("schema") == EPISODE_SCHEMA:
                rows.append(value)
        return tuple(sorted(rows, key=lambda row: str(row["episode_id"])))

    @staticmethod
    def _phase_completion(
        events: list[dict[str, Any]], phase: str, errors: list[str]
    ) -> dict[str, Any]:
        matches = [
            event
            for event in events
            if event.get("event_type") == "phase_completed"
            and isinstance(event.get("payload"), dict)
            and event["payload"].get("phase") == phase
        ]
        if len(matches) != 1:
            errors.append(f"phase {phase} has {len(matches)} completion events")
            return {}
        return matches[0]["payload"]

    def _assert_capture_sealed(self) -> None:
        """Validate every object consumed by a post-capture branch."""

        errors: list[str] = []
        events = self.ledger.events()
        try:
            main = self._episodes()
            main_matches = [
                row for row in main if row.get("phase") == Phase.MAIN.value
            ]
            if len(main_matches) != 1:
                raise HarnessError("main episode is missing or duplicated")
            main_record = main_matches[0]
            summary = load_json_object(self.root / "main/summary.json")
            baseline = load_json_object(self.root / "main/baseline.json")
            manifest_value = load_json_object(
                self.root / "web_snapshot/manifest.json"
            )
            packet = load_json_object(
                self.root / "web_snapshot/privileged_packet.json"
            )
            expected_packet = privileged_packet(self.root / "web_snapshot")
            selected = summary["selected_checkpoint"]
            if (
                not isinstance(selected, int)
                or isinstance(selected, bool)
                or selected < 0
                or selected >= len(main_record.get("checkpoints", []))
            ):
                raise HarnessError("selected checkpoint is outside the main run")
            selected_row = main_record["checkpoints"][selected]
            completion = self._phase_completion(events, "capture", errors)
            if (
                summary.get("episode_record_hash")
                != main_record.get("episode_record_hash")
                or summary.get("baseline") != baseline
                or summary.get("baseline_evaluation_hash")
                != hash_json(baseline)
                or summary.get("selected_checkpoint_hash")
                != selected_row.get("manifest_hash")
                or summary.get("selected_checkpoint_path")
                != selected_row.get("path")
                or summary.get("web_snapshot_id")
                != manifest_value.get("snapshot_id")
                or summary.get("web_privileged_packet_hash")
                != packet.get("packet_hash")
                or packet != expected_packet
            ):
                errors.append("captured inputs differ from the main summary")
            if completion and (
                completion.get("main_record_hash")
                != main_record.get("episode_record_hash")
                or completion.get("baseline_evaluation_hash")
                != hash_json(baseline)
                or completion.get("selected_checkpoint_hash")
                != selected_row.get("manifest_hash")
                or completion.get("web_snapshot_id")
                != manifest_value.get("snapshot_id")
                or completion.get("web_privileged_packet_hash")
                != packet.get("packet_hash")
            ):
                errors.append("capture completion event differs from captured inputs")
            checkpoint_path = safe_child(self.root, selected_row["path"])
            if manifest(checkpoint_path).get("manifest_hash") != selected_row.get(
                "manifest_hash"
            ):
                errors.append("selected checkpoint content was modified")
            baseline_artifact = safe_child(
                self.root / "episodes/main/main/workspace",
                baseline["artifact_path"],
            )
            if baseline.get("artifact_hash") != hash_file(baseline_artifact):
                errors.append("baseline artifact was modified")
        except (HarnessError, KeyError, OSError, TypeError) as exc:
            errors.append(f"capture cannot be reconstructed: {exc}")
        if errors:
            raise HarnessError("captured run is invalid: " + "; ".join(errors))

    def _validate_phase_records(self, errors: list[str]) -> None:
        """Bind mutable convenience summaries back to immutable run receipts."""

        events = self.ledger.events()
        event_by_index = {event.get("event_index"): event for event in events}
        episodes = self._episodes()
        episode_by_id = {row["episode_id"]: row for row in episodes}
        state = self._state()

        try:
            main = episode_by_id["main"]
            summary = load_json_object(self.root / "main/summary.json")
            baseline = load_json_object(self.root / "main/baseline.json")
            packet = load_json_object(
                self.root / "web_snapshot/privileged_packet.json"
            )
            web_manifest = load_json_object(
                self.root / "web_snapshot/manifest.json"
            )
            selected = summary["selected_checkpoint"]
            selected_row = main["checkpoints"][selected]
            if (
                summary.get("schema") != "dcp_main_capture_summary_v1"
                or summary.get("episode_record_hash")
                != main.get("episode_record_hash")
                or summary.get("baseline") != baseline
                or summary.get("baseline_evaluation_hash")
                != hash_json(baseline)
                or not isinstance(selected, int)
                or isinstance(selected, bool)
                or state.get("selected_checkpoint") != selected
                or summary.get("selected_checkpoint_hash")
                != selected_row.get("manifest_hash")
                or summary.get("selected_checkpoint_path")
                != selected_row.get("path")
                or summary.get("web_snapshot_id")
                != web_manifest.get("snapshot_id")
                or summary.get("web_privileged_packet_hash")
                != packet.get("packet_hash")
            ):
                errors.append("main capture summary differs from frozen records")
            capture_event = self._phase_completion(events, "capture", errors)
            if capture_event and (
                capture_event.get("main_record_hash")
                != main.get("episode_record_hash")
                or capture_event.get("baseline_evaluation_hash")
                != hash_json(baseline)
                or capture_event.get("selected_checkpoint_hash")
                != summary.get("selected_checkpoint_hash")
                or capture_event.get("web_snapshot_id")
                != web_manifest.get("snapshot_id")
                or capture_event.get("web_privileged_packet_hash")
                != packet.get("packet_hash")
            ):
                errors.append("main capture completion event differs from summary")
            baseline_artifact = safe_child(
                self.root / "episodes/main/main/workspace",
                baseline["artifact_path"],
            )
            if baseline.get("artifact_hash") != hash_file(baseline_artifact):
                errors.append("baseline artifact hash differs from frozen evaluation")
        except (HarnessError, KeyError, IndexError, OSError, TypeError) as exc:
            errors.append(f"main capture records cannot be reconstructed: {exc}")

        try:
            challenge_summary = load_json_object(
                self.root / "challenge/summary.json"
            )
            challenges = sorted(
                (
                    row
                    for row in episodes
                    if row.get("phase") == Phase.CHALLENGE.value
                ),
                key=lambda row: row["ordinal"],
            )
            positive_records: list[dict[str, Any]] = []
            for path in sorted(
                (self.root / "episodes/positive_control").glob("*/record.json")
            ):
                record = load_json_object(path)
                body = dict(record)
                claimed = body.pop("record_hash", None)
                if claimed != hash_json(body):
                    errors.append(f"positive-control record hash mismatch: {path}")
                episode_id = record.get("episode_id")
                prestart = event_by_index.get(record.get("prestart_event_index"))
                completed = [
                    event
                    for event in events
                    if event.get("event_type") == "positive_control_completed"
                    and isinstance(event.get("payload"), dict)
                    and event["payload"].get("episode_id") == episode_id
                ]
                agent = record.get("agent")
                try:
                    if (
                        not isinstance(agent, dict)
                        or not agent.get("provider_receipt_hash")
                        or hash_file(Path(agent["stdout_path"]))
                        != agent.get("stdout_hash")
                        or hash_file(Path(agent["stderr_path"]))
                        != agent.get("stderr_hash")
                    ):
                        errors.append(
                            f"positive-control agent receipt is invalid: {episode_id}"
                        )
                    prestart_payload = (
                        prestart.get("payload", {}) if prestart else {}
                    )
                    if (
                        not isinstance(prestart, dict)
                        or prestart.get("event_type")
                        != "positive_control_prestarted"
                        or prestart.get("event_hash")
                        != record.get("prestart_receipt_hash")
                        or prestart_payload.get("episode_id") != episode_id
                        or len(completed) != 1
                        or completed[0]["payload"].get("record_hash") != claimed
                        or completed[0]["payload"].get("success")
                        is not record.get("success")
                    ):
                        errors.append(
                            f"positive-control events are invalid: {episode_id}"
                        )
                    expected_marker = self._draw_receipt(str(episode_id)).split(
                        ":", 1
                    )[1][:32]
                    workspace = path.parent / "workspace"
                    expected_success = False
                    try:
                        action = read_action(workspace)
                        response = (
                            workspace / "CANARY_RESPONSE.txt"
                        ).read_text(encoding="utf-8").strip()
                        expected_success = bool(
                            agent.get("returncode") == 0
                            and agent.get("timed_out") is False
                            and agent.get("identity_ok") is True
                            and agent.get("interface_ok") is True
                            and action.kind == "finish"
                            and response == expected_marker
                        )
                    except (HarnessError, OSError, UnicodeError):
                        expected_success = False
                    if record.get("success") is not expected_success:
                        errors.append(
                            f"positive-control result cannot be reconstructed: {episode_id}"
                        )
                except (HarnessError, KeyError, OSError, UnicodeError) as exc:
                    errors.append(
                        f"positive-control record cannot be reconstructed: {episode_id}: {exc}"
                    )
                positive_records.append(record)
            expected_hashes = [row["episode_record_hash"] for row in challenges]
            positive_hashes = [row["record_hash"] for row in positive_records]
            if (
                challenge_summary.get("schema")
                != "dcp_challenge_summary_v1"
                or challenge_summary.get("challenger_episodes")
                != len(challenges)
                or challenge_summary.get("challenger_record_hashes")
                != expected_hashes
                or challenge_summary.get("positive_control_episodes")
                != len(positive_records)
                or challenge_summary.get("positive_control_successes")
                != sum(bool(row.get("success")) for row in positive_records)
                or challenge_summary.get("positive_control_record_hashes")
                != positive_hashes
            ):
                errors.append("challenge summary differs from frozen records")
            challenge_event = self._phase_completion(events, "challenge", errors)
            if challenge_event and challenge_event.get("summary_hash") != hash_json(
                challenge_summary
            ):
                errors.append("challenge completion event differs from summary")
        except (HarnessError, KeyError, OSError, TypeError) as exc:
            errors.append(f"challenge records cannot be reconstructed: {exc}")

        if self.config.audit.grade != "evidence":
            return
        try:
            gate3_summary = load_json_object(self.root / "gate3/summary.json")
            preseal_index = gate3_summary["contract_preseal_event_index"]
            preseal = event_by_index.get(preseal_index)
            if (
                not isinstance(preseal, dict)
                or preseal.get("event_type") != "gate3_contracts_presealed"
                or preseal.get("event_hash")
                != gate3_summary.get("contract_preseal_receipt_hash")
            ):
                errors.append("Gate-3 preseal receipt is not in the event ledger")
            first_indices: list[int] = []
            for family, phase_pair, state_key in (
                (
                    "feedback",
                    (Phase.FEEDBACK_TRUTHFUL, Phase.FEEDBACK_NEUTRAL),
                    "gate3_feedback_pairs",
                ),
                (
                    "sham",
                    (Phase.SHAM_REFERENCE, Phase.SHAM_PROPOSED),
                    "gate3_sham_pairs",
                ),
            ):
                value = load_json(self.root / f"gate3/{family}_pairs.json")
                if not isinstance(value, list):
                    raise HarnessError(f"{family} pair ledger is not an array")
                rows = value
                if (
                    rows != gate3_summary.get(f"{family}_pairs")
                    or rows != state.get(state_key)
                ):
                    errors.append(
                        f"Gate-3 {family} pair ledger differs from state or summary"
                    )
                for row in rows:
                    body = dict(row)
                    claimed = body.pop("pair_record_hash", None)
                    if claimed != hash_json(body):
                        errors.append(
                            f"Gate-3 pair record hash mismatch: {row.get('pair_id')}"
                        )
                    pair_id = row.get("pair_id")
                    expected_order = {phase.value for phase in phase_pair}
                    if (
                        row.get("family") != family
                        or set(row.get("branch_order", [])) != expected_order
                        or row.get("randomization_draw_receipt_hash")
                        != self._draw_receipt(f"{pair_id}:order")
                    ):
                        errors.append(f"Gate-3 pair draw is invalid: {pair_id}")
                    first_index = row.get("first_branch_started_event_index")
                    if isinstance(first_index, int) and not isinstance(
                        first_index, bool
                    ):
                        first_indices.append(first_index)
                    else:
                        errors.append(
                            f"Gate-3 pair has no execution-start event: {pair_id}"
                        )
                    for phase in phase_pair:
                        prestart = row.get("branch_prestarts", {}).get(
                            phase.value
                        )
                        if not isinstance(prestart, dict):
                            errors.append(
                                f"Gate-3 branch prestart is absent: {pair_id}:{phase.value}"
                            )
                            continue
                        event = event_by_index.get(prestart.get("event_index"))
                        payload = event.get("payload", {}) if event else {}
                        if (
                            not isinstance(event, dict)
                            or event.get("event_type")
                            != "gate3_branch_prestarted"
                            or event.get("event_hash")
                            != prestart.get("receipt_hash")
                            or payload.get("pair_id") != pair_id
                            or payload.get("phase") != phase.value
                            or payload.get("execution_contract_hash")
                            != self._phase_contract_hash(phase)
                            or payload.get("randomization_draw_receipt_hash")
                            != row.get("randomization_draw_receipt_hash")
                        ):
                            errors.append(
                                f"Gate-3 branch prestart receipt is invalid: {pair_id}:{phase.value}"
                            )
                        episode_id = row.get("branches", {}).get(phase.value)
                        if episode_id is None:
                            if row.get("infrastructure_invalid_preaction") is not True:
                                errors.append(
                                    f"Gate-3 undispatched branch lacks infrastructure attrition: {pair_id}:{phase.value}"
                                )
                            continue
                        record = episode_by_id.get(episode_id)
                        if (
                            not isinstance(record, dict)
                            or record.get("phase") != phase.value
                            or record.get("pair_id") != pair_id
                            or record.get("prestart_contract_receipt_hash")
                            != prestart.get("receipt_hash")
                        ):
                            errors.append(
                                f"Gate-3 branch record differs from pair ledger: {episode_id}"
                            )
            if first_indices and gate3_summary.get(
                "first_branch_started_event_index"
            ) != min(first_indices):
                errors.append("Gate-3 first-branch index differs from pair ledger")
            gate3_event = self._phase_completion(events, "gate3", errors)
            if gate3_event and gate3_event.get("summary_hash") != hash_json(
                gate3_summary
            ):
                errors.append("Gate-3 completion event differs from summary")
        except (HarnessError, KeyError, OSError, TypeError) as exc:
            errors.append(f"Gate-3 records cannot be reconstructed: {exc}")

    def _validate_run_records(self) -> None:
        errors: list[str] = []
        event_completions = {
            event.get("payload", {}).get("episode_id"): event.get("payload", {})
            for event in self.ledger.events()
            if event.get("event_type") == "episode_completed"
            and isinstance(event.get("payload"), dict)
        }
        for record_path in sorted((self.root / "episodes").glob("**/record.json")):
            record = load_json_object(record_path)
            if record.get("schema") != EPISODE_SCHEMA:
                continue
            body = dict(record)
            claimed = body.pop("episode_record_hash", None)
            if claimed != hash_json(body):
                errors.append(f"episode record hash mismatch: {record_path}")
            completion = event_completions.get(record.get("episode_id"))
            if not isinstance(completion, dict) or completion.get(
                "episode_record_hash"
            ) != claimed:
                errors.append(f"episode is not bound by its completion event: {record_path}")
            generation_path = record_path.parent / "generation_record.json"
            if generation_path.exists():
                generation = load_json_object(generation_path)
                generation_body = dict(generation)
                generation_claim = generation_body.pop("generation_record_hash", None)
                if generation_claim != hash_json(generation_body):
                    errors.append(f"generation record hash mismatch: {generation_path}")
                projected = dict(record)
                projected.pop("episode_record_hash", None)
                projected.pop("completed_at", None)
                projected["schema"] = "dcp_harness_generation_v1"
                projected["evaluation"] = None
                if projected != generation_body:
                    errors.append(
                        f"private evaluation does not extend the frozen generation: {record_path}"
                    )
            workspace = record_path.parent / "workspace"
            evaluation = record.get("evaluation")
            if isinstance(evaluation, dict) and evaluation.get("outcome") == "artifact":
                try:
                    artifact = safe_child(workspace, evaluation["artifact_path"])
                    if evaluation.get("artifact_hash") != hash_file(artifact):
                        errors.append(f"committed artifact hash mismatch: {record_path}")
                except (HarnessError, KeyError, OSError) as exc:
                    errors.append(f"committed artifact is unavailable: {record_path}: {exc}")
            turns = record.get("turns")
            if not isinstance(turns, list):
                errors.append(f"episode turns are malformed: {record_path}")
                turns = []
            for turn in turns:
                if not isinstance(turn, dict):
                    errors.append(f"episode contains a malformed turn: {record_path}")
                    continue
                turn_number = turn.get("turn")
                turn_body = dict(turn)
                turn_claim = turn_body.pop("turn_record_hash", None)
                if turn_claim != hash_json(turn_body):
                    errors.append(f"turn record hash mismatch: {record_path}:{turn_number}")
                if not isinstance(turn_number, int) or isinstance(turn_number, bool):
                    continue
                turn_dir = record_path.parent / "turns" / f"{turn_number:03d}"
                try:
                    if load_json_object(turn_dir / "turn.json") != turn:
                        errors.append(f"turn file differs from episode record: {turn_dir}")
                    prompt = (turn_dir / "prompt.txt").read_text(encoding="utf-8")
                    if turn.get("prompt_hash") != hash_json({"prompt": prompt}):
                        errors.append(f"prompt hash mismatch: {turn_dir}")
                    agent = turn.get("agent")
                    if not isinstance(agent, dict):
                        raise HarnessError("agent receipt is missing")
                    if not agent.get("provider_receipt_hash"):
                        errors.append(f"agent provider receipt is absent: {turn_dir}")
                    if hash_file(Path(agent["stdout_path"])) != agent.get("stdout_hash"):
                        errors.append(f"agent stdout hash mismatch: {turn_dir}")
                    if hash_file(Path(agent["stderr_path"])) != agent.get("stderr_hash"):
                        errors.append(f"agent stderr hash mismatch: {turn_dir}")
                except (HarnessError, KeyError, OSError, UnicodeError) as exc:
                    errors.append(f"turn receipt cannot be reconstructed: {turn_dir}: {exc}")
            checkpoints = record.get("checkpoints")
            if not isinstance(checkpoints, list):
                errors.append(f"checkpoint ledger is malformed: {record_path}")
                checkpoints = []
            for row in checkpoints:
                if not isinstance(row, dict):
                    errors.append(f"checkpoint row is malformed: {record_path}")
                    continue
                try:
                    checkpoint_path = safe_child(self.root, row["path"])
                    observed = manifest(checkpoint_path)
                    if observed["manifest_hash"] != row.get("manifest_hash"):
                        errors.append(f"checkpoint content hash mismatch: {checkpoint_path}")
                except (HarnessError, KeyError, OSError) as exc:
                    errors.append(f"checkpoint cannot be reconstructed: {record_path}: {exc}")
        valid_web, web_errors = validate_snapshot(self.root / "web_snapshot")
        if not valid_web:
            errors.extend(f"Web snapshot: {error}" for error in web_errors)
        self._validate_phase_records(errors)
        if errors:
            raise HarnessError("record validation failed: " + "; ".join(errors))

    def _run_view(self) -> RunView:
        self._validate_run_records()
        return RunView(
            root=self.root,
            config=self.config,
            registration=self.frozen_registration,
            state=self._state(),
            contracts=self.contracts,
            source_manifest=load_json_object(
                self.root / "registration/source_workspace.json"
            ),
            web_manifest=load_json_object(self.root / "web_snapshot/manifest.json"),
            episodes=self._episodes(),
            event_head=self.ledger.head,
        )

    def finalize(self) -> dict[str, Any]:
        with self._lock():
            self._assert_ledger_valid()
            state = self._state()
            required = {"capture": "complete", "challenge": "complete"}
            if self.config.audit.grade == "evidence":
                required["gate3"] = "complete"
            for phase, status in required.items():
                if state["phases"][phase] != status:
                    raise HarnessError(f"phase {phase} is not complete")
            report_path = self.root / "finalize_report.json"
            if state["phases"]["finalize"] == "complete":
                report = load_json_object(report_path)
                replay = verify_bundle(self.root / "bundle")
                if (
                    replay.get("ok") is not True
                    or replay.get("bundle_id") != report.get("bundle_id")
                ):
                    raise HarnessError("finalized Bundle no longer replays exactly")
                return report
            ok, errors = self.ledger.verify()
            if not ok:
                raise HarnessError("cannot finalize an invalid ledger: " + "; ".join(errors))
            package = self.adapter.build_evidence(self._run_view())
            self._validate_evidence_bindings(package)
            if package.gate3 is None:
                certificate = evaluate(
                    package.registration,
                    package.gate1,
                    package.gate2,
                    integrity=package.integrity,
                )
                manifest_value = write_core_bundle(
                    self.root / "bundle",
                    package.registration,
                    package.integrity,
                    package.gate1,
                    package.gate2,
                    certificate,
                )
            else:
                certificate = evaluate(
                    package.registration,
                    package.gate1,
                    package.gate2,
                    package.gate3,
                    integrity=package.integrity,
                )
                manifest_value = write_full_audit_bundle(
                    self.root / "bundle",
                    package.registration,
                    package.integrity,
                    package.gate1,
                    package.gate2,
                    package.gate3,
                    certificate,
                )
            replay = verify_bundle(self.root / "bundle")
            if replay.get("ok") is not True:
                raise HarnessError(
                    "freshly written Bundle failed deterministic replay: "
                    + "; ".join(replay.get("errors", []))
                )
            report = {
                "schema": "dcp_harness_finalize_report_v1",
                "bundle_id": manifest_value["bundle_id"],
                "bundle_path": str(self.root / "bundle"),
                "certificate_content_id": hash_json(certificate.to_dict()),
                "verdict": certificate.to_dict()["verdict"],
                "kernel_replay_matches": replay["kernel_replay_matches"],
                "formal_certificate_issued": False,
                "provenance_scope": replay["provenance_scope"],
            }
            write_json(report_path, report)
            state = self._state()
            state["phases"]["finalize"] = "complete"
            self._write_state(state)
            self.ledger.append(
                "bundle_finalized",
                {"bundle_id": report["bundle_id"], "verdict": report["verdict"]},
            )
            return report

    def _validate_evidence_bindings(self, package: EvidencePackage) -> None:
        if not isinstance(package, EvidencePackage):
            raise HarnessError("task adapter did not return an EvidencePackage")
        reg = package.registration
        integrity = package.integrity
        contracts = self.contracts
        errors: list[str] = []
        if asdict(reg) != asdict(self.frozen_registration):
            errors.append(
                "evidence registration differs from the prospectively frozen registration"
            )
        expected_reg = {
            "claim_id": self.config.claim_id,
            "model_id": self.config.agent.model,
            "interface_hash": self.backend.interface_hash,
            "grade_requested": self.config.audit.grade,
            "registered_n_feedback_pairs": self.config.audit.feedback_pairs,
            "registered_n_sham_pairs": self.config.audit.sham_pairs,
            "max_feedback_pair_replacements": self.config.audit.max_feedback_pair_replacements,
            "max_sham_pair_replacements": self.config.audit.max_sham_pair_replacements,
            "gate3_checkpoint_scope": self.config.audit.checkpoint_scope,
        }
        contract_reg_fields = [
            "gate2_control_contract_hash",
            "challenge_distribution_hash",
        ]
        if self.config.audit.grade == "evidence":
            contract_reg_fields.extend(
                [
            "scaffold_hash",
            "feedback_schema_hash",
            "sham_operator_hash",
            "neutral_sham_generator_hash",
            "truthful_feedback_generator_hash",
            "reference_null_generator_hash",
            "gate3_paired_arm_contract_hash",
            "gate3_truthful_arm_contract_hash",
            "gate3_neutral_arm_contract_hash",
            "gate3_neutral_recovery_contract_hash",
            "gate3_resource_contract_hash",
            "gate3_opportunity_contract_hash",
            "gate3_branch_policy_hash",
            "gate3_pair_randomization_distribution_hash",
            "sham_randomization_distribution_hash",
            "sham_paired_arm_contract_hash",
            "sham_reference_arm_contract_hash",
            "sham_proposed_arm_contract_hash",
                ]
            )
        for field, expected in expected_reg.items():
            if getattr(reg, field) != expected:
                errors.append(f"registration.{field} is not bound to the recorded run")
        for field in contract_reg_fields:
            if getattr(reg, field) != contracts[field]:
                errors.append(f"registration.{field} differs from the frozen contract")
        if reg.audit_slot_id != contracts["audit_slot_id"]:
            errors.append("registration.audit_slot_id differs from the reserved slot")
        if (
            reg.audit_slot_reservation_receipt_hash
            != contracts["audit_slot_reservation_receipt_hash"]
        ):
            errors.append("registration audit-slot receipt differs from the frozen receipt")

        main = next((row for row in self._episodes() if row["phase"] == Phase.MAIN.value), None)
        if main is None:
            errors.append("main episode is absent")
        else:
            self._compare_artifact_scores(
                package.gate1.astar, main["evaluation"], "Gate-1 A*", errors
            )
        baseline = load_json_object(self.root / "main/baseline.json")
        self._compare_artifact_scores(
            package.gate1.baseline, baseline, "Gate-1 baseline", errors
        )
        challenges = {
            row["episode_id"]: row
            for row in self._episodes()
            if row["phase"] == Phase.CHALLENGE.value
        }
        evidence_controls = {item.attempt_id: item for item in package.gate2.controls}
        if set(challenges) != set(evidence_controls):
            errors.append("Gate-2 evidence does not disclose exactly the recorded challengers")
        for episode_id in set(challenges) & set(evidence_controls):
            self._compare_control(
                evidence_controls[episode_id], challenges[episode_id], errors
            )
        challenge_summary = load_json_object(self.root / "challenge/summary.json")
        if (
            package.gate2.adequacy.positive_control_trials
            != challenge_summary["positive_control_episodes"]
            or package.gate2.adequacy.positive_control_successes
            != challenge_summary["positive_control_successes"]
        ):
            errors.append("Gate-2 adequacy does not match the positive-control ledger")

        web_manifest = load_json_object(self.root / "web_snapshot/manifest.json")
        web_used = web_manifest["request_count"] > 0
        integrity_expected = {
            "astar_hash": main["evaluation"]["artifact_hash"] if main else "",
            "baseline_hash": baseline["artifact_hash"],
            "verifier_hash": contracts["verifier_hash"],
            "p_hash": contracts["p_hash"],
            "resource_contract_hash": contracts["resource_contract_hash"],
            "selection_rule_hash": contracts["selection_rule_hash"],
            "k_manifest_hash": contracts["k_manifest_hash"],
            "e0_manifest_hash": contracts["e0_manifest_hash"],
            "private_unit_manifest_hash": contracts[
                "private_unit_manifest_hash"
            ],
            "observed_web_manifest_hash": web_manifest["snapshot_id"],
            "challenger_policy_hash": contracts["challenger_policy_hash"],
            "opportunity_contract_hash": contracts["opportunity_contract_hash"],
            "claim_family_manifest_hash": contracts["claim_family_manifest_hash"],
            "alpha_ledger_receipt_hash": contracts[
                "audit_slot_reservation_receipt_hash"
            ],
            "audit_slot_registry_entry_hash": contracts[
                "audit_slot_registry_entry_hash"
            ],
            "web_access_used": web_used,
            "web_replay_scope": (
                "observed_request_response_frozen" if web_used else "not_used"
            ),
        }
        if main is not None:
            integrity_expected["lineage_manifest_hash"] = main[
                "episode_record_hash"
            ]
        for field, expected in integrity_expected.items():
            if getattr(integrity, field) != expected:
                errors.append(f"integrity.{field} is not bound to the recorded run")
        if (
            integrity.private_isolation_pass
            is not contracts["private_isolation_pass"]
        ):
            errors.append(
                "integrity.private_isolation_pass differs from the frozen backend"
            )
        research_turns = [
            turn
            for record in self._episodes()
            for turn in record.get("turns", [])
            if isinstance(turn, dict) and isinstance(turn.get("agent"), dict)
        ]

        def receipt_ok(turn: dict[str, Any]) -> bool:
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

        receipts_ok = bool(
            research_turns and all(receipt_ok(turn) for turn in research_turns)
        )
        if integrity.provenance_pass and not receipts_ok:
            errors.append("integrity.provenance_pass exceeds the recorded agent receipts")
        challenge_contracts_ok = all(
            record["evaluation"]["outcome"]
            != RawAttemptOutcome.EXECUTION_CONTRACT_VIOLATION.value
            for record in self._episodes()
            if record["phase"] == Phase.CHALLENGE.value
        )
        if integrity.challenger_contract_pass and not challenge_contracts_ok:
            errors.append(
                "integrity.challenger_contract_pass exceeds the challenger ledger"
            )

        if package.gate3 is None and self.config.audit.grade == "evidence":
            errors.append("an evidence-grade run omitted Gate-3 evidence")
        if package.gate3 is not None:
            self._compare_gate3(package.gate3, errors)
        if errors:
            raise HarnessError("evidence/runtime binding failed: " + "; ".join(errors))

    @staticmethod
    def _compare_artifact_scores(
        artifact: Any, evaluation: dict[str, Any], label: str, errors: list[str]
    ) -> None:
        if (
            artifact.artifact_hash != evaluation["artifact_hash"]
            or list(artifact.per_unit) != evaluation["per_unit"]
            or list(artifact.unit_ids) != evaluation["unit_ids"]
            or artifact.validity.value != evaluation["validity"]
        ):
            errors.append(f"{label} differs from the private-verifier record")

    @staticmethod
    def _compare_control(
        control: ControlAttempt, record: dict[str, Any], errors: list[str]
    ) -> None:
        evaluation = record["evaluation"]
        expected_scores = evaluation["per_unit"] if evaluation["outcome"] == "artifact" else None
        if (
            control.outcome.value != evaluation["outcome"]
            or control.validity.value != evaluation["validity"]
            or control.artifact_hash != evaluation["artifact_hash"]
            or (list(control.per_unit) if control.per_unit is not None else None)
            != expected_scores
            or list(control.unit_ids) != evaluation["unit_ids"]
            or control.prestart_contract_receipt_hash
            != record["prestart_contract_receipt_hash"]
            or control.independent_draw_receipt_hash
            != record["independent_draw_receipt_hash"]
            or control.scope_contract_hash != record["execution_contract_hash"]
        ):
            errors.append(f"Gate-2 control {control.attempt_id} differs from its run record")

    def _compare_gate3(self, gate3: Any, errors: list[str]) -> None:
        state = self._state()
        feedback_ledger = {row["pair_id"]: row for row in state["gate3_feedback_pairs"]}
        sham_ledger = {row["pair_id"]: row for row in state["gate3_sham_pairs"]}
        if {pair.pair_id for pair in gate3.pairs} != set(feedback_ledger):
            errors.append("Gate-3 evidence does not disclose exactly the feedback pair ledger")
        if {pair.pair_id for pair in gate3.sham.pairs} != set(sham_ledger):
            errors.append("Gate-3 evidence does not disclose exactly the sham pair ledger")
        episode_by_id = {row["episode_id"]: row for row in self._episodes()}
        for pair in gate3.pairs:
            ledger = feedback_ledger.get(pair.pair_id)
            if ledger is None:
                continue
            self._compare_pair_branch(pair.truthful, Phase.FEEDBACK_TRUTHFUL, ledger, episode_by_id, errors)
            self._compare_pair_branch(pair.neutral, Phase.FEEDBACK_NEUTRAL, ledger, episode_by_id, errors)
            if (
                pair.replacement_of != ledger["replacement_of"]
                or pair.randomization_draw_receipt_hash
                != ledger["randomization_draw_receipt_hash"]
                or pair.randomization_distribution_hash
                != self.contracts[
                    "gate3_pair_randomization_distribution_hash"
                ]
                or pair.assignment_frozen is not True
                or pair.independence_ok is not True
            ):
                errors.append(
                    f"feedback pair {pair.pair_id} differs from its randomized ledger"
                )
        for pair in gate3.sham.pairs:
            ledger = sham_ledger.get(pair.pair_id)
            if ledger is None:
                continue
            self._compare_pair_branch(pair.reference_null, Phase.SHAM_REFERENCE, ledger, episode_by_id, errors)
            self._compare_pair_branch(pair.proposed_sham, Phase.SHAM_PROPOSED, ledger, episode_by_id, errors)
            if (
                pair.replacement_of != ledger["replacement_of"]
                or pair.randomization_draw_receipt_hash
                != ledger["randomization_draw_receipt_hash"]
                or pair.randomization_distribution_hash
                != self.contracts["sham_randomization_distribution_hash"]
                or pair.assignment_frozen is not True
                or pair.independence_ok is not True
            ):
                errors.append(
                    f"sham pair {pair.pair_id} differs from its randomized ledger"
                )

    def _compare_pair_branch(
        self,
        branch: Any,
        phase: Phase,
        ledger: dict[str, Any],
        episodes: dict[str, dict[str, Any]],
        errors: list[str],
    ) -> None:
        episode_id = ledger["branches"].get(phase.value)
        if episode_id is None:
            prestart = ledger.get("branch_prestarts", {}).get(phase.value, {})
            if (
                branch.outcome != RawAttemptOutcome.INFRASTRUCTURE_INVALID
                or branch.prestart_contract_receipt_hash
                != prestart.get("receipt_hash")
                or branch.execution_contract_hash
                != self._phase_contract_hash(phase)
                or branch.infrastructure_outcome_independent is not True
            ):
                errors.append(f"unstarted {phase.value} branch is not infrastructure_invalid")
            return
        record = episodes.get(episode_id)
        if record is None:
            errors.append(f"Gate-3 branch record is missing: {episode_id}")
            return
        evaluation = record["evaluation"]
        if (
            branch.branch_id != episode_id
            or branch.outcome.value != evaluation["outcome"]
            or branch.validity.value != evaluation["validity"]
            or branch.artifact_hash != evaluation["artifact_hash"]
            or (list(branch.per_unit) if branch.per_unit is not None else [])
            != evaluation["per_unit"]
            or list(branch.unit_ids) != evaluation["unit_ids"]
            or branch.utility != evaluation["utility"]
            or branch.prestart_contract_receipt_hash
            != record["prestart_contract_receipt_hash"]
            or branch.execution_contract_hash != record["execution_contract_hash"]
            or branch.infrastructure_outcome_independent
            is not bool(record["infrastructure_invalid_preaction"])
        ):
            errors.append(f"Gate-3 branch {episode_id} differs from its run record")
