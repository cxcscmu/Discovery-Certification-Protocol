"""Top-level fail-closed orchestration: frozen inputs -> machine certificate."""

from __future__ import annotations

from copy import deepcopy
import json
from dataclasses import dataclass, field
from typing import Optional

from dcp.certificate import build_certificate, certificate_json
from dcp.gate1 import evaluate_gate1
from dcp.gate2 import evaluate_gate2
from dcp.gate3 import evaluate_gate3, evaluate_neutral_hit_witness
from dcp.integrity import (
    validate_gate2_hit_integrity,
    validate_gate3_integrity,
    validate_integrity,
    validate_neutral_hit_integrity,
    validate_neutral_recovery_ledger_integrity,
)
from dcp.registration import Registration, validate_registration
from dcp.types import (
    AdequacyEvidence,
    AttemptStatus,
    ControlClassification,
    Gate1Evidence,
    Gate1Result,
    Gate2Evidence,
    Gate2Result,
    Gate3Evidence,
    Gate3Result,
    IntegrityEvidence,
    Recovery,
    TriState,
    Verdict,
)
from dcp.verdict import final_verdict


@dataclass
class Certificate:
    registration: Registration
    integrity: Optional[IntegrityEvidence]
    registration_errors: list[str]
    integrity_errors: list[str]
    gate3_integrity_errors: list[str]
    gate3_neutral_hit_integrity_errors: list[str]
    gate3_neutral_ledger_integrity_errors: list[str]
    gate1: Gate1Result
    gate2: Gate2Result
    gate3: Optional[Gate3Result]
    verdict: Verdict
    _sealed_json: Optional[str] = field(default=None, init=False, repr=False)

    def to_dict(self) -> dict:
        if self._sealed_json is None:
            self._seal()
        return json.loads(self._sealed_json)

    def to_json(self, indent: int = 2) -> str:
        return certificate_json(self.to_dict(), indent=indent)

    def _seal(self) -> None:
        payload = build_certificate(
            self.registration,
            self.integrity,
            self.registration_errors,
            self.integrity_errors,
            self.gate3_integrity_errors,
            self.gate3_neutral_hit_integrity_errors,
            self.gate3_neutral_ledger_integrity_errors,
            self.gate1,
            self.gate2,
            self.verdict,
            self.gate3,
        )
        self._sealed_json = certificate_json(payload, indent=None)


def _empty_gate1(ev: Gate1Evidence, reason: str) -> Gate1Result:
    from dcp.types import Validity

    astar = getattr(ev, "astar", None)
    baseline = getattr(ev, "baseline", None)
    astar_validity = getattr(astar, "validity", Validity.UNRESOLVED)
    baseline_validity = getattr(baseline, "validity", Validity.UNRESOLVED)
    if not isinstance(astar_validity, Validity):
        astar_validity = Validity.UNRESOLVED
    if not isinstance(baseline_validity, Validity):
        baseline_validity = Validity.UNRESOLVED
    return Gate1Result(
        result_validity=TriState.INCONCLUSIVE,
        astar_validity=astar_validity,
        baseline_validity=baseline_validity,
        x=None,
        effect_mean=None,
        effect_lcb=None,
        effect_ucb=None,
        utility_pass=False,
        utility_confirmed_below=False,
        baseline_fails_p=TriState.INCONCLUSIVE,
        baseline_satisfies_p=False,
        reason=reason,
    )


def _empty_gate2(reason: str) -> Gate2Result:
    return Gate2Result(
        no_feedback_recovery=Recovery.INCONCLUSIVE,
        classifications=[],
        n_started=0,
        n_evaluable=0,
        n_ind=0,
        hits=0,
        admissible_hits=0,
        unresolved=0,
        p_upper=None,
        best_control_margin=None,
        adequacy_pass=False,
        adequacy_reasons=[reason],
        hit_admissibility_pass=False,
        hit_admissibility_reasons=[reason],
        positive_control_recall_lcb=None,
        positive_control_successes=0,
        positive_control_trials=0,
        adequacy_calibration_id="",
        adequacy_manifest_hash="",
        a_i=None,
        reason=reason,
    )


def _empty_gate3(
    reason: str, *, neutral_contract_audit_pass: Optional[bool] = None
) -> Gate3Result:
    from dcp.types import EffectStatus

    return Gate3Result(
        checkpoint_scope="",
        checkpoint_hash="",
        window_hash="",
        feedback_pairs_manifest_hash="",
        design_checks_pass=False,
        stopping_rule_pass=False,
        registered_pairs_complete=False,
        all_started_pairs_disclosed=False,
        no_pair_replacements=False,
        paired_contract_audit_pass=False,
        truthful_channel_audit_pass=False,
        neutral_channel_audit_pass=False,
        started_pair_count=0,
        paired_arm_contract_hash="",
        truthful_arm_contract_hash="",
        neutral_arm_contract_hash="",
        neutral_recovery_contract_hash="",
        truthful_feedback_generator_hash="",
        neutral_sham_generator_hash="",
        contract_preseal_receipt_hash="",
        contract_sealed_before_branches_pass=False,
        contract_sealed_event_index=-1,
        first_branch_started_event_index=-1,
        neutral_scope_audit_manifest_hash="",
        neutral_challenger_policy_hash="",
        neutral_scope_contract={},
        sham_adequacy=TriState.INCONCLUSIVE,
        feedback_effect=EffectStatus.INCONCLUSIVE,
        effect_mean=None,
        effect_lcb=None,
        effect_ucb=None,
        n_pairs_started=0,
        n_pairs_analyzed=0,
        pair_ids_analyzed=[],
        pair_records=[],
        pairs_unresolved=0,
        pairs_infrastructure_excluded=0,
        truthful_valid_rate=0.0,
        neutral_valid_rate=0.0,
        truthful_model_failure_rate=1.0,
        neutral_model_failure_rate=1.0,
        pair_infrastructure_failure_rate=1.0,
        branch_health_pass=False,
        branch_health_reasons=[reason],
        sham_delta_null_mean=None,
        sham_delta_null_lcb=None,
        sham_delta_null_ucb=None,
        sham_n=0,
        sham_all_started_pairs_disclosed=False,
        sham_no_pair_replacements=False,
        sham_started_pair_count=0,
        sham_pair_records=[],
        sham_development_manifest_hash="",
        sham_confirmatory_manifest_hash="",
        sham_paired_arm_contract_hash="",
        sham_reference_arm_contract_hash="",
        sham_proposed_arm_contract_hash="",
        sham_reference_null_generator_hash="",
        sham_contract_preseal_receipt_hash="",
        sham_contract_sealed_event_index=-1,
        sham_first_branch_started_event_index=-1,
        neutral_recovery=Recovery.INCONCLUSIVE,
        neutral_adequacy_pass=False,
        neutral_adequacy_reasons=[reason],
        neutral_positive_control_recall_lcb=None,
        neutral_positive_control_successes=0,
        neutral_positive_control_trials=0,
        neutral_adequacy_calibration_id="",
        neutral_adequacy_manifest_hash="",
        neutral_classifications=[],
        neutral_n_ind=0,
        neutral_hits=0,
        neutral_admissible_hits=0,
        neutral_unresolved=0,
        neutral_p_upper=None,
        neutral_reason=reason,
        neutral_in_gate2_scope=False,
        lineage_empty_hit_refutes_core=False,
        reason=reason,
        neutral_contract_audit_pass=neutral_contract_audit_pass,
    )


def _preserve_neutral_hit(
    g3: Gate3Result,
    ev: Gate3Evidence,
    classifications: list[ControlClassification],
    *,
    lineage_empty_hit: bool,
    malformed_neutral_pairs: int,
) -> None:
    """Overlay a decisive neutral hit onto an otherwise inconclusive Gate 3."""
    hits = sum(item.status == AttemptStatus.CONFIRMED_HIT for item in classifications)
    if hits == 0:
        return
    g3.checkpoint_scope = ev.checkpoint_scope
    g3.checkpoint_hash = ev.checkpoint_hash
    g3.window_hash = ev.window_hash
    g3.paired_arm_contract_hash = ev.paired_arm_contract_hash
    g3.neutral_arm_contract_hash = ev.neutral_arm_contract_hash
    g3.neutral_recovery_contract_hash = ev.neutral_recovery_contract_hash
    g3.neutral_sham_generator_hash = ev.neutral_sham_generator_hash
    g3.contract_preseal_receipt_hash = ev.contract_preseal_receipt_hash
    g3.contract_sealed_before_branches_pass = ev.contract_sealed_before_branches_pass
    g3.contract_sealed_event_index = ev.contract_sealed_event_index
    g3.first_branch_started_event_index = ev.first_branch_started_event_index
    g3.neutral_scope_audit_manifest_hash = ev.neutral_scope_audit_manifest_hash
    g3.neutral_contract_audit_pass = ev.neutral_contract_audit_pass
    g3.neutral_challenger_policy_hash = ev.neutral_challenger_policy_hash
    g3.neutral_scope_contract = {
        "model_id": ev.neutral_model_id,
        "interface_hash": ev.neutral_interface_hash,
        "resource_contract_hash": ev.neutral_resource_contract_hash,
        "k_manifest_hash": ev.neutral_k_manifest_hash,
        "e0_manifest_hash": ev.neutral_e0_manifest_hash,
        "web_manifest_hash": ev.neutral_web_manifest_hash,
        "opportunity_contract_hash": ev.neutral_opportunity_contract_hash,
        "challenger_policy_hash": ev.neutral_challenger_policy_hash,
    }
    g3.neutral_recovery = Recovery.RECOVERED
    g3.neutral_classifications = classifications
    g3.neutral_n_ind = len(
        {item.independent_unit_id for item in classifications if item.counts_in_n_ind}
    )
    g3.neutral_hits = hits
    g3.neutral_admissible_hits = hits
    g3.neutral_unresolved = malformed_neutral_pairs + sum(
        item.status
        in {
            AttemptStatus.UNRESOLVED,
            AttemptStatus.EXECUTION_CONTRACT_VIOLATION,
        }
        for item in classifications
    )
    g3.neutral_p_upper = None
    g3.neutral_reason = (
        "at least one separately integrity-validated neutral branch reached P; "
        "feedback-effect/sham errors cannot erase this positive witness"
    )
    g3.neutral_in_gate2_scope = lineage_empty_hit
    g3.lineage_empty_hit_refutes_core = lineage_empty_hit
    g3.reason = g3.neutral_reason


def _suppress_unvalidated_neutral_hit(g3: Gate3Result) -> None:
    """Prevent the full Gate-3 path from bypassing witness admissibility."""
    if g3.neutral_recovery != Recovery.RECOVERED:
        return
    g3.neutral_recovery = Recovery.INCONCLUSIVE
    g3.neutral_admissible_hits = 0
    g3.neutral_unresolved = max(1, g3.neutral_unresolved)
    g3.neutral_p_upper = None
    g3.neutral_reason = (
        "a raw score hit was observed, but no neutral candidate passed the "
        "separate positive-witness integrity check"
    )
    g3.lineage_empty_hit_refutes_core = False
    g3.reason = g3.neutral_reason


def evaluate(
    reg: Registration,
    gate1_ev: Gate1Evidence,
    gate2_ev: Gate2Evidence,
    gate3_ev: Optional[Gate3Evidence] = None,
    verifier_flaw: bool = False,
    *,
    integrity: Optional[IntegrityEvidence] = None,
) -> Certificate:
    input_errors: list[str] = []
    if not isinstance(reg, Registration):
        input_errors.append("registration must be a Registration record")
        reg = Registration(
            claim_id="invalid-registration",
            audit_family_id="invalid-family",
            model_id="invalid-model",
            interface_hash="invalid-interface",
            task_family_profile="invalid-task-family",
        )
    try:
        # The certificate owns a point-in-time snapshot.  Caller mutation after
        # evaluate() cannot rewrite the frozen thresholds or attestations.
        reg = deepcopy(reg)
        gate1_ev = deepcopy(gate1_ev)
        gate2_ev = deepcopy(gate2_ev)
        gate3_ev = deepcopy(gate3_ev)
        integrity = deepcopy(integrity)
    except (TypeError, ValueError, AttributeError) as exc:
        input_errors.append(f"input snapshot failed: {type(exc).__name__}: {exc}")
    try:
        reg_errors = input_errors + validate_registration(reg)
    except (
        TypeError,
        ValueError,
        AttributeError,
        ArithmeticError,
        OverflowError,
    ) as exc:
        reg_errors = [f"registration schema error: {type(exc).__name__}: {exc}"]
    # Any supplied lineage-empty neutral branch is a potential global recovery
    # witness even when only Core was requested.  It must not disappear merely
    # because the optional causal grade is not requested.
    effective_gate3 = gate3_ev
    try:
        integrity_errors = validate_integrity(reg, integrity, gate1_ev, gate2_ev)
    except (
        TypeError,
        ValueError,
        AttributeError,
        ArithmeticError,
        OverflowError,
    ) as exc:
        integrity_errors = [f"integrity schema error: {type(exc).__name__}: {exc}"]
    if type(verifier_flaw) is not bool:
        integrity_errors.append("verifier_flaw must be a boolean")
    gate2_hit_integrity_errors: list[str] = []
    gate2_hit_candidate_indices: list[int] = []
    if not reg_errors and isinstance(integrity, IntegrityEvidence):
        try:
            (
                gate2_hit_integrity_errors,
                gate2_hit_candidate_indices,
            ) = validate_gate2_hit_integrity(
                reg,
                integrity,
                gate1_ev,
                gate2_ev,
            )
        except (
            TypeError,
            ValueError,
            AttributeError,
            ArithmeticError,
            OverflowError,
        ) as exc:
            gate2_hit_integrity_errors = [
                f"Gate-2 hit schema error: {type(exc).__name__}: {exc}"
            ]
    try:
        gate3_integrity_errors = (
            validate_gate3_integrity(reg, integrity, gate2_ev, effective_gate3)
            if effective_gate3 is not None and isinstance(integrity, IntegrityEvidence)
            else []
        )
    except (
        TypeError,
        ValueError,
        AttributeError,
        ArithmeticError,
        OverflowError,
    ) as exc:
        gate3_integrity_errors = [f"Gate 3 schema error: {type(exc).__name__}: {exc}"]
    neutral_hit_integrity_errors: list[str] = []
    neutral_hit_pair_indices: list[int] = []
    neutral_ledger_integrity_errors: list[str] = []
    if effective_gate3 is not None and isinstance(integrity, IntegrityEvidence):
        try:
            (
                neutral_hit_integrity_errors,
                neutral_hit_pair_indices,
            ) = validate_neutral_hit_integrity(
                reg, integrity, gate2_ev, effective_gate3
            )
        except (
            TypeError,
            ValueError,
            AttributeError,
            ArithmeticError,
            OverflowError,
        ) as exc:
            neutral_hit_integrity_errors = [
                f"neutral-hit schema error: {type(exc).__name__}: {exc}"
            ]
        try:
            neutral_ledger_integrity_errors = (
                validate_neutral_recovery_ledger_integrity(
                    reg, effective_gate3, neutral_hit_integrity_errors
                )
            )
        except (TypeError, ValueError, AttributeError, OverflowError) as exc:
            neutral_ledger_integrity_errors = [
                f"neutral-ledger schema error: {type(exc).__name__}: {exc}"
            ]

    if reg_errors or integrity_errors:
        reason = "input failed registration/integrity validation"
        g1 = _empty_gate1(gate1_ev, reason)
        g2 = _empty_gate2(reason)
        g3 = (
            _empty_gate3(
                reason,
                neutral_contract_audit_pass=(
                    gate3_ev.neutral_contract_audit_pass
                    if isinstance(gate3_ev, Gate3Evidence)
                    and type(gate3_ev.neutral_contract_audit_pass) is bool
                    else None
                ),
            )
            if gate3_ev is not None
            else None
        )
        # A full-ledger failure blocks certification, but a separately valid
        # recovery candidate remains a monotone counterexample.  Score only
        # the candidate-local envelopes selected above.  Adequacy can remain
        # failed because search coverage is irrelevant once a hit exists.
        if (
            not reg_errors
            and integrity_errors
            and not gate2_hit_integrity_errors
            and gate2_hit_candidate_indices
            and type(verifier_flaw) is bool
        ):
            try:
                local_adequacy = (
                    gate2_ev.adequacy
                    if isinstance(gate2_ev.adequacy, AdequacyEvidence)
                    else AdequacyEvidence()
                )
                local_gate2_ev = Gate2Evidence(
                    controls=[
                        gate2_ev.controls[index]
                        for index in gate2_hit_candidate_indices
                    ],
                    adequacy=local_adequacy,
                )
                candidate_g1 = evaluate_gate1(reg, gate1_ev)
                candidate_g2 = evaluate_gate2(
                    reg,
                    local_gate2_ev,
                    gate1_ev.astar,
                )
                if candidate_g2.no_feedback_recovery == Recovery.RECOVERED:
                    candidate_g2.reason += (
                        "; separately validated local witness survived "
                        "unrelated full-ledger defects"
                    )
                    g1 = candidate_g1
                    g2 = candidate_g2
            except (
                TypeError,
                ValueError,
                AttributeError,
                ArithmeticError,
                OverflowError,
            ):
                # The ordinary fail-closed objects above remain authoritative
                # if the local witness cannot be evaluated.
                pass
    else:
        try:
            # Gate 1 owns the one canonical A* evaluation.  Gates 2/3 receive
            # that exact object; callers cannot substitute another target.
            g1 = evaluate_gate1(reg, gate1_ev)
            g2 = evaluate_gate2(reg, gate2_ev, gate1_ev.astar)
            g3 = None
        except (
            TypeError,
            ValueError,
            AttributeError,
            ArithmeticError,
            OverflowError,
        ) as exc:
            integrity_errors.append(
                f"evaluation input error: {type(exc).__name__}: {exc}"
            )
            reason = "gate evaluation failed closed"
            g1 = _empty_gate1(gate1_ev, reason)
            g2 = _empty_gate2(reason)
            g3 = (
                _empty_gate3(
                    reason,
                    neutral_contract_audit_pass=(
                        effective_gate3.neutral_contract_audit_pass
                        if isinstance(effective_gate3, Gate3Evidence)
                        and type(effective_gate3.neutral_contract_audit_pass) is bool
                        else None
                    ),
                )
                if effective_gate3 is not None
                else None
            )

        if not integrity_errors and effective_gate3 is not None:
            neutral_classifications: list[ControlClassification] = []
            neutral_witness_recovered = False
            neutral_lineage_empty_hit = False
            try:
                (
                    neutral_classifications,
                    neutral_witness_recovered,
                    neutral_lineage_empty_hit,
                ) = evaluate_neutral_hit_witness(
                    reg,
                    effective_gate3,
                    gate1_ev.astar,
                    integrity,
                    neutral_hit_pair_indices,
                )
            except (
                TypeError,
                ValueError,
                AttributeError,
                ArithmeticError,
                OverflowError,
            ) as exc:
                neutral_hit_integrity_errors.append(
                    f"neutral-hit evaluation error: {type(exc).__name__}: {exc}"
                )
            if gate3_integrity_errors:
                g3 = _empty_gate3(
                    "Gate 3 integrity validation failed",
                    neutral_contract_audit_pass=(
                        effective_gate3.neutral_contract_audit_pass
                        if type(effective_gate3.neutral_contract_audit_pass) is bool
                        else None
                    ),
                )
            else:
                try:
                    g3 = evaluate_gate3(reg, effective_gate3, gate1_ev.astar, integrity)
                except (
                    TypeError,
                    ValueError,
                    AttributeError,
                    ArithmeticError,
                    OverflowError,
                ) as exc:
                    gate3_integrity_errors.append(
                        f"Gate 3 evaluation input error: {type(exc).__name__}: {exc}"
                    )
                    g3 = _empty_gate3(
                        "Gate 3 evaluation failed closed",
                        neutral_contract_audit_pass=(
                            effective_gate3.neutral_contract_audit_pass
                            if type(effective_gate3.neutral_contract_audit_pass) is bool
                            else None
                        ),
                    )
            try:
                if neutral_witness_recovered:
                    _preserve_neutral_hit(
                        g3,
                        effective_gate3,
                        neutral_classifications,
                        lineage_empty_hit=neutral_lineage_empty_hit,
                        malformed_neutral_pairs=max(
                            0,
                            len(effective_gate3.pairs) - len(neutral_hit_pair_indices),
                        ),
                    )
                else:
                    _suppress_unvalidated_neutral_hit(g3)
            except (
                TypeError,
                ValueError,
                AttributeError,
                ArithmeticError,
                OverflowError,
            ) as exc:
                neutral_hit_integrity_errors.append(
                    f"neutral-hit reconciliation error: {type(exc).__name__}: {exc}"
                )

    gate3_core_errors = []
    if effective_gate3 is not None and neutral_ledger_integrity_errors:
        scope = getattr(effective_gate3, "checkpoint_scope", None)
        # Explicit lineage_prefix is outside Core's no-lineage scope.  Any
        # malformed or lineage-empty scope may contain a hidden Core witness,
        # so Core cannot remain certified.
        scope_binding_failed = any(
            token in error
            for error in neutral_ledger_integrity_errors
            for token in (
                "scope manifest",
                "global recovery-ledger",
                "checkpoint_scope",
                "checkpoint_hash",
            )
        )
        if scope != "lineage_prefix" or scope_binding_failed:
            gate3_core_errors = neutral_ledger_integrity_errors

    verdict = final_verdict(
        reg,
        reg_errors,
        integrity_errors,
        gate3_core_errors,
        g1,
        g2,
        g3,
        verifier_flaw=verifier_flaw,
        gate3_integrity_errors=gate3_integrity_errors,
    )
    certificate = Certificate(
        registration=reg,
        integrity=integrity,
        registration_errors=reg_errors,
        integrity_errors=integrity_errors,
        gate3_integrity_errors=gate3_integrity_errors,
        gate3_neutral_hit_integrity_errors=neutral_hit_integrity_errors,
        gate3_neutral_ledger_integrity_errors=neutral_ledger_integrity_errors,
        gate1=g1,
        gate2=g2,
        gate3=g3,
        verdict=verdict,
    )
    certificate._seal()
    return certificate
