"""Deterministic evaluation core for the Discovery Certification Protocol.

The package evaluates recorded outcomes, no-lineage recovery attempts, and
optional paired feedback evidence. It is LLM-free and performs no network
access. Use :func:`dcp.api.verify_bundle` to replay a published Audit Bundle.
"""

from dcp.evaluate import evaluate
from dcp.facade import (
    AuditRecord,
    STRICT_CORE_PROFILE_V1,
    audit,
    strict_core_registration,
)
from dcp.integrity import (
    artifact_results_hash,
    adequacy_evidence_hash,
    branch_result_hash,
    feedback_pairs_manifest_hash,
    gate3_neutral_recovery_ledger_manifest_hash,
    gate3_neutral_scope_manifest_hash,
    gate3_scope_manifest_hash,
    private_results_manifest_hash,
    recovery_ledger_manifest_hash,
    sham_pairs_manifest_hash,
    unit_manifest_hash,
)
from dcp.registration import Registration, validate_registration
from dcp.types import InconclusiveClass, IntegrityEvidence

__all__ = [
    "audit",
    "AuditRecord",
    "evaluate",
    "strict_core_registration",
    "STRICT_CORE_PROFILE_V1",
    "Registration",
    "IntegrityEvidence",
    "InconclusiveClass",
    "unit_manifest_hash",
    "artifact_results_hash",
    "adequacy_evidence_hash",
    "private_results_manifest_hash",
    "branch_result_hash",
    "feedback_pairs_manifest_hash",
    "gate3_neutral_scope_manifest_hash",
    "gate3_neutral_recovery_ledger_manifest_hash",
    "gate3_scope_manifest_hash",
    "recovery_ledger_manifest_hash",
    "sham_pairs_manifest_hash",
    "validate_registration",
]

__version__ = "0.4.2"
