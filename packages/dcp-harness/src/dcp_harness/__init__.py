"""Controlled evidence production for DCP audits."""

from dcp_harness.adapter import (
    AuditMaterials,
    BaseTaskAdapter,
    EpisodeContext,
    EpisodeEvaluation,
    EvidencePackage,
    Phase,
    RegistrationContext,
    RunView,
)
from dcp_harness.config import HarnessConfig, load_config
from dcp_harness.evidence import AuditAttestations, assemble_evidence
from dcp_harness.runtime import Harness

__all__ = [
    "AuditMaterials",
    "BaseTaskAdapter",
    "AuditAttestations",
    "EpisodeContext",
    "EpisodeEvaluation",
    "EvidencePackage",
    "Harness",
    "HarnessConfig",
    "Phase",
    "RegistrationContext",
    "RunView",
    "assemble_evidence",
    "load_config",
]

__version__ = "0.1.0a1"
