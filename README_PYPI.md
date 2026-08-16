# DCP Audit

`dcp-audit` is the small offline verifier for the Discovery Certification
Protocol. It checks a content-addressed Audit Bundle and deterministically
replays the recorded DCP decision. It does not call a model, access the Web, or
rerun the original Auto-Research system.

## Install

Use an isolated environment because another distribution already uses the
top-level `dcp` package name.

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install dcp-audit
```

The numerical dependencies are pinned in the first release because a DCP
certificate is compared with its fresh replay exactly.

## Verify a Bundle

```bash
dcp verify path/to/audit-bundle
```

The default output is a short, human-readable summary.

```text
Replay: VERIFIED
Bundle: sha256:...
Profile: full_audit_v1
Core: certified
Evidence: certified
Provenance: local_content_addressed_only
Formal issuance: no
```

Use JSON for automation.

```bash
dcp verify path/to/audit-bundle --json
```

The installed `dcp` command is the public CLI. The older
`python -m dcp verify ...` entry point remains available with its original
JSON-only output for compatibility with frozen audit workflows.

Exit status `0` means that the manifest, payload hashes, and kernel replay
agree. It does not mean that the scientific verdict must be `certified`.
Refuted and inconclusive decisions can also be validly replayed. Exit status
`1` means verification failed, while `2` means the command was used
incorrectly.

## Python API

```python
from dcp.api import verify_bundle

report = verify_bundle("path/to/audit-bundle")
if not report["ok"]:
    raise RuntimeError(report["errors"])

verdict = report["replayed_verdict"]
print(verdict["core"], verdict["evidence"])
```

## Scope

This release supports the Core evidence bundle and `full_audit_v1` profiles.
It verifies local content integrity and deterministic kernel replay. It does
not authenticate who ran the experiment, validate external registry
signatures, or issue a formal certificate. Those boundaries are stated in
every verification report.

The GitHub reference repository contains complete offline examples under
`examples/audits/` and a separate generalized evidence-producing harness. Each
published Bundle retains its own producer and provenance record.
