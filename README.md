<h1 align="center">Discovery Certification Protocol</h1>

<p align="center">
  <a href="https://github.com/cxcscmu/Discovery-Certification-Protocol"><img src="https://img.shields.io/badge/GitHub-Repository-181717?logo=github" alt="GitHub repository"></a>
  <a href="https://arxiv.org/abs/XXXX.XXXXX"><img src="https://img.shields.io/badge/Paper-arXiv-b31b1b?logo=arxiv" alt="arXiv paper"></a>
  <a href="https://pypi.org/project/dcp-audit/"><img src="https://img.shields.io/pypi/v/dcp-audit?label=dcp-audit&logo=pypi&color=3775A9" alt="dcp-audit on PyPI"></a>
  <a href="https://pypi.org/project/dcp-harness/"><img src="https://img.shields.io/pypi/v/dcp-harness?label=dcp-harness&logo=pypi&color=3775A9" alt="dcp-harness on PyPI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache--2.0-D22128" alt="Apache-2.0 license"></a>
</p>

**Scores Alone Do Not Prove Discovery.** The Discovery Certification Protocol
(DCP) audits whether a measured gain from an AI research agent depends on the
adaptive evidence produced during a registered research run. It evaluates the
numeric outcome. It does not ask an LLM to decide whether two methods are
semantically equivalent, and it does not claim historical priority.

This repository publishes two Python packages.

| Package | Import | Command | Use it when |
| --- | --- | --- | --- |
| [`dcp-audit`](https://pypi.org/project/dcp-audit/) | `dcp` | `dcp verify` | You already have an Audit Bundle and want to verify it offline |
| [`dcp-harness`](https://pypi.org/project/dcp-harness/) | `dcp_harness` | `dcp-harness` | You want to capture a prospective agent run, run its controls, and produce an Audit Bundle |

The verifier is deliberately small and model-free. The harness is a separate
Claude Code CLI wrapper because producing evidence requires agent execution,
task-specific experiments, Web capture, and registered ablations.

## Install

Python 3.11 or newer is required. Use an isolated environment because another
distribution also uses the top-level `dcp` import name.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install dcp-audit dcp-harness
```

To install the current source checkout instead of PyPI releases, run:

```bash
python -m pip install -e ".[dev]"
python -m pip install -e packages/dcp-harness
```

## Verify an existing Audit Bundle

Verification is offline. It checks the Bundle manifest and payload hashes,
recomputes the protocol decision from the recorded evidence, and compares the
fresh decision with the saved certificate.

```bash
dcp verify examples/audits/sqlite-web
dcp verify examples/audits/virtual-catalyst
```

A successful replay prints a short report.

```text
Replay: VERIFIED
Bundle: sha256:...
Profile: full_audit_v1
Core: certified
Evidence: certified
Provenance: local_content_addressed_only
Formal issuance: no
```

Use `--json` in scripts or CI.

```bash
dcp verify examples/audits/sqlite-web --json > verification.json
```

Exit code `0` means the evidence and deterministic replay agree. It does not
mean the verdict must be `certified`. A correctly replayed `refuted` or
`inconclusive` result also exits with `0`. Exit code `1` means verification
failed, while `2` means the CLI invocation was invalid.

### Verify from Python

```python
from dcp.api import verify_bundle

report = verify_bundle("examples/audits/sqlite-web")
if not report["ok"]:
    raise RuntimeError("; ".join(report["errors"]))

verdict = report["replayed_verdict"]
print("Core:", verdict["core"])
print("Evidence:", verdict["evidence"])
print("Bundle:", report["bundle_id"])
```

`report["ok"]` is the replay-integrity result. The scientific decision is in
`report["replayed_verdict"]`. Treat a saved verdict as untrusted whenever
`report["ok"]` is false.

## What DCP checks

DCP uses up to three registered checks.

1. **Outcome check.** The claimed artifact must be valid and must beat a frozen
   baseline by the registered margin on a held-out evaluator.
2. **No-lineage recovery check.** Independent matched challengers receive the
   public task material and frozen observed-Web packet, but not the adaptive
   research lineage. Any valid challenger that reaches the registered outcome
   region refutes the Core claim. Non-recovery can certify Core only when the
   registered sample bound and control-adequacy checks pass.
3. **Feedback check.** For an Evidence claim, paired branches compare truthful
   experimental feedback with a calibrated neutral channel from a frozen
   checkpoint. This tests whether the run's feedback carried a measurable
   increment.

All thresholds, budgets, model identity, task materials, held-out evaluator,
challenge distribution, and branch policies are frozen before the main run.
The output is scoped to that registration.

## Run a prospective audit

`dcp-harness` is a lightweight wrapper around Claude Code CLI. It records the
main research loop, mediates task experiments, captures allowed Web responses,
launches the registered no-lineage and feedback controls, and writes a Bundle
for `dcp-audit`.

For a certifying run you need:

- Claude Code CLI installed and authenticated
- a pinned Docker image that contains the CLI and runtime dependencies
- a public starter workspace for the agent
- a trusted task adapter with the private evaluator and feedback policies
- a preregistered budget and statistical plan

Host execution is available for development, but it does not attest private
isolation. Keep API credentials and private evaluator data outside the public
workspace and out of version control.

### 1. Create an audit project

```bash
dcp-harness init my-audit
```

This creates:

```text
my-audit/
  dcp-harness.json
  task_adapter.py
  workspace/
```

Put only public starting files in `workspace/`. Complete `task_adapter.py` with
the task's experiment handler, private evaluator, frozen baseline, checkpoint
rule, and evidence builder. The generated adapter is an executable template
with every required method and a conservative registration example.

### 2. Configure the agent, Web policy, and audit size

Edit `dcp-harness.json`. A typical Web-enabled section looks like this:

```json
{
  "schema": "dcp_harness_config_v1",
  "claim_id": "my-claim-v1",
  "source_workspace": "workspace",
  "task_adapter": "task_adapter.py:adapter",
  "task_options": {},
  "agent": {
    "backend": "claude-code",
    "execution": "docker",
    "model": "your-registered-model",
    "accepted_model_ids": ["your-registered-model"],
    "claude_binary": "claude",
    "container_image": "your-image@sha256:...",
    "dotenv": ".env",
    "effort": "high",
    "max_budget_usd": 10.0,
    "timeout_seconds": 1800,
    "max_turns": 8,
    "memory_mb": 3072,
    "cpus": 2.0
  },
  "web": {
    "enabled": true,
    "allowed_hosts": ["docs.example.org"],
    "allow_subdomains": false,
    "max_requests": 20,
    "max_redirects": 3,
    "max_raw_bytes": 2000000,
    "max_delivered_bytes": 300000,
    "timeout_seconds": 30
  },
  "audit": {
    "grade": "evidence",
    "challenger_episodes": 96,
    "positive_control_episodes": 45,
    "feedback_pairs": 30,
    "sham_pairs": 60,
    "max_feedback_pair_replacements": 2,
    "max_sham_pair_replacements": 2,
    "checkpoint_scope": "lineage_prefix"
  }
}
```

The numbers above illustrate the packaged template. Select them prospectively
from the claim's registered error and cost plan rather than copying them
blindly.

### 3. Check the frozen interface

```bash
dcp-harness doctor --config my-audit/dcp-harness.json
```

`doctor` loads and hashes the adapter, checks the Claude Code executable and
reported model identity, and validates the configured execution environment.
Resolve every failure before beginning a prospective run.

### 4. Run and finalize the audit

The shortest path runs all applicable phases and then replay-checks the new
Bundle.

```bash
dcp-harness run \
  --config my-audit/dcp-harness.json \
  --run my-audit/run-001

dcp verify my-audit/run-001/bundle
```

Long audits can be run phase by phase. Completed phases are resumable.

```bash
dcp-harness capture   --config my-audit/dcp-harness.json --run my-audit/run-001
dcp-harness challenge --config my-audit/dcp-harness.json --run my-audit/run-001
dcp-harness gate3     --config my-audit/dcp-harness.json --run my-audit/run-001
dcp-harness finalize  --config my-audit/dcp-harness.json --run my-audit/run-001
dcp-harness status    --config my-audit/dcp-harness.json --run my-audit/run-001
```

Add `--json` to any command that supports it for machine-readable output.

### Drive the harness from Python

```python
from dcp_harness import Harness, load_config

config = load_config("my-audit/dcp-harness.json")
run = Harness(config, "my-audit/run-001")

run.capture()
run.challenge()
if config.audit.grade == "evidence":
    run.gate3()
certificate = run.finalize()

print(certificate["bundle_id"])
print(certificate["verdict"])
```

The same run directory must not be opened with a different frozen config,
adapter, model interface, or registration. Such a mismatch fails closed.

## Web capture and replay

The harness does not expose Claude Code's direct shell, Web, MCP, or subagent
tools to the research agent. The agent requests a Web fetch or task experiment
through a recorded JSON action. Only the main run may fetch a new allowlisted
HTTPS URL. The gateway stores the raw response and the exact model-visible
text, together with URL, redirect, peer, size, and hash-chain receipts.
Challengers and Gate 3 branches can only replay canonical URLs already captured
by the main run, and replay never accesses the network.

Task-specific laboratory calls should be implemented as registered
`experiment` actions in the trusted adapter so that both the request and the
returned observation enter the same ledger.

## Included examples

Four self-contained Bundles are under [`examples/audits`](examples/audits).
They require no model key or network access.

| Example | Result |
| --- | --- |
| `sqlite-web` | Core certified, Evidence certified |
| `virtual-catalyst` | Core certified, Evidence certified |
| `sqlite-core` | Core certified, Evidence not tested |
| `device-calibration-core` | Core certified, Evidence not tested |

Every example is bound to its frozen task, model, budget, evaluator, and
challenge policy. See [`examples/README.md`](examples/README.md) for the exact
Bundle identifiers and plain-language task descriptions.

## Local development

Run the verifier tests and all public Bundle replays:

```bash
python -m pytest -q \
  tests/test_dcp_bundle.py \
  tests/test_dcp_facade.py \
  tests/test_dcp_v2_smoke.py \
  tests/test_public_release.py
```

Run the harness tests, which use a deterministic fake backend and offline Web
fixtures:

```bash
PYTHONPATH=.:packages/dcp-harness/src \
  python -m pytest packages/dcp-harness/tests -q
```

Build both distributions:

```bash
python -m build
python -m build packages/dcp-harness
```

## License

Licensed under the [Apache License 2.0](LICENSE).
