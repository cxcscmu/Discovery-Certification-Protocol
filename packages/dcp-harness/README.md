# DCP Harness

`dcp-harness` is a lightweight evidence-producing shell for Auto Research. It
wraps Claude Code CLI, controls the agent's external actions, records the run,
performs the registered DCP ablations, and writes a Bundle that anyone can
check offline with `dcp-audit`.

The wrapper gives the agent only file tools. Claude's shell, Web, MCP, and
subagent tools are disabled. The only external action is a strict JSON file.
The harness can execute a task experiment or fetch an allowlisted HTTPS URL,
then records the request, raw response, model-visible text, workspace change,
model identity, and receipt hashes before starting a fresh model session.
Only the main run may use live Web access. Challengers and Gate 3 branches get
an exact replay of URLs observed by the main run.

A small task adapter supplies task semantics, private evaluation, baseline,
and truthful or neutral experiment feedback. Private scores are opened only
after every candidate in a phase has committed. The adapter registers all
thresholds and sample counts before the main run. It also supplies SHA-256
digests for the private verifier, held-out units, baseline policy, and feedback
policies; these materials are rechecked before every phase. The harness fills mechanical
evidence from the frozen ledger, invokes the unchanged `dcp-audit` kernel, and
immediately checks that the resulting Bundle replays exactly.

## Quickstart

```bash
python -m pip install dcp-harness
dcp-harness init my-audit
dcp-harness doctor --config my-audit/dcp-harness.json
dcp-harness run --config my-audit/dcp-harness.json --run my-audit/run-001
dcp verify my-audit/run-001/bundle
```

The commands can also be run separately and resumed safely.

```bash
dcp-harness capture   --config my-audit/dcp-harness.json --run my-audit/run-001
dcp-harness challenge --config my-audit/dcp-harness.json --run my-audit/run-001
dcp-harness gate3     --config my-audit/dcp-harness.json --run my-audit/run-001
dcp-harness finalize  --config my-audit/dcp-harness.json --run my-audit/run-001
dcp-harness status    --config my-audit/dcp-harness.json --run my-audit/run-001
```

## Trust boundary

The harness owns agent execution, action mediation, Web capture and replay,
randomization, checkpoints, receipts, and append-only ledgers. The Python task
adapter is trusted only for the parts that necessarily depend on the task. It
prepares public files, runs the private verifier, and defines truthful and
neutral observations. `assemble_evidence()` derives scores, hashes, counts,
and branch records mechanically. Its `AuditAttestations` input contains the
small set of task-specific judgments that cannot be inferred from bytes. Every
attestation defaults to false.

The model API connection is infrastructure transport, not a research Web
channel. In container mode the agent has no tool capable of starting an
arbitrary network request. A task adapter that talks to another service must
treat that service as a registered experiment and return its observation
through the audited action channel.

## Current scope

The alpha supports one local auditor, Claude Code CLI, Docker isolation,
allowlisted HTTPS capture, exact observed-URL replay, Gate 2 challenges, Gate 3
paired feedback and sham branches, pre-action infrastructure replacement,
resumable phases, and deterministic local Bundles. Host mode is available for
development but cannot attest private isolation. Local Bundles always retain
`formal_certificate_issued=false`; formal countersigning belongs to a future
external registry rather than this package.

See the repository [usage guide](../../README.md#run-a-prospective-audit) for
the complete CLI and Python examples.

Licensed under Apache-2.0.
