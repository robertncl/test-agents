# Copilot & Docker Sandbox POC Test Agents

A **stdlib-only Python test-harness** that operationalises the
*GitHub Copilot App — Cloud & Local Sandbox Functionality and Security-Control
Verification* POC plan (`Copilot-Sandbox-POC-Plan.md`).

It encodes **61 test cases** — the plan's 49 (functional `TC-F-*`, security
`TC-S-*`, adversarial `TC-A-*`, audit `TC-G-*`) plus a **12-case Docker sandbox
baseline** (`TC-D-*`) — as runnable, evidence-producing **agents**, one per
sandbox surface. Each case carries its method, exact commands/prompts, pass
criteria, regulatory theme (plan §7) and go/no-go criterion (plan §9).

> **Scaffold by design.** Per the POC scope, agents do **not** execute against a
> live environment. They generate the evidence-pack scaffolding (Appendix B),
> you run each case by hand in the ring-fenced POC org, record the disposition,
> and the harness rolls everything up into a traceability matrix and a weighted
> go/no-go scorecard. `execution.dry_run` is `true` in config to make this explicit.

## Why agents (not one script)

Each agent maps to a distinct surface and owner in the plan:

| Agent (key) | Surface | Cases | Plan § |
|---|---|---|---|
| `docker` | Docker sandbox (isolation **baseline**) | `TC-D-01..12` | reference bar for §3.1 |
| `local` | Copilot local sandbox (Microsoft MXC) | `TC-F-01..04`, `TC-S-01..03` | §5.1 / §6.1 |
| `cloud` | Copilot cloud sandbox (Azure Container Apps) | `TC-F-05..09`, `TC-S-04..07` | §5.2 / §6.1 |
| `app` | GitHub Copilot app (Interactive/Plan/Autopilot) | `TC-F-10..16` | §5.3 |
| `governance` | Enterprise governance & policy | `TC-S-08..13` | §6.2 |
| `guardrail` | Agent guardrail chain | `TC-S-14..21` | §6.3 |
| `adversarial` | Known-bypass / assume-breach | `TC-A-01..08` | §6.4 |
| `audit` | Audit, detection & evidence | `TC-G-01..04` | §6.5 |

The Docker agent is the **baseline**: the same isolation controls (filesystem,
egress, capabilities, resource limits, escape, ephemerality, supply chain)
expressed as container-runtime checks — the bar Copilot's local sandbox must meet.

## Quick start

```bash
# 0. Requires Python 3.10+ only. No pip install.
cp config/poc.example.json config/poc.json     # then edit for your POC org

python run.py validate                          # check config + catalogue (61 cases)
python run.py list                              # all agents and cases
python run.py show TC-S-19                       # one case, with ${tokens} resolved

# 1. Scaffold an Appendix-B evidence record per case (start with gate-blocking P1)
python run.py plan --priority P1
python run.py plan                               # then the rest

# 2. Execute each case by hand in the ring-fenced POC org, then record the result
python run.py record TC-D-01 \
    --disposition PASS --tester robert \
    --note "host paths unreachable; only /work visible" \
    --agent-action "container could not read ~/.ssh or /etc/host-secret" \
    --artifact evidence/artifacts/tc-d-01.log \
    --alert SENT-12345

# 3. Roll up reports (regenerate any time)
python run.py report
#   reports/TRACEABILITY.md        - every case -> framework clauses (§7)
#   reports/GO-NO-GO-SCORECARD.md  - weighted readiness + decision logic (§9)
#   reports/RUN-SUMMARY.md         - dispositions + outstanding P1s
#   reports/EVIDENCE-INDEX.md      - the evidence pack index
```

Dispositions: `PASS`, `FAIL`, `PARTIAL` (passed with a documented compensating
control), `SKIPPED`, `BLOCKED`, `MANUAL_REVIEW`, `NOT_RUN`.

## Configuration (`config/poc.json`)

Drives `${token}` substitution in every case so the same definitions adapt to
your environment: `${org}`, `${mirror_host}`, `${canary_endpoint}`,
`${image_mirror}`, `${run_flags}`, `${honeytoken_pat}`, `${actions_secret}`,
`${copilot_env_secret}`. It also records the policy posture (cloud-sandbox gate,
firewall mode, Autopilot) into each evidence record's config snapshot.

**`config/poc.json` is git-ignored** (it names internal hosts). Commit only the
example.

## Safety (read before adversarial testing)

The `adversarial` agent reproduces published 2026 bypasses. Run it **only** under
these operational guardrails — see `docs/SAFETY.md`:

- ring-fenced POC org / disposable repos only, **never** production;
- **synthetic honeytokens only**, wired to Sentinel — never real credentials;
- responsible disclosure to GitHub for any container/sandbox escape;
- `TC-D-05` (resource-storm) and escape probes are destructive primitives — keep
  `dry_run` on and run only on a disposable host.

## Layout

```
core/        model, frameworks (§7/§9), config, evidence (Appendix B), agent, report
agents/      one module per surface (docker, local, cloud, app, governance,
             guardrail, adversarial, audit)
config/      poc.example.json (copy to poc.json)
evidence/    generated per-case records (git-ignored) + artifacts/
reports/     generated markdown roll-ups (git-ignored)
run.py       orchestrator CLI
docs/        SAFETY.md, AGENTS.md
```

## Extending

- **Add a case:** append a `TestCase(...)` to the relevant `agents/*.py`, give it
  a `theme` (→ `core/frameworks.THEMES`) and, if gate-weighted, a `criterion`
  (→ `CRITERIA`). `python run.py validate` checks ids/themes/criteria.
- **Make a case self-execute later:** set its `live_action` hook; the scaffold
  model already carries the slot. (Out of scope for this build.)

> Point-in-time evaluation of public/technical-preview software. Re-confirm every
> control against current GitHub docs at execution (POC plan Appendix C).
