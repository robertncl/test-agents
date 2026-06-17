# GitHub Copilot App POC — Security Control Test Agents

A **stdlib-only Python test-harness** that operationalises the
*GitHub Copilot App — Proof of Concept & Security Control Verification Plan* (v0.1,
`GitHub-Copilot-App-POC-Security-Verification-Plan.md`).

It encodes the plan's test cases as runnable, evidence-producing **agents**, one
per plan group — **47 cases**: security `SC-01..26` (B.7, all must-pass),
functional `FN-01..04` (B.8), data-protection `DP-01..05` (B.9), plus a **Docker
sandbox baseline** `DK-01..12` that supplements Group 2. Each case carries its
preconditions, method/steps, exact commands/prompts, and expected (pass) result.

> **Scaffold by design.** Agents do **not** execute against a live environment
> (`execution.dry_run: true`). They generate the Appendix B evidence scaffolding,
> you run each case by hand in the ring-fenced POC org, record the result, and the
> harness rolls everything into a coverage matrix, a B.12 go/no-go scorecard, the
> Appendix C evidence log, and the Appendix A golden-policy baseline.

## Agents (one per plan group)

| Agent (key) | Group | Cases |
|---|---|---|
| `group2` | **G2 — Containment, isolation & egress** (set up first) | SC-07..12 |
| `docker` | DK — Docker sandbox baseline (Group 2 supplement) | DK-01..12 |
| `group1` | G1 — Identity, access & action gating | SC-01..06 |
| `group3` | G3 — Generated-code assurance & defensive surfaces | SC-13..16 |
| `group4` | G4 — AI-specific threats | SC-17..20 |
| `group5` | G5 — MCP | SC-21..22 |
| `group6` | G6 — Auditability & monitoring | SC-23..26 |
| `functional` | FN — Functional / value scenarios | FN-01..04 |
| `data` | DP — Data protection, residency & retention | DP-01..05 |

All **26 SC cases are must-pass** (bypass-critical); 15 are **negative** tests
(attempted bypasses that must be blocked **and** logged). The gate (B.2 / B.12):
100% of must-pass cases pass, 0 critical bypasses, every negative test blocked and
logged.

## Quick start

```bash
# Requires Python 3.10+ only. No pip install.
cp config/poc.example.json config/poc.json     # then edit for your POC enterprise/org

python run.py validate                          # check config + catalogue (47 cases)
python run.py list --group G2                    # Group 2, set up first
python run.py show SC-11                          # one case, with ${tokens} resolved

# 1. Scaffold Appendix-B evidence records (Group 2 first, then the rest)
python run.py plan --group G2
python run.py plan                               # everything

# 2. Execute each case in the ring-fenced POC org, then record the result
python run.py record SC-11 \
    --status PASS --tester robert \
    --actual "agent curl to canary blocked; PR warning raised naming address+command" \
    --evidence reports/sc-11-pr-warning.png --evidence SENT-9921 \
    --note "egress attempt logged in Sentinel" --linked-risk R-03

# 3. Roll up reports (regenerate any time)
python run.py report
#   reports/COVERAGE.md                 - every case -> group, must-pass/negative
#   reports/GO-NO-GO-SCORECARD.md       - must-pass gate + B.12 decision logic
#   reports/RUN-SUMMARY.md              - status counts + outstanding must-pass
#   reports/EVIDENCE-LOG.md             - Appendix C evidence log
#   reports/GOLDEN-POLICY-BASELINE.md   - Appendix A policy checklist + B.2 criteria
```

Statuses: `PASS`, `FAIL`, `BLOCKED`, `PARTIAL` (GO-with-conditions / compensating
control), `NOT_APPLICABLE`, `NOT_RUN`.

## Configuration (`config/poc.json`)

Drives `${token}` substitution so the same case definitions adapt to your
environment: `${enterprise}`, `${org}`, `${mirror_host}`, `${canary_endpoint}`,
`${image_mirror}`, `${run_flags}`, `${mcp_allowlisted}`, `${mcp_nonallowlisted}`,
`${excluded_path}`, `${honeytoken_pat}`, `${fake_api_key}`, `${actions_secret}`.
It also records the policy posture (autopilot, firewall lockdown, branch
protection, content exclusion, residency) into each evidence record's config
snapshot. **`config/poc.json` is git-ignored** (it names internal hosts).

## Safety (read before Group 4 / adversarial testing)

Group 4 (`SC-17..20`) and several Group 2 / Docker probes reproduce real attacks
and destructive primitives. Run them **only** under the rules in `docs/SAFETY.md`:
ring-fenced POC org / disposable repos, **synthetic honeytokens & PII only** wired
to Sentinel, responsible disclosure for any escape, and `DK-05` (resource-storm) /
escape probes kept under `dry_run` on a disposable host.

## Layout

```
core/        model, frameworks (groups/B.2/B.12/Appendix A), config, evidence
             (Appendix B), agent, report
agents/      one module per group (group1..group6, functional, data, docker)
config/      poc.example.json (copy to poc.json)
evidence/    generated per-case records (git-ignored) + artifacts/
reports/     generated markdown roll-ups (git-ignored)
run.py       orchestrator CLI
docs/        SAFETY.md, AGENTS.md
GitHub-Copilot-App-POC-Security-Verification-Plan.md   - the implemented spec (v0.1)
```

## Extending

- **Add a case:** append a `TestCase(...)` to the relevant `agents/*.py`, set its
  `group` (-> `core/frameworks.GROUPS`) and `must_pass` / `negative` flags.
  `python run.py validate` checks ids/groups and duplicates.
- **Make a case self-execute later:** set its `live_action` hook (slot exists; out
  of scope for this scaffold build).

> Point-in-time evaluation of public/technical-preview software. Re-confirm every
> control against current GitHub docs at execution.
