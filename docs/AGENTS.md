# Agents & Test-Case Catalogue (plan v0.1)

Nine agents, one per group of the GitHub Copilot App POC plan. 47 cases total:
SC-01..26 (B.7, all must-pass), FN-01..04 (B.8), DP-01..05 (B.9), DK-01..12
(Docker baseline, Group 2 supplement). Run `python run.py list` for the live view.

Each `TestCase` mirrors the Appendix B template: `id`, `group`, `control`
(control under test), `preconditions[]`, `method[]` (steps), `commands[]`,
`expected` (pass result), `must_pass`, `negative`, and `measure` (FN cases).
`${tokens}` resolve from `config/poc.json`.

## `group2` — G2 Containment, isolation & egress (set up first) · all must-pass
| ID | Control | Negative |
|---|---|---|
| SC-07 | Local sandbox isolation | yes |
| SC-08 | Local sandbox central enforcement (Intune) | yes |
| SC-09 | Worktree session isolation | yes |
| SC-10 | Cloud sandbox ephemerality & deletion | - |
| SC-11 | Agent firewall (egress allowlist) | yes |
| SC-12 | Agent firewall change control | yes |

## `docker` — DK Docker sandbox baseline (Group 2 supplement)
Container-runtime reference for the same isolation properties (supports SC-07/09/10/11).

| ID | Control | | ID | Control |
|---|---|---|---|---|
| DK-01 | Filesystem isolation | | DK-07 | Ephemerality / no residue |
| DK-02 | Network egress restriction | | DK-08 | Read-only root filesystem |
| DK-03 | Capability restriction | | DK-09 | Image provenance / supply chain |
| DK-04 | Non-root + no-new-privileges | | DK-10 | Seccomp / AppArmor |
| DK-05 | Resource limits (DoS) | | DK-11 | Secret isolation in env |
| DK-06 | Container escape probes | | DK-12 | Egress-attempt detection |

## `group1` — G1 Identity, access & action gating · all must-pass
SC-01 trigger gating by write access · SC-02 branch confinement · SC-03 credential
confinement · SC-04 human merge gate · SC-05 self-approval prevention ·
SC-06 workflow run gating.

## `group3` — G3 Generated-code assurance · all must-pass
SC-13 CodeQL pre-check · SC-14 dependency/malware check · SC-15 secret scanning ·
SC-16 `/security-review` skill.

## `group4` — G4 AI-specific threats · all must-pass · **read docs/SAFETY.md**
SC-17 hidden-instruction filtering · SC-18 indirect prompt injection via repo
content · SC-19 autonomy boundary (automations) · SC-20 autopilot + Agent Merge chain.

## `group5` — G5 MCP · all must-pass
SC-21 MCP allowlist enforcement · SC-22 MCP data egress.

## `group6` — G6 Auditability & monitoring · all must-pass
SC-23 commit attribution & signing · SC-24 agentic audit-log capture ·
SC-25 SIEM ingestion & alerting · SC-26 activity reporting.

## `functional` — FN Functional / value (measures, not must-pass)
FN-01 prompt->plan->draft PR · FN-02 parallel agents via My Work · FN-03 Copilot
code review value · FN-04 Canvas-based steering.

## `data` — DP Data protection, residency & retention (B.9, compliance gate)
DP-01 data-flow map · DP-02 residency position · DP-03 retention table ·
DP-04 content exclusion · DP-05 PII handling.

## Gate (B.2 / B.12)
- **Must-pass:** 100% of SC cases pass; 0 critical bypasses.
- **Negative tests:** every attempted bypass blocked **and** logged (PASS + evidence ref).
- **Compliance (B.9):** evidenced data-flow + documented residency gate GO vs GO-WITH-CONDITIONS.
- **Governance:** locked, exportable golden-policy baseline (Appendix A).
