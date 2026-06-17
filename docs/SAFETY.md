# Safety & Rules of Engagement

The `adversarial` agent (`TC-A-*`) and several isolation probes reproduce
**published attacks and destructive primitives**. They exist to measure *residual
exposure* and validate *detection* — not to weaponise. Treat this as a controlled
security test with explicit rules of engagement.

## Hard rules

1. **Ring-fenced only.** Run exclusively in the dedicated POC organisation /
   disposable repos. No production repos, no production Azure subscriptions, Key
   Vaults, or the live DevSecOps platform (POC plan §4).
2. **Honeytokens only.** Every secret used in a test is synthetic and wired to a
   Microsoft Sentinel alert. **Never** place real credentials in any environment
   under test — including the `copilot`/Agents environment.
3. **Assume-breach posture.** The goal of `TC-A-*` is to show that *successful
   injection produces no security impact*. If a test exfiltrates a honeytoken,
   that is data — record it, confirm containment + detection, do not escalate.
4. **Responsible disclosure.** Any container/sandbox escape (`TC-A-08`, `TC-D-06`)
   or undocumented control gap is reported to GitHub via responsible disclosure
   before any wider discussion.
5. **Destructive primitives stay gated.** `TC-D-05` (fork/memory storm) and escape
   probes can disrupt a host. Keep `execution.dry_run = true`; only run them, if
   at all, on a throwaway host you own.

## Pre-flight checklist (POC plan §4)

- [ ] Preview terms reviewed by Legal/Procurement.
- [ ] Data-residency stance confirmed with Compliance **before** any code enters a
      cloud sandbox (GitHub-hosted Azure).
- [ ] Honeytokens deployed and Sentinel alerting verified.
- [ ] Kill-switch ready: disable **Cloud Sandbox access** policy + delete POC org.
- [ ] `config/poc.json` reviewed; `secrets.policy` states honeytoken-only usage
      (`python run.py validate` warns if not).

## Disposition discipline

- Use `PARTIAL` when a control holds *only* with a compensating control — and
  record that control, its owner, and a review date in the `--note`.
- A `BLOCKED` P1 (could not execute) is **not** a pass. The scorecard treats
  P1 `FAIL`/`BLOCKED` as gate-blocking under the §9 decision logic.
