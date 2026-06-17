# Copilot POC — Security Control Test Agents

Test agents that execute the security-control verification cases from
[`GitHub-Copilot-App-POC-Security-Verification-Plan.md`](GitHub-Copilot-App-POC-Security-Verification-Plan.md)
(section **B.7**) against a **Docker sandbox** standing in for the GitHub Copilot
**local** and **cloud** sandboxes.

> **Status:** **Group 2 — Containment, isolation & egress (SC-07 … SC-12)** is implemented.
> The framework is group-agnostic; other groups (SC-01…, FN-*, DP-*) plug in the same way.

Each agent maps 1:1 to a test case. Where a control can be exercised locally it runs
**real probes** and returns `PASS`/`FAIL` with evidence; where it needs a live
GitHub/Intune tenant it returns `BLOCKED` with the exact **manual steps** to capture
evidence. Nothing is faked into a green result.

---

## Quick start

```bash
# 1. List the agents
python run.py list --group 2

# 2. Pure-local cases need no Docker (git + file-permission models)
python run.py run SC-09 SC-12 -v

# 3. Bring up the hardened sandbox target for the isolation/egress cases
sandbox/launch.sh up                       # builds + runs the hardened container

# 4. Run the full group; write a JSON result set + a Markdown evidence log
python run.py run --group 2 -v \
    --json out/results.json --evidence out/evidence.md

# 5. Tear down
sandbox/launch.sh down
```

No third-party Python packages — standard library only (Python 3.9+). `docker` and
`git` are used by some agents and are detected at runtime.

---

## What each agent does

| ID | Control | How it's tested here | Live run |
|----|---------|----------------------|----------|
| **SC-07** | Local sandbox isolation | Execs 7 probes inside the hardened container: read outside `/workspace`, write outside it, outbound TCP/HTTP, privilege escalation (`mount`, `su`). Secure = all blocked. | Docker |
| **SC-08** | Local sandbox central enforcement | Verifies the root-owned, read-only policy marker can't be tampered with by the non-root user; checks `userCanDisable=false`. Intune distribution is a manual step. | Docker + manual |
| **SC-09** | Worktree session isolation | Builds a real two-worktree git repo; proves session B can't see session A's uncommitted files/edits and each session has an independent HEAD. Optional cross-container volume check. | Host (git) |
| **SC-10** | Cloud sandbox ephemerality | Runs a state-machine model of the documented Stop→snapshot→Delete lifecycle and asserts *Deleted = unrecoverable*. Live tenant evidence is a manual step. | Simulation + manual |
| **SC-11** | Agent firewall (egress allowlist) | Probes a non-allowlisted host, raw TCP, and DNS exfil from inside the default-deny container; secure = all blocked, attempts logged. Allowlist-allow path via optional `--proxy`. | Docker |
| **SC-12** | Agent firewall change control | Models the allowlist as a protected file: non-privileged change rejected, privileged change applied **and** written to an append-only audit log. | Host (model) |

Full detail (probes, expected results, mapping to the plan) is in
[`docs/AGENTS.md`](docs/AGENTS.md).

---

## The sandbox target

`sandbox/launch.sh` builds [`sandbox/Dockerfile`](sandbox/Dockerfile) and runs it with
the OS-level restrictions a local sandbox is expected to enforce:

```
--network none            default-deny egress (nothing allowlisted → all outbound blocked)
--read-only               immutable rootfs (writes confined to tmpfs /workspace,/tmp)
--cap-drop ALL            no Linux capabilities (blocks mount, raw sockets, …)
--security-opt no-new-privileges   no setuid/su privilege gain
non-root uid 1000, pids/memory limits
```

To prove the probes actually detect bypasses, launch the **negative control** and
watch SC-07/SC-11 flip to `FAIL`:

```bash
sandbox/launch.sh up --insecure     # permissive container
python run.py run SC-07 SC-11 --backend docker
sandbox/launch.sh up                # back to hardened
```

---

## CLI reference

```
python run.py list [--group N]
python run.py describe SC-07
python run.py run <IDs…|--group N|--all> [options]

  --backend auto|docker|host|manual   auto (default): docker if a target is up,
                                       else the agent's native host/sim mode, else BLOCKED
  --container NAME                     docker sandbox name (default: copilot-sandbox)
  --workspace DIR                      project dir inside the sandbox (default: /workspace)
  --proxy URL                          egress proxy for SC-11 allowlist-allow path
  --blocked-host HOST                  non-allowlisted host for SC-11
  --simulate                           record a simulation PASS where supported (SC-10)
  --json PATH                          machine-readable results
  --evidence PATH                      Markdown evidence log (POC Appendix C columns)
  -v / --verbose                       per-probe detail + manual steps
```

**Exit code:** non-zero if any *must-pass* case `FAIL`s or `ERROR`s. `BLOCKED` does
**not** fail the run — it means "live evidence still required".

### Result statuses

| Status | Meaning |
|--------|---------|
| `PASS` | Control behaved as the plan's *Expected (pass) result*. |
| `FAIL` | A bypass / insecure behaviour was observed. |
| `BLOCKED` | Couldn't execute (no Docker target, or needs a live tenant). Manual steps emitted. |
| `ERROR` | The agent itself failed unexpectedly. |

---

## Adding more cases

1. Drop `agents/groupN/scNN_*.py` with a `TestAgent` subclass decorated `@register`.
2. Import it from `agents/groupN/__init__.py`, and import that package from `agents/__init__.py`.
3. It appears automatically in `run.py list` / `run`.

See [`docs/AGENTS.md`](docs/AGENTS.md) for the agent contract and probe model.
