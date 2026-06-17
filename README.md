# Copilot POC — Sandbox Agent Security-Control Tests

A test harness that launches the **GitHub Copilot agent** inside a sandbox and
asserts that the sandbox enforces three classes of security control:

1. **Host filesystem isolation** — nothing on the host outside the shared
   workspace is reachable, and sandbox writes never leak to the host.
2. **Filesystem & network policy control** — read-only vs read-write
   workspace, read allowlists, default-deny egress, and egress allowlists.
3. **MCP access policy control** — only allowlisted MCP servers reach the
   agent; denied servers are stripped from its effective configuration.

The same scenarios run across three sandbox **backends**, each governed by a
policy authored in **its own native format** (see
[Per-sandbox native policies](#per-sandbox-native-policies)):

| Backend | What it is | Native policy | Status |
|---|---|---|---|
| `docker` | A hardened `docker run` container | `policies/docker/*.json` (Docker primitives) | **Verified** — 9/9 enforceable scenarios pass |
| `openshell` | [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell) gateway sandbox | `policies/openshell/*.yaml` (landlock policy) | **Wired to the real CLI (v0.0.63)** — runs where an image provisions |
| `copilot_local` | The OS sandbox the Copilot CLI uses locally | `policies/copilot_local/*.bwrap` / `*.sb` | Runnable where `bwrap` (Linux) or `sandbox-exec` (macOS) exists |

Structure inspired by OpenShell's
[`examples/`](https://github.com/NVIDIA/OpenShell/tree/main/examples): a native
policy declares what's allowed, a backend enforces it, and a driver runs the
agent inside.

## Layout

```
sandbox/
  policy.py              # generic Policy spec (the test's statement of intent)
  agent.py               # run the Copilot agent in any backend; render MCP config
  scenarios.py           # the security scenarios (single source of truth)
  testing.py             # pytest glue used by the per-sandbox folders
  backends/
    base.py              # Backend interface, capabilities, BackendUnavailable
    docker.py            # hardened `docker run`, built from docker-native policy
    openshell.py         # real create/upload/policy-set/exec/download/delete
    copilot_local.py     # bubblewrap (Linux) / Seatbelt (macOS)
policies/
  workspace-rw.json      # generic spec: rw workspace, no host, no net, MCP allowlist
  workspace-ro.json      #   "        : read-only workspace
  net-allowlist.json     #   "        : egress allowlist
  docker/*.json          # docker-NATIVE policies
  openshell/*.yaml       # openshell-NATIVE landlock policies
  copilot_local/*.bwrap  # bubblewrap-NATIVE policies (Linux)
  copilot_local/*.sb     # Seatbelt-NATIVE policies (macOS)
tests/
  docker/                # 4 test files, pinned BACKEND="docker"
  openshell/             # 4 test files, pinned BACKEND="openshell"
  copilot_local/         # 4 test files, pinned BACKEND="copilot_local"
examples/
  run_copilot_agent.py   # launch the real Copilot agent in a sandbox
run_tests.py             # zero-dependency runner + matrix report
```

The generic `policies/*.json` is the **specification** each scenario asserts
against; the per-backend files are the **native enforcement** each sandbox
actually consumes.

## Quick start

```bash
# Zero dependencies — uses only the Python stdlib.
python3 run_tests.py --list             # backend availability + scenarios
python3 run_tests.py                    # full matrix, every available backend
python3 run_tests.py --backend docker   # one backend
python3 run_tests.py --category mcp-policy

# Or via pytest (pip install -r requirements.txt) — tests are split per sandbox:
pytest                                   # all three folders
pytest tests/docker                      # just the Docker sandbox
pytest tests/openshell tests/copilot_local
```

A scenario is **skip**ped (never failed) when a backend isn't installed, can't
provision, or can't enforce the capability under test. The process exits
non-zero only on a real **FAIL** / **ERROR**.

### Verified result in this environment

```
docker         OK   docker 29.5.3
openshell      OK   openshell gateway connected (image=python:3.12-slim)
copilot_local  n/a  no local sandbox primitive (install bubblewrap)

Total 30  10 pass  0 fail  0 error  20 skip
```

Docker enforces and passes everything it can. OpenShell's gateway is connected
and the lifecycle runs, but no sandbox **image** provisions here (the community
registry needs auth and bare images restart-loop), so its exec-based scenarios
skip with that reason; its config-level MCP check still passes. `copilot_local`
skips because `bwrap` isn't installed.

## What each scenario proves

**host-fs-isolation**
- `host-secret-invisible` — a secret on the host *outside* the workspace can't
  be read inside the sandbox.
- `write-no-leak` — a write to a non-workspace path doesn't appear on the host.
- `workspace-shared` — positive control: the workspace really is shared, so the
  two results above aren't a false positive from a broken mount.

**fs-policy**
- `ro-blocks-write` / `rw-allows-write` — read-only vs read-write workspace.
- `read-allowlist` — a host file granted via the read allowlist is readable; an
  ungranted sibling stays invisible.

**network-policy**
- `net-default-deny` — default-deny blocks all egress.
- `net-allowlist` — only allowlisted hosts are reachable *(needs the
  `network-allowlist` capability — `openshell`; skipped on `docker` /
  `copilot_local`, which do full deny only)*.

**mcp-policy**
- `mcp-config-gating` — the effective MCP config exposes only allowlisted
  servers; denied ones (a filesystem-root server, an exfil server) are stripped.
- `mcp-in-sandbox` — verified from inside the sandbox: the rendered MCP config
  the agent would load does not contain the denied server.

## Enforcement matrix

| Capability | docker | openshell | copilot_local |
|---|:--:|:--:|:--:|
| host FS isolation | ✅ | ✅ | ✅ |
| read-only workspace | ✅ | ✅ | ✅ |
| network full deny | ✅ | ✅ | ✅ |
| network per-host allowlist | ➖ (needs egress proxy) | ✅ | ➖ |
| MCP allowlist | ✅ | ✅ | ✅ |

✅ enforced and tested · ➖ not enforced by this backend (scenario skips)

## Per-sandbox native policies

Each backend reads its own native artifact; the host workspace path is injected
at runtime (`{workspace}` / `{workdir}`), and dynamic allowlist paths a scenario
is exercising are appended on top.

- **docker** (`policies/docker/<name>.json`) — Docker primitives mapped 1:1 to
  `docker run` flags: `network_mode`, `read_only`, `cap_drop`, `security_opt`,
  `tmpfs`, `user`, and the workspace mount mode.
- **openshell** (`policies/openshell/<name>.yaml`) — the landlock policy schema
  OpenShell actually reports: `filesystem_policy.read_only/read_write`,
  `landlock`, `process.run_as_user`, and `network_policy.endpoints`
  (`host:port:mode:protocol:action`).
- **copilot_local** (`policies/copilot_local/<name>.bwrap` and `.sb`) — a
  bubblewrap argument list for Linux and a Seatbelt profile for macOS.

## Running the real Copilot agent in the sandbox

The scenarios use small deterministic probes so the suite is reproducible and
needs no credentials. To put the **actual agent** under the same policy:

```bash
GITHUB_TOKEN=... python3 examples/run_copilot_agent.py \
    --backend docker --policy workspace-rw \
    --workspace ./my-project \
    --prompt "Read README.md and summarise it."
```

The agent process *is* the sandboxed command, so every file/network/MCP action
it takes is confined by exactly the policy the tests validate.

## Configuration (env)

| Env var | Backend | Purpose |
|---|---|---|
| `SANDBOX_TEST_IMAGE` | docker | container image (default `python:3.12-alpine`) |
| `DOCKER_BIN` | docker | docker binary |
| `OPENSHELL_BIN` | openshell | openshell binary |
| `OPENSHELL_FROM` | openshell | base image for sandboxes (default `python:3.12-slim`; point at a community image where pullable) |
| `OPENSHELL_WORKDIR` | openshell | workspace dir inside the sandbox (default `/workspace`) |
| `BWRAP_BIN` | copilot_local | bubblewrap binary (Linux) |
| `COPILOT_SANDBOX_CMD` | copilot_local | override the local sandbox command; placeholders `{argv} {workspace} {policy}` |
| `COPILOT_AGENT_CMD` | agent | how to launch the Copilot agent; must contain `{prompt}` |
| `COPILOT_BIN` | agent | copilot binary |

## Requirements

- Python 3.10+ (stdlib only for `run_tests.py`).
- `docker` for the reference backend.
- An OpenShell gateway + a provisionable sandbox image for the `openshell`
  backend (`openshell status` must show *Connected*).
- `bubblewrap` (`apt install bubblewrap`) for `copilot_local` on Linux, or
  `sandbox-exec` on macOS.
- `pytest` only for the `tests/` front-end.
