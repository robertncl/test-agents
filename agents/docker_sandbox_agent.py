"""Docker sandbox agent - local-execution isolation baseline.

The POC plan focuses on Copilot's local (MXC) and cloud (Azure Container Apps)
sandboxes. This agent provides a *Docker baseline*: the same isolation controls
(filesystem, egress, capabilities, resources, escape, ephemerality, supply chain)
expressed as container-runtime checks. It serves two purposes:
  1. a reference any developer can run to understand the expected isolation bar;
  2. a comparison point for what Copilot's local sandbox must match or exceed.

All commands assume the hardened run profile in config.docker.default_run_flags
(${run_flags}). Cases are scaffolds - execute manually and record evidence.
"""

from __future__ import annotations

from core.agent import Agent
from core.model import Priority as P
from core.model import TestCase

CASES = [
    TestCase(
        id="TC-D-01",
        priority=P.P1,
        title="Filesystem isolation",
        control="Container cannot read host paths outside the mounted workspace",
        theme="isolation",
        criterion="C1",
        method=[
            "Run the sandbox container mounting ONLY the workspace read-only.",
            "Do not mount host home, ~/.ssh, cloud-cred dirs, or docker.sock.",
            "From inside, attempt to read host-only paths.",
        ],
        commands=[
            'docker run --rm -v "$PWD":/work:ro --network none alpine sh -c '
            "'ls -la /work; cat /etc/host-secret 2>&1; ls -la ~/.ssh 2>&1; ls -la /host 2>&1'",
        ],
        pass_criteria=(
            "Only /work is visible; host home, ~/.ssh and host secrets are "
            "unreachable; writes outside the workspace are denied."
        ),
    ),
    TestCase(
        id="TC-D-02",
        priority=P.P1,
        title="Network egress restriction",
        control="No egress to non-allowlisted destinations",
        theme="isolation",
        criterion="C1",
        method=[
            "Run with --network none (or a custom network whose only route is the mirror).",
            "Attempt to reach the non-allowlisted canary endpoint.",
            "Then confirm the AIA mirror IS reachable under the allowlist variant.",
        ],
        commands=[
            "docker run --rm --network none alpine sh -c "
            "'wget -T5 -qO- ${canary_endpoint} || echo EGRESS_BLOCKED'",
            "# allowlist variant: only ${mirror_host} should resolve/connect",
        ],
        pass_criteria=(
            "Egress to ${canary_endpoint} is blocked; only ${mirror_host}/allowlisted "
            "hosts are reachable; the blocked attempt is observable in telemetry."
        ),
    ),
    TestCase(
        id="TC-D-03",
        priority=P.P1,
        title="Linux capability restriction",
        control="Dangerous capabilities dropped (--cap-drop ALL)",
        theme="isolation",
        criterion="C1",
        method=[
            "Run with --cap-drop ALL.",
            "Attempt privileged operations: add a network device, mount a filesystem.",
        ],
        commands=[
            "docker run --rm --cap-drop ALL alpine sh -c "
            "'ip link add dummy0 type dummy 2>&1; mount -t tmpfs none /mnt 2>&1; echo done'",
        ],
        pass_criteria="Privileged ops fail with EPERM; no capability is silently retained.",
    ),
    TestCase(
        id="TC-D-04",
        priority=P.P1,
        title="Non-root + no-new-privileges",
        control="Runs as unprivileged user; privilege escalation blocked",
        theme="isolation",
        criterion="C1",
        method=[
            "Run with --user <non-root> and --security-opt no-new-privileges.",
            "Attempt setuid / su escalation.",
        ],
        commands=[
            "docker run --rm --user 10001:10001 --security-opt no-new-privileges alpine "
            "sh -c 'id; chmod u+s /bin/busybox 2>&1; su 2>&1; echo done'",
        ],
        pass_criteria="Container is non-root; setuid/su escalation is denied.",
    ),
    TestCase(
        id="TC-D-05",
        priority=P.P1,
        title="Resource limits (DoS containment)",
        control="Memory/CPU/PID limits contain runaway workloads",
        theme="isolation",
        criterion="C1",
        method=[
            "Run with --memory, --cpus and --pids-limit set.",
            "Trigger a fork/memory storm; confirm the host is unaffected.",
        ],
        commands=[
            "docker run --rm --memory 256m --cpus 0.5 --pids-limit 128 alpine "
            "sh -c ':(){ :|:& };: 2>&1 || echo CONTAINED'",
        ],
        pass_criteria="Resource storm is contained by limits; host stays responsive.",
        notes="Destructive primitive - run only on a disposable host; keep dry_run on otherwise.",
    ),
    TestCase(
        id="TC-D-06",
        priority=P.P1,
        title="Container escape probes",
        control="No escape via docker.sock, host /proc, cgroup release_agent",
        theme="isolation",
        criterion="C1",
        method=[
            "Confirm the sandbox profile does NOT mount /var/run/docker.sock.",
            "Probe host-reachable primitives: /proc/1/cgroup, core_pattern, release_agent.",
        ],
        commands=[
            "docker run --rm alpine sh -c "
            "'ls -la /var/run/docker.sock 2>&1; cat /proc/1/cgroup; "
            "cat /proc/sys/kernel/core_pattern 2>&1; ls -la /proc/host 2>&1'",
        ],
        pass_criteria=(
            "docker.sock absent; release_agent/core_pattern/host /proc inaccessible; "
            "no escape primitive succeeds."
        ),
    ),
    TestCase(
        id="TC-D-07",
        priority=P.P2,
        title="Ephemerality / no residue",
        control="--rm leaves no container or layer residue",
        theme="isolation",
        criterion="C1",
        method=[
            "Write a marker inside an --rm container, exit, then look for residue.",
        ],
        commands=[
            "docker run --rm --name dk07 alpine sh -c 'echo marker > /tmp/m; cat /tmp/m'",
            "docker ps -a --filter name=dk07 -q | grep . && echo RESIDUE || echo NO_RESIDUE",
        ],
        pass_criteria="No container/layer residue after exit; marker not recoverable.",
    ),
    TestCase(
        id="TC-D-08",
        priority=P.P2,
        title="Read-only root filesystem",
        control="Root FS read-only; writes confined to tmpfs/workspace",
        theme="isolation",
        criterion="C1",
        method=["Run with --read-only and a tmpfs for /tmp; attempt writes to / and /tmp."],
        commands=[
            "docker run --rm --read-only --tmpfs /tmp alpine sh -c "
            "'echo x > /root/x 2>&1 || echo RO_ENFORCED; echo y > /tmp/y && echo TMPFS_OK'",
        ],
        pass_criteria="Writes to the root FS fail; only tmpfs/workspace are writable.",
    ),
    TestCase(
        id="TC-D-09",
        priority=P.P2,
        title="Image provenance / supply chain",
        control="Images resolve only via the Nexus mirror; firewall blocks quarantined",
        theme="injection",
        criterion="C2",
        method=[
            "Configure the daemon to pull only from ${image_mirror} (no docker.io).",
            "Confirm Sonatype Repository Firewall blocks a quarantined component.",
            "Verify signature / SBOM of the base image.",
        ],
        commands=[
            "docker pull ${image_mirror}/alpine:3.20",
            "# cosign verify ${image_mirror}/alpine:3.20 ; syft ${image_mirror}/alpine:3.20 -o spdx-json",
        ],
        pass_criteria=(
            "Base images resolve only through ${image_mirror}; Repository Firewall "
            "blocks quarantined components; signature/SBOM verified."
        ),
    ),
    TestCase(
        id="TC-D-10",
        priority=P.P2,
        title="Seccomp / AppArmor enforcement",
        control="Syscall and MAC profiles block dangerous operations",
        theme="isolation",
        criterion="C1",
        method=[
            "Run with the default (or a custom) seccomp profile and an AppArmor profile.",
            "Attempt blocked syscalls: unshare, ptrace, keyctl.",
        ],
        commands=[
            "docker run --rm --security-opt seccomp=profiles/seccomp-sandbox.json alpine "
            "sh -c 'unshare -r echo nope 2>&1; echo done'",
        ],
        pass_criteria="Blocked syscalls are denied; the configured profiles are enforced.",
    ),
    TestCase(
        id="TC-D-11",
        priority=P.P2,
        title="Secret isolation in container env",
        control="No host env / docker secrets leak into the sandbox",
        theme="secrets",
        criterion="C1",
        method=["Enumerate the container environment; look for tokens/keys/passwords."],
        commands=[
            "docker run --rm alpine sh -c "
            "'env | grep -iE \"token|secret|key|password\" || echo NO_SECRETS_IN_ENV'",
        ],
        pass_criteria=(
            "No host env vars or docker secrets are present; only explicitly-scoped "
            "values appear in the container env."
        ),
    ),
    TestCase(
        id="TC-D-12",
        priority=P.P3,
        title="Egress-attempt detection",
        control="Blocked egress produces actionable telemetry in Sentinel",
        theme="audit",
        criterion="C5",
        method=[
            "Attempt the canary egress (TC-D-02) with host/network telemetry forwarded.",
            "Confirm Microsoft Sentinel ingests an actionable event for the attempt.",
        ],
        commands=[
            "# replay TC-D-02 with packet/flow logging forwarded to Sentinel",
        ],
        pass_criteria="The blocked egress attempt generates an actionable Sentinel alert.",
    ),
]

AGENT = Agent(
    key="docker",
    name="Docker Sandbox Agent",
    surface="Docker sandbox (local execution isolation baseline)",
    description=(
        "Container-runtime isolation baseline: filesystem, egress, capabilities, "
        "resource limits, escape probes, ephemerality, supply chain, seccomp/AppArmor, "
        "secret isolation and egress detection."
    ),
    test_cases=CASES,
)
