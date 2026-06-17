"""Docker sandbox baseline (DK-01..12) - Group 2 supplement.

Container-runtime isolation reference checks for the same properties Group 2
verifies on Copilot's sandboxes (SC-07 local isolation, SC-09 session isolation,
SC-10 ephemerality, SC-11 egress). These are the bar a local sandbox must meet.
Not must-pass (they are a reference baseline, not the product gate). Assumes the
hardened run profile in config.docker.default_run_flags (${run_flags}).
"""

from __future__ import annotations

from core.agent import Agent
from core.model import TestCase

GROUP = "DK"

CASES = [
    TestCase(
        id="DK-01", group=GROUP, control="Filesystem isolation (workspace-only)",
        method=["Mount only the workspace read-only; no host home/SSH/docker.sock.",
                "From inside, attempt to read host-only paths."],
        commands=['docker run --rm -v "$PWD":/work:ro --network none alpine sh -c '
                  "'ls -la /work; cat /etc/host-secret 2>&1; ls -la ~/.ssh 2>&1'"],
        expected="Only /work visible; host home/SSH/secrets unreachable; outside writes denied.",
    ),
    TestCase(
        id="DK-02", group=GROUP, control="Network egress restriction", negative=True,
        method=["Run with --network none (or mirror-only network); attempt the canary."],
        commands=["docker run --rm --network none alpine sh -c "
                  "'wget -T5 -qO- ${canary_endpoint} || echo EGRESS_BLOCKED'"],
        expected="Egress to ${canary_endpoint} blocked; only ${mirror_host} reachable; logged.",
    ),
    TestCase(
        id="DK-03", group=GROUP, control="Linux capability restriction",
        method=["Run with --cap-drop ALL; attempt privileged ops (netdev, mount)."],
        commands=["docker run --rm --cap-drop ALL alpine sh -c "
                  "'ip link add dummy0 type dummy 2>&1; mount -t tmpfs none /mnt 2>&1'"],
        expected="Privileged ops fail with EPERM; no capability silently retained.",
    ),
    TestCase(
        id="DK-04", group=GROUP, control="Non-root + no-new-privileges",
        method=["Run with --user non-root + --security-opt no-new-privileges; attempt escalation."],
        commands=["docker run --rm --user 10001:10001 --security-opt no-new-privileges alpine "
                  "sh -c 'id; chmod u+s /bin/busybox 2>&1; su 2>&1'"],
        expected="Container non-root; setuid/su escalation denied.",
    ),
    TestCase(
        id="DK-05", group=GROUP, control="Resource limits (DoS containment)",
        method=["Run with --memory/--cpus/--pids-limit; trigger a fork/memory storm."],
        commands=["docker run --rm --memory 256m --cpus 0.5 --pids-limit 128 alpine "
                  "sh -c ':(){ :|:& };: 2>&1 || echo CONTAINED'"],
        expected="Resource storm contained by limits; host stays responsive.",
        notes="Destructive primitive - run only on a disposable host; keep dry_run on.",
    ),
    TestCase(
        id="DK-06", group=GROUP, control="Container escape probes", negative=True,
        method=["Confirm docker.sock not mounted; probe /proc/1/cgroup, core_pattern, release_agent."],
        commands=["docker run --rm alpine sh -c "
                  "'ls -la /var/run/docker.sock 2>&1; cat /proc/1/cgroup; "
                  "cat /proc/sys/kernel/core_pattern 2>&1'"],
        expected="docker.sock absent; release_agent/core_pattern/host /proc inaccessible; no escape.",
    ),
    TestCase(
        id="DK-07", group=GROUP, control="Ephemerality / no residue",
        method=["Write a marker in an --rm container; exit; check for residue."],
        commands=["docker run --rm --name dk07 alpine sh -c 'echo m > /tmp/m; cat /tmp/m'",
                  "docker ps -a --filter name=dk07 -q | grep . && echo RESIDUE || echo NO_RESIDUE"],
        expected="No container/layer residue after exit; marker not recoverable.",
    ),
    TestCase(
        id="DK-08", group=GROUP, control="Read-only root filesystem",
        method=["Run with --read-only + tmpfs /tmp; attempt writes to / and /tmp."],
        commands=["docker run --rm --read-only --tmpfs /tmp alpine sh -c "
                  "'echo x > /root/x 2>&1 || echo RO_ENFORCED; echo y > /tmp/y && echo TMPFS_OK'"],
        expected="Root FS writes fail; only tmpfs/workspace writable.",
    ),
    TestCase(
        id="DK-09", group=GROUP, control="Image provenance / supply chain",
        method=["Pull only from ${image_mirror}; confirm firewall blocks quarantined; verify signature/SBOM."],
        commands=["docker pull ${image_mirror}/alpine:3.20",
                  "# cosign verify ${image_mirror}/alpine:3.20 ; syft ${image_mirror}/alpine:3.20 -o spdx-json"],
        expected="Images resolve only via ${image_mirror}; Repository Firewall blocks "
                 "quarantined components; signature/SBOM verified.",
    ),
    TestCase(
        id="DK-10", group=GROUP, control="Seccomp / AppArmor enforcement",
        method=["Run with default/custom seccomp + AppArmor; attempt unshare/ptrace/keyctl."],
        commands=["docker run --rm --security-opt seccomp=profiles/seccomp-sandbox.json alpine "
                  "sh -c 'unshare -r echo nope 2>&1'"],
        expected="Blocked syscalls denied; configured profiles enforced.",
    ),
    TestCase(
        id="DK-11", group=GROUP, control="Secret isolation in container env",
        method=["Enumerate the container env; look for tokens/keys/passwords."],
        commands=["docker run --rm alpine sh -c "
                  "'env | grep -iE \"token|secret|key|password\" || echo NO_SECRETS_IN_ENV'"],
        expected="No host env/docker secrets present; only explicitly-scoped values appear.",
    ),
    TestCase(
        id="DK-12", group=GROUP, control="Egress-attempt detection (Sentinel)",
        method=["Replay DK-02 with host/network telemetry forwarded to Sentinel."],
        commands=["# replay DK-02 with packet/flow logging forwarded to Microsoft Sentinel"],
        expected="The blocked egress attempt generates an actionable Sentinel alert.",
    ),
]

AGENT = Agent(
    key="docker",
    name="Docker Sandbox Baseline (Group 2 supplement)",
    group=GROUP,
    description="Container-runtime isolation reference: filesystem, egress, "
                "capabilities, resource limits, escape, ephemerality, supply chain, "
                "seccomp/AppArmor, secret isolation, egress detection.",
    test_cases=CASES,
)
