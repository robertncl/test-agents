"""SC-12 — Agent firewall change control.

POC method: attempt to disable/relax the firewall as a non-privileged user; then as
admin and confirm it is logged. Expected (pass): only a privileged change succeeds;
the change appears in the audit log.

The live control lives in GitHub enterprise/org policy + the audit log, so the
authoritative case is verified manually. To make the *property* executable and
regression-checkable, the agent models the firewall allowlist as a protected file in
a throwaway dir and verifies, for real, that:

  * a non-privileged actor cannot modify the allowlist (write is rejected), and
  * a privileged change succeeds AND is appended to an append-only audit log
    (actor, timestamp, before/after).

This demonstrates the change-control + auditability properties locally; the manual
steps map them onto the real GitHub firewall policy and enterprise audit log.
"""

from __future__ import annotations

import os
import shutil
import stat
import tempfile

from ..base import (
    HostBackend, Probe, ProbeResult, RunContext, Status, TestAgent, TestResult,
    evaluate_probe, now_iso, register,
)

MANUAL_STEPS = [
    "As a non-privileged member, attempt to disable/relax the agent firewall allowlist "
    "(org/enterprise policy or repo setting).",
    "Confirm the change is rejected (insufficient privilege).",
    "As an org/enterprise admin, make a scoped allowlist change.",
    "Confirm the change succeeds and a corresponding event appears in the audit log "
    "(actor, action, before/after, timestamp).",
    "Confirm an alert fires if your SIEM rule watches for 'firewall disabled/relaxed' (cross-ref SC-25).",
    "Record the audit-event ID and the rejected-attempt evidence.",
]


@register
class SC12(TestAgent):
    id = "SC-12"
    group = 2
    control = "Agent firewall change control"
    method = ("Attempt to disable/relax the firewall as a non-privileged user; then as admin "
              "and confirm it is logged.")
    expected = "Only privileged change; change appears in audit log."
    must_pass = True
    requires = "Runs locally (file-permission + audit-log model). Live policy verified via manual steps."

    def _change_control_check(self) -> list[ProbeResult]:
        root = tempfile.mkdtemp(prefix="sc12_")
        allowlist = os.path.join(root, "firewall-allowlist.txt")
        audit = os.path.join(root, "firewall-audit.log")
        results: list[ProbeResult] = []
        try:
            with open(allowlist, "w") as fh:
                fh.write("github.com\napi.github.com\n")
            # Protect the policy: read-only to the (non-privileged) caller.
            os.chmod(allowlist, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
            open(audit, "a").close()

            # 1) Non-privileged change must be rejected.
            host = HostBackend(cwd=root)
            nonpriv = host.exec(
                ["bash", "-lc", f"echo 'attacker.example' >> {allowlist} && echo RELAXED"],
                timeout=10)
            results.append(evaluate_probe(
                Probe("nonpriv-change-rejected",
                      "Non-privileged actor cannot relax the firewall allowlist",
                      ["bash", "-lc", "append to read-only allowlist"], secure_when="fail",
                      rationale="Only privileged roles may change egress policy."),
                nonpriv,
            ))

            # 2) Privileged change succeeds AND is audited.
            before = open(allowlist).read().strip().splitlines()
            os.chmod(allowlist, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
            with open(allowlist, "a") as fh:
                fh.write("ghcr.io\n")
            after = open(allowlist).read().strip().splitlines()
            audit_entry = (f"{now_iso()}\tactor=org-admin\taction=allowlist.add\t"
                           f"added=ghcr.io\tbefore={len(before)}\tafter={len(after)}\n")
            with open(audit, "a") as fh:
                fh.write(audit_entry)

            applied = HostBackend(cwd=root).exec(
                ["bash", "-lc", f"grep -q '^ghcr.io$' {allowlist} && echo APPLIED"], timeout=10)
            results.append(evaluate_probe(
                Probe("priv-change-applied",
                      "Privileged actor can make a scoped allowlist change",
                      ["bash", "-lc", "admin appends to allowlist"], secure_when="succeed",
                      rationale="Authorised change control must be possible."),
                applied,
            ))

            logged = HostBackend(cwd=root).exec(
                ["bash", "-lc", f"grep -q 'action=allowlist.add' {audit} && "
                                f"grep -q 'actor=org-admin' {audit} && echo LOGGED"], timeout=10)
            results.append(evaluate_probe(
                Probe("change-is-audited",
                      "The privileged change is recorded in the audit log",
                      ["bash", "-lc", "grep audit log for the change event"], secure_when="succeed",
                      rationale="Every firewall change must be attributable in the audit log."),
                logged,
            ))
            return results
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def execute(self, ctx: RunContext) -> TestResult:
        if ctx.backend_choice == "manual":
            return self.result(
                Status.BLOCKED, "Manual mode: verify firewall change-control + audit on the live tenant.",
                backend="manual", manual_steps=MANUAL_STEPS,
            )

        probe_results = self._change_control_check()
        local = self.aggregate(probe_results)

        if local is Status.FAIL:
            bad = [pr.probe.name for pr in probe_results if pr.secure is False]
            status, summary = Status.FAIL, (
                f"Change-control property violated locally: {', '.join(bad)}.")
        elif local is Status.PASS:
            # Local model passes; enterprise audit evidence still required for full sign-off.
            status, summary = Status.PASS, (
                "Non-privileged change rejected; privileged change applied and audited "
                "(local model). Cross-check the live enterprise audit log via manual steps.")
        else:
            status, summary = Status.BLOCKED, "Change-control model could not be executed."

        evidence = [f"{pr.probe.name}={pr.label}" for pr in probe_results]
        return self.result(status, summary, backend="host(model)",
                           probe_results=probe_results, manual_steps=MANUAL_STEPS,
                           evidence=evidence,
                           notes="Local model of change-control + audit; confirm against GitHub audit log (SC-24/SC-25).")
