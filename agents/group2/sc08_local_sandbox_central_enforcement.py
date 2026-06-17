"""SC-08 — Local sandbox central enforcement.

POC method: push the sandbox policy via Intune; verify a user on the endpoint
cannot disable it. Expected (pass): policy enforced; user cannot override.

True Intune enforcement cannot be exercised by this harness, so the case is
``BLOCKED`` by default with concrete manual steps. As supporting evidence the agent
runs one *concrete* probe: a centrally-owned policy marker placed in the sandbox
image (``/etc/itest/sandbox-policy.json``, root-owned, mode 0444) must NOT be
writable by the non-root sandbox user — i.e. a local user cannot tamper with the
pushed policy. This demonstrates the enforcement property locally even though the
distribution channel (Intune) is verified out-of-band.
"""

from __future__ import annotations

from ..base import (
    Probe, RunContext, Status, TestAgent, TestResult, register,
)

POLICY_PATH = "/etc/itest/sandbox-policy.json"

MANUAL_STEPS = [
    "In Intune, assign the local-sandbox configuration profile to the pilot device group.",
    "On a managed pilot endpoint, sign in as a standard (non-admin) user.",
    "Attempt to disable the sandbox (`/sandbox disable`, edit the local policy file, "
    "or toggle the setting in the app).",
    "Confirm the override is rejected and the effective policy remains 'enabled'.",
    "In Intune, confirm the device reports 'Compliant' / policy applied.",
    "Capture the Intune policy ID, the device compliance state, and the rejected-override "
    "evidence in the Evidence Log.",
]


@register
class SC08(TestAgent):
    id = "SC-08"
    group = 2
    control = "Local sandbox central enforcement"
    method = "Push sandbox policy via Intune; verify a user cannot disable it on the endpoint."
    expected = "Policy enforced; user cannot override."
    must_pass = True
    requires = "Intune-managed pilot endpoint (manual), or the hardened sandbox container for the local override probe."

    def _probes(self, ctx: RunContext) -> list[Probe]:
        return [
            Probe(
                name="policy-marker-present",
                description=f"Centrally-pushed policy marker exists ({POLICY_PATH}).",
                command=["bash", "-lc", f"test -f {POLICY_PATH} && echo PRESENT"],
                secure_when="succeed",
                rationale="The enforced policy must actually be present on the endpoint.",
            ),
            Probe(
                name="policy-marker-immutable-by-user",
                description="Non-root sandbox user cannot tamper with the pushed policy.",
                command=["bash", "-lc", f"echo '{{\"enabled\":false}}' > {POLICY_PATH} && echo OVERRODE"],
                secure_when="fail",
                rationale="A local user must not be able to disable/relax the centrally-set policy.",
            ),
            Probe(
                name="policy-declares-no-user-override",
                description="Policy declares userCanDisable=false.",
                command=["bash", "-lc", f"grep -q '\"userCanDisable\"[[:space:]]*:[[:space:]]*false' {POLICY_PATH} && echo LOCKED"],
                secure_when="succeed",
                rationale="The policy content itself must forbid local disablement.",
            ),
        ]

    def execute(self, ctx: RunContext) -> TestResult:
        if ctx.backend_choice == "manual":
            return self.result(
                Status.BLOCKED,
                "Manual mode: verify Intune enforcement on a managed pilot endpoint.",
                backend="manual", manual_steps=MANUAL_STEPS,
            )

        backend = ctx.docker_backend()
        if not backend.available():
            return self.result(
                Status.BLOCKED,
                "Intune enforcement is verified out-of-band; sandbox container not running "
                "for the local override probe. Start it or use --backend manual.",
                backend=backend.describe(), manual_steps=MANUAL_STEPS,
            )

        probe_results = self.run_probes(backend, self._probes(ctx))
        local = self.aggregate(probe_results)

        # The local probe can only DISPROVE enforcement (FAIL) or support it. A clean
        # local result is necessary but not sufficient for a full PASS — Intune
        # evidence is captured manually — so we cap the status at BLOCKED with notes.
        if local is Status.FAIL:
            status, summary = Status.FAIL, (
                "A local user was able to tamper with the pushed sandbox policy — "
                "central enforcement is not effective.")
        elif local is Status.PASS:
            status, summary = Status.BLOCKED, (
                "Local override correctly rejected (policy immutable to non-root user). "
                "Intune distribution + compliance must be evidenced manually for a full PASS.")
        else:
            status, summary = Status.BLOCKED, "Local enforcement probe could not run."

        evidence = [f"{pr.probe.name}={pr.label}" for pr in probe_results]
        return self.result(status, summary, backend=backend.describe(),
                           probe_results=probe_results, manual_steps=MANUAL_STEPS,
                           evidence=evidence,
                           notes="Full PASS requires Intune policy-ID + device-compliance evidence.")
