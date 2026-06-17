"""SC-10 — Cloud sandbox ephemerality & deletion.

POC method: start a cloud session, write data, **Stop** then **Delete**; verify the
snapshot lifecycle. Expected (pass): Stopped = snapshot restorable; Deleted =
environment + snapshot unrecoverable.

The GitHub-hosted cloud sandbox cannot be driven by this harness, so the live case is
``BLOCKED`` with manual steps and GitHub-API verification pointers. To make the
*expected behaviour* executable and regression-checkable, the agent also runs a small
state-machine **simulation** of the documented lifecycle and asserts:

    RUNNING --Stop--> STOPPED (snapshot present, restorable)
    STOPPED --Start--> RUNNING (data restored from snapshot)
    *       --Delete--> DELETED (environment gone, snapshot purged, restore fails)

This proves the spec we will hold the live sandbox to; it does not substitute for
live evidence (hence BLOCKED, not PASS, unless ``--simulate`` is explicitly chosen).
"""

from __future__ import annotations

from ..base import RunContext, Status, TestAgent, TestResult, register

MANUAL_STEPS = [
    "Start a cloud sandbox session and write a uniquely identifiable file/marker.",
    "Click **Stop**; confirm a restorable snapshot is created (note the snapshot/session ID).",
    "Restart the session; confirm the written data is restored from the snapshot.",
    "Click **Delete**; confirm the environment is destroyed.",
    "Attempt to restore/reattach the deleted session; confirm it is unrecoverable.",
    "Via GitHub API / audit log, confirm the delete event and that no snapshot remains.",
    "Record session ID, snapshot ID, delete event ID, and the failed-restore evidence.",
]


class _CloudSandboxModel:
    """Reference model of the documented cloud-sandbox lifecycle."""

    def __init__(self) -> None:
        self.state = "RUNNING"
        self.data: dict[str, str] = {}
        self.snapshot: dict | None = None

    def write(self, key: str, value: str) -> None:
        if self.state != "RUNNING":
            raise RuntimeError(f"cannot write in state {self.state}")
        self.data[key] = value

    def stop(self) -> None:
        if self.state != "RUNNING":
            raise RuntimeError(f"cannot stop from {self.state}")
        self.snapshot = dict(self.data)   # snapshot captured on stop
        self.state = "STOPPED"

    def start(self) -> None:
        if self.state != "STOPPED":
            raise RuntimeError(f"cannot start from {self.state}")
        if self.snapshot is None:
            raise RuntimeError("no snapshot to restore")
        self.data = dict(self.snapshot)   # restored from snapshot
        self.state = "RUNNING"

    def delete(self) -> None:
        self.state = "DELETED"
        self.snapshot = None              # snapshot purged on delete
        self.data = {}

    def restore(self) -> dict:
        if self.state == "DELETED" or self.snapshot is None:
            raise RuntimeError("environment and snapshot are unrecoverable")
        return dict(self.snapshot)


def _simulate() -> tuple[bool, list[str]]:
    """Run the lifecycle assertions; return (passed, human-readable checks)."""
    checks: list[str] = []
    ok = True

    m = _CloudSandboxModel()
    m.write("artifact", "secret-123")

    # Stop => restorable snapshot.
    m.stop()
    try:
        restored = m.restore()
        cond = m.state == "STOPPED" and restored.get("artifact") == "secret-123"
        checks.append(f"[{'PASS' if cond else 'FAIL'}] Stopped: snapshot restorable")
        ok &= cond
    except Exception as exc:  # pragma: no cover - defensive
        checks.append(f"[FAIL] Stopped: snapshot should be restorable ({exc})")
        ok = False

    # Start => data restored from snapshot.
    m.start()
    cond = m.state == "RUNNING" and m.data.get("artifact") == "secret-123"
    checks.append(f"[{'PASS' if cond else 'FAIL'}] Restart: data restored from snapshot")
    ok &= cond

    # Delete => unrecoverable.
    m.delete()
    deleted_ok = m.state == "DELETED" and m.snapshot is None
    checks.append(f"[{'PASS' if deleted_ok else 'FAIL'}] Deleted: environment + snapshot gone")
    ok &= deleted_ok

    restore_blocked = False
    try:
        m.restore()
    except RuntimeError:
        restore_blocked = True
    checks.append(f"[{'PASS' if restore_blocked else 'FAIL'}] Deleted: restore attempt fails")
    ok &= restore_blocked

    return ok, checks


@register
class SC10(TestAgent):
    id = "SC-10"
    group = 2
    control = "Cloud sandbox ephemerality & deletion"
    method = "Start cloud session, write data, Stop then Delete; verify snapshot lifecycle."
    expected = "Stopped = snapshot restorable; Deleted = environment + snapshot unrecoverable."
    must_pass = True
    requires = "Live cloud-sandbox tenant (manual). --simulate runs the lifecycle model only."

    def execute(self, ctx: RunContext) -> TestResult:
        sim_ok, checks = _simulate()
        evidence = ["simulation:" + ("ok" if sim_ok else "FAILED")] + checks

        if not sim_ok:
            # The reference model itself is wrong — surface as ERROR so it's noticed.
            return self.result(
                Status.ERROR,
                "Lifecycle reference model failed its own assertions — fix SC-10 model.",
                backend="simulation", evidence=evidence, manual_steps=MANUAL_STEPS,
            )

        if ctx.simulate:
            return self.result(
                Status.PASS,
                "Lifecycle model verified: Stopped=restorable, Deleted=unrecoverable "
                "(SIMULATION — not live cloud evidence).",
                backend="simulation", evidence=evidence,
                notes="Simulation only. Replace with live-tenant evidence for a real POC PASS.",
            )

        return self.result(
            Status.BLOCKED,
            "Lifecycle model verified in simulation; live cloud-sandbox Stop/Delete "
            "evidence must be captured manually (see steps). Re-run with --simulate to "
            "record the model check.",
            backend="manual+simulation", evidence=evidence, manual_steps=MANUAL_STEPS,
            notes="Requires GHE cloud-sandbox tenant; verify deletion via API/audit log.",
        )
