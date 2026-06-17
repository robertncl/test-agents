#!/usr/bin/env python3
"""POC security-control test-agent runner.

Implements the test agents referenced by
``GitHub-Copilot-App-POC-Security-Verification-Plan.md`` (section B.7).
Currently shipped: **Group 2 — Containment, isolation & egress** (SC-07 … SC-12).

Usage
-----
    python run.py list [--group N]
    python run.py describe SC-07
    python run.py run SC-07 SC-11
    python run.py run --group 2 [--backend auto|docker|host|manual] [--container NAME]
    python run.py run --all --json out/results.json --evidence out/evidence.md

Backends
--------
    auto    (default) docker where a target is running, else the agent's native
            host/simulation mode, else BLOCKED with manual steps.
    docker  force the Docker sandbox target (container set by --container).
    host    host-only checks (git worktrees, file-permission models).
    manual  never execute; emit the documented manual verification steps.

Exit code is non-zero if any *must-pass* case FAILs or ERRORs (BLOCKED does not fail
the run — it means "evidence still required").
"""

from __future__ import annotations

import argparse
import json
import os
import sys

import agents
from agents.base import RunContext, Status, TestResult, all_agents, agents_by_group, get_agent

# --------------------------------------------------------------------------- #
# Terminal helpers
# --------------------------------------------------------------------------- #
_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
_PALETTE = {
    Status.PASS: "32",     # green
    Status.FAIL: "31",     # red
    Status.BLOCKED: "33",  # yellow
    Status.ERROR: "35",    # magenta
}


def _c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _COLOR else text


def _status(s: Status) -> str:
    return _c(f"{s.value:<7}", _PALETTE.get(s, "0"))


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
def cmd_list(args) -> int:
    sel = agents_by_group(args.group) if args.group else all_agents()
    if not sel:
        print(f"No agents for group {args.group}.")
        return 0
    print(f"{'ID':<7} {'Grp':<4} {'Must':<5} Control")
    print("-" * 72)
    for a in sel:
        print(f"{a.id:<7} {a.group:<4} {'✓' if a.must_pass else ' ':<5} {a.control}")
    print(f"\n{len(sel)} agent(s). Use `describe <ID>` for detail, `run <ID|--group N>` to execute.")
    return 0


def cmd_describe(args) -> int:
    a = get_agent(args.id)
    if not a:
        print(f"Unknown test case: {args.id}", file=sys.stderr)
        return 2
    print(f"{a.id} — {a.control}  (Group {a.group}, must-pass={a.must_pass})")
    print("-" * 72)
    print(f"Method   : {a.method}")
    print(f"Expected : {a.expected}")
    print(f"Requires : {a.requires}")
    return 0


def _select(args) -> list:
    if args.all:
        return all_agents()
    if args.group:
        return agents_by_group(args.group)
    selected = []
    for tid in args.ids:
        a = get_agent(tid)
        if not a:
            print(f"Unknown test case: {tid}", file=sys.stderr)
            sys.exit(2)
        selected.append(a)
    return selected


def cmd_run(args) -> int:
    selected = _select(args)
    if not selected:
        print("Nothing selected. Pass test IDs, --group N, or --all.", file=sys.stderr)
        return 2

    ctx = RunContext(
        backend_choice=args.backend,
        container=args.container,
        workspace=args.workspace,
        simulate=args.simulate,
        tester=args.tester,
        extra={k: v for k, v in (("proxy", args.proxy), ("blocked_host", args.blocked_host)) if v},
    )

    results: list[TestResult] = []
    print(f"Running {len(selected)} case(s) · backend={args.backend} · container={args.container}\n")
    for a in selected:
        try:
            res = a.execute(ctx)
        except Exception as exc:  # an agent crash must not abort the suite
            res = a.result(Status.ERROR, f"agent raised: {exc!r}", backend="n/a")
        results.append(res)
        print(f"  {_status(res.status)} {res.id}  {res.summary}")
        if args.verbose:
            for pr in res.probe_results:
                mark = {True: "ok ", False: "!! ", None: "·· "}[pr.secure]
                print(f"        {mark}{pr.probe.name}: {pr.detail} (exit={pr.outcome.exit_code})")
            for step in res.manual_steps:
                print(f"        manual> {step}")

    _summary(results)
    if args.json:
        _write_json(args.json, results, ctx)
    if args.evidence:
        _write_evidence(args.evidence, results, ctx)

    failed = [r for r in results if r.must_pass and r.status in (Status.FAIL, Status.ERROR)]
    return 1 if failed else 0


def _summary(results: list[TestResult]) -> None:
    counts = {s: sum(1 for r in results if r.status is s) for s in Status}
    print("\n" + "-" * 72)
    print("  ".join(f"{_status(s).strip()}={counts[s]}" for s in Status))
    blocked = counts[Status.BLOCKED]
    if blocked:
        print(f"\nNote: {blocked} case(s) BLOCKED — need a live target/tenant. "
              f"See manual steps (run with -v) and capture evidence.")


def _write_json(path: str, results: list[TestResult], ctx: RunContext) -> None:
    _ensure_dir(path)
    payload = {
        "plan": "GitHub-Copilot-App-POC-Security-Verification-Plan.md",
        "group": 2,
        "backend": ctx.backend_choice,
        "container": ctx.container,
        "results": [r.to_dict() for r in results],
    }
    with open(path, "w") as fh:
        json.dump(payload, fh, indent=2)
    print(f"\nWrote JSON results -> {path}")


def _write_evidence(path: str, results: list[TestResult], ctx: RunContext) -> None:
    """Markdown evidence log matching POC Appendix C columns."""
    _ensure_dir(path)
    lines = [
        "# Evidence Log — Group 2 (Containment, isolation & egress)",
        "",
        f"_Generated by run.py · backend={ctx.backend_choice} · container={ctx.container}_",
        "",
        "| Case ID | Date | Tester | Result | Evidence ref(s) | Notes |",
        "|---|---|---|---|---|---|",
    ]
    for r in results:
        row = r.evidence_row(tester=ctx.tester)
        refs = row["Evidence ref(s)"].replace("|", "\\|")
        notes = row["Notes"].replace("|", "\\|")
        lines.append(f"| {row['Case ID']} | {row['Date']} | {row['Tester']} | "
                     f"{row['Result']} | {refs} | {notes} |")
    with open(path, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"Wrote evidence log -> {path}")


def _ensure_dir(path: str) -> None:
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)


# --------------------------------------------------------------------------- #
# Argument parsing
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="run.py",
        description="POC security-control test-agent runner (Group 2: SC-07…SC-12).",
    )
    sub = p.add_subparsers(dest="command", required=True)

    pl = sub.add_parser("list", help="list available test agents")
    pl.add_argument("--group", type=int, help="filter by B.7 group number")
    pl.set_defaults(func=cmd_list)

    pd = sub.add_parser("describe", help="show one test case's metadata")
    pd.add_argument("id", help="test case ID, e.g. SC-07")
    pd.set_defaults(func=cmd_describe)

    pr = sub.add_parser("run", help="execute test agents")
    pr.add_argument("ids", nargs="*", help="test case IDs (e.g. SC-07 SC-11)")
    pr.add_argument("--group", type=int, help="run all cases in a group")
    pr.add_argument("--all", action="store_true", help="run every registered case")
    pr.add_argument("--backend", choices=["auto", "docker", "host", "manual"], default="auto")
    pr.add_argument("--container", default="copilot-sandbox", help="docker sandbox target name")
    pr.add_argument("--workspace", default="/workspace", help="project dir inside the sandbox")
    pr.add_argument("--proxy", help="egress proxy URL for SC-11 allowlist-allow path")
    pr.add_argument("--blocked-host", dest="blocked_host", help="non-allowlisted host for SC-11")
    pr.add_argument("--simulate", action="store_true", help="record simulation PASS where supported (SC-10)")
    pr.add_argument("--tester", default="poc-harness", help="tester name for the evidence log")
    pr.add_argument("--json", help="write machine-readable results to this path")
    pr.add_argument("--evidence", help="write a Markdown evidence log to this path")
    pr.add_argument("-v", "--verbose", action="store_true", help="show per-probe detail and manual steps")
    pr.set_defaults(func=cmd_run)
    return p


def main(argv=None) -> int:
    # Importing `agents` already registered every shipped agent.
    _ = agents
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
