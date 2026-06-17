#!/usr/bin/env python3
"""Zero-dependency runner for the sandbox security-control scenarios.

Runs every scenario against every (or a selected) backend and prints a matrix.
Exits non-zero if any scenario FAILs or ERRORs (SKIPs do not fail the run).

Usage:
    python run_tests.py                     # all scenarios, all backends
    python run_tests.py --backend docker    # one backend
    python run_tests.py --category mcp-policy
    python run_tests.py --list              # list backends + scenarios, then exit
"""

from __future__ import annotations

import argparse
import sys

from sandbox.backends import ALL_BACKENDS, all_backends, get_backend
from sandbox.scenarios import CATEGORIES, ERROR, FAIL, PASS, SKIP, scenarios_for

GLYPH = {PASS: "PASS", FAIL: "FAIL", SKIP: "skip", ERROR: "ERR "}


def _color(status: str, text: str) -> str:
    if not sys.stdout.isatty():
        return text
    code = {PASS: "32", FAIL: "31", SKIP: "33", ERROR: "35"}.get(status, "0")
    return f"\033[{code}m{text}\033[0m"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--backend", action="append", help="restrict to backend(s)")
    ap.add_argument("--category", choices=CATEGORIES, help="restrict to a category")
    ap.add_argument("--list", action="store_true", help="list and exit")
    args = ap.parse_args()

    backends = (
        [get_backend(n) for n in args.backend] if args.backend else all_backends()
    )
    scenarios = scenarios_for(args.category)

    if args.list:
        print("Backends:")
        for b in all_backends():
            ok, reason = b.is_available()
            mark = "available" if ok else "UNAVAILABLE"
            print(f"  - {b.name:<14} {mark:<12} {reason}")
        print("\nScenarios:")
        for s in scenarios:
            print(f"  - [{s.category}] {s.key}: {s.title}")
        return 0

    print("Backend availability:")
    for b in backends:
        ok, reason = b.is_available()
        print(f"  {b.name:<14} {'OK ' if ok else 'n/a'}  {reason}")
    print()

    counts = {PASS: 0, FAIL: 0, SKIP: 0, ERROR: 0}
    results: dict[tuple[str, str], object] = {}

    current_cat = None
    for s in scenarios:
        if s.category != current_cat:
            current_cat = s.category
            print(f"\n=== {current_cat} ===")
        line = f"  {s.key:<22}"
        cells = []
        for b in backends:
            outcome = s.evaluate(b)
            results[(s.key, b.name)] = outcome
            counts[outcome.status] += 1
            cells.append(f"{b.name}:{_color(outcome.status, GLYPH[outcome.status])}")
        print(line + "  ".join(cells))
        # detail lines for non-pass outcomes
        for b in backends:
            o = results[(s.key, b.name)]
            if o.status in (FAIL, ERROR):
                print(f"      └─ {b.name}: {o.message}")
                if o.evidence:
                    print(f"         {o.evidence}")

    total = sum(counts.values())
    print("\n" + "-" * 60)
    print(
        f"Total {total}  "
        f"{_color(PASS, str(counts[PASS]) + ' pass')}  "
        f"{_color(FAIL, str(counts[FAIL]) + ' fail')}  "
        f"{_color(ERROR, str(counts[ERROR]) + ' error')}  "
        f"{_color(SKIP, str(counts[SKIP]) + ' skip')}"
    )

    return 1 if (counts[FAIL] or counts[ERROR]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
