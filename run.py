#!/usr/bin/env python3
"""Orchestrator for the Copilot / Docker sandbox POC test agents.

Stdlib only - no `pip install` required. Subcommands:

  list                       list agents and their test cases
  show   <TEST-ID>           print a single test case (method, commands, criteria)
  plan   [--agent K] [...]   scaffold an evidence record per case into evidence/
  record <TEST-ID> [...]     fill in a case's evidence (disposition, tester, ...)
  report                     (re)generate traceability + scorecard + summary + index
  validate                   sanity-check config and the test-case catalogue

Examples:
  python run.py list
  python run.py show TC-S-19
  python run.py plan --priority P1
  python run.py record TC-D-01 --disposition PASS --tester robert \\
      --note "host paths unreachable" --artifact evidence/artifacts/tc-d-01.log
  python run.py report
"""

from __future__ import annotations

import argparse
import os
import sys

from agents import ALL_AGENTS, find_case, get_agent
from core import config as cfg_mod
from core import evidence as ev
from core import report as rpt
from core.model import Disposition

EVIDENCE_DIR = os.environ.get("POC_EVIDENCE_DIR", "evidence")
REPORT_DIR = os.environ.get("POC_REPORT_DIR", "reports")


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _load_cfg(args) -> dict:
    return cfg_mod.load_config(getattr(args, "config", None))


def _selected_agents(agent_key: str | None):
    if not agent_key:
        return ALL_AGENTS
    a = get_agent(agent_key)
    if not a:
        sys.exit(f"Unknown agent '{agent_key}'. Known: {[x.key for x in ALL_AGENTS]}")
    return [a]


# --------------------------------------------------------------------------- #
# subcommands
# --------------------------------------------------------------------------- #
def cmd_list(args) -> None:
    total = 0
    for a in _selected_agents(args.agent):
        c = a.counts_by_priority()
        n = len(a.test_cases)
        total += n
        print(f"\n[{a.key}] {a.name}  ({n} cases: "
              f"P1={c['P1']} P2={c['P2']} P3={c['P3']})")
        print(f"    surface: {a.surface}")
        for tc in a.test_cases:
            print(f"    {tc.id:<9} {tc.priority.value}  {tc.title}")
    print(f"\nTotal test cases: {total}")


def cmd_show(args) -> None:
    found = find_case(args.test_id)
    if not found:
        sys.exit(f"No such test case: {args.test_id}")
    agent, tc = found
    cfg = _load_cfg(args)
    tok = cfg_mod.tokens(cfg)
    sub = cfg_mod.substitute
    print(f"{tc.id}  [{tc.priority.value}]  {tc.title}")
    print(f"agent     : {agent.key} ({agent.surface})")
    print(f"control   : {tc.control}")
    if tc.threat:
        print(f"threat    : {tc.threat}")
    print(f"theme     : {tc.theme}    criterion: {tc.criterion or '-'}")
    print("method    :")
    for m in tc.method:
        print(f"  - {sub(m, tok)}")
    print("commands  :")
    for c in tc.commands:
        print(f"  $ {sub(c, tok)}")
    print(f"pass      : {sub(tc.pass_criteria, tok)}")
    if tc.notes:
        print(f"notes     : {tc.notes}")


def cmd_plan(args) -> None:
    cfg = _load_cfg(args)
    env = cfg_mod.env_snapshot(cfg)
    snap = cfg_mod.config_snapshot(cfg)
    tok = cfg_mod.tokens(cfg)
    created = skipped = 0
    for a in _selected_agents(args.agent):
        for tc in a.select(priorities=args.priority):
            path = ev.record_path(EVIDENCE_DIR, tc.id)
            if os.path.exists(path) and not args.force:
                skipped += 1
                continue
            rec = ev.build_record(tc, a.surface, env, snap, tok)
            ev.save_record(EVIDENCE_DIR, rec)
            created += 1
    print(f"Scaffolded {created} evidence record(s) into {EVIDENCE_DIR}/ "
          f"({skipped} preserved; use --force to regenerate).")
    if created:
        print("Next: execute each case in the ring-fenced POC org, then "
              "`python run.py record <TEST-ID> --disposition ...`.")


def cmd_record(args) -> None:
    rec = ev.load_record(EVIDENCE_DIR, args.test_id)
    if rec is None:
        found = find_case(args.test_id)
        if not found:
            sys.exit(f"No such test case: {args.test_id}")
        agent, tc = found
        cfg = _load_cfg(args)
        rec = ev.build_record(
            tc, agent.surface, cfg_mod.env_snapshot(cfg),
            cfg_mod.config_snapshot(cfg), cfg_mod.tokens(cfg),
        )
    if args.disposition:
        valid = [d.value for d in Disposition]
        if args.disposition not in valid:
            sys.exit(f"Invalid disposition '{args.disposition}'. Valid: {valid}")
        rec.disposition = args.disposition
    if args.tester:
        rec.tester = args.tester
    if args.note:
        rec.notes = (rec.notes + "\n" if rec.notes else "") + args.note
    if args.agent_action:
        rec.agent_action = args.agent_action
    for art in args.artifact or []:
        rec.artifacts.append(art)
    for alert in args.alert or []:
        rec.sentinel_alert_ids.append(alert)
    rec.timestamp = ev.utc_now()
    path = ev.save_record(EVIDENCE_DIR, rec)
    print(f"Updated {path}  ->  disposition={rec.disposition} tester={rec.tester or '-'}")


def cmd_report(args) -> None:
    records = ev.load_all_records(EVIDENCE_DIR)
    os.makedirs(REPORT_DIR, exist_ok=True)
    outputs = {
        "TRACEABILITY.md": rpt.traceability_matrix(ALL_AGENTS),
        "GO-NO-GO-SCORECARD.md": rpt.go_no_go_scorecard(ALL_AGENTS, records),
        "RUN-SUMMARY.md": rpt.run_summary(ALL_AGENTS, records),
        "EVIDENCE-INDEX.md": rpt.evidence_index(records),
    }
    for name, body in outputs.items():
        with open(os.path.join(REPORT_DIR, name), "w", encoding="utf-8") as f:
            f.write(body)
    print(f"Wrote {len(outputs)} report(s) to {REPORT_DIR}/:")
    for name in outputs:
        print(f"  - {os.path.join(REPORT_DIR, name)}")
    if not records:
        print("(No evidence records yet - run `python run.py plan` first.)")


def cmd_validate(args) -> None:
    problems = []
    # config
    try:
        cfg = _load_cfg(args)
        print(f"config: OK ({cfg.get('_source')})")
        if not cfg.get("execution", {}).get("dry_run", True):
            print("  WARNING: execution.dry_run is FALSE - live execution intended.")
        sp = cfg.get("secrets", {}).get("policy", "")
        if "honeytoken" not in sp.lower():
            problems.append("secrets.policy should state honeytoken-only usage.")
    except FileNotFoundError as e:
        problems.append(str(e))
    # catalogue: unique ids, known criteria/themes
    from core.frameworks import CRITERIA, THEMES
    seen = {}
    for a in ALL_AGENTS:
        for tc in a.test_cases:
            if tc.id in seen:
                problems.append(f"Duplicate test id {tc.id} ({a.key} & {seen[tc.id]}).")
            seen[tc.id] = a.key
            if tc.theme and tc.theme not in THEMES:
                problems.append(f"{tc.id}: unknown theme '{tc.theme}'.")
            if tc.criterion and tc.criterion not in CRITERIA:
                problems.append(f"{tc.id}: unknown criterion '{tc.criterion}'.")
    print(f"catalogue: {len(seen)} unique test cases across {len(ALL_AGENTS)} agents.")
    if problems:
        print("\nISSUES:")
        for p in problems:
            print(f"  - {p}")
        sys.exit(1)
    print("validate: OK")


# --------------------------------------------------------------------------- #
# arg parsing
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="run.py",
        description="POC test agents for Docker & GitHub Copilot local/cloud sandboxes.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--config", help="path to POC config JSON (default: config/poc.json|example).")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("list", help="list agents and test cases")
    s.add_argument("--agent", help="restrict to one agent key")
    s.set_defaults(func=cmd_list)

    s = sub.add_parser("show", help="print one test case")
    s.add_argument("test_id")
    s.set_defaults(func=cmd_show)

    s = sub.add_parser("plan", help="scaffold evidence records")
    s.add_argument("--agent", help="restrict to one agent key")
    s.add_argument("--priority", nargs="*", choices=["P1", "P2", "P3"], help="filter priorities")
    s.add_argument("--force", action="store_true", help="overwrite existing records")
    s.set_defaults(func=cmd_plan)

    s = sub.add_parser("record", help="fill in a case's evidence")
    s.add_argument("test_id")
    s.add_argument("--disposition", help="PASS|FAIL|PARTIAL|SKIPPED|BLOCKED|MANUAL_REVIEW|NOT_RUN")
    s.add_argument("--tester")
    s.add_argument("--note")
    s.add_argument("--agent-action", dest="agent_action")
    s.add_argument("--artifact", action="append", help="path to a captured artifact (repeatable)")
    s.add_argument("--alert", action="append", help="Sentinel alert ID (repeatable)")
    s.set_defaults(func=cmd_record)

    s = sub.add_parser("report", help="(re)generate reports")
    s.set_defaults(func=cmd_report)

    s = sub.add_parser("validate", help="sanity-check config + catalogue")
    s.set_defaults(func=cmd_validate)
    return p


def main(argv=None) -> None:
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
