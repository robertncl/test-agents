#!/usr/bin/env python3
"""Orchestrator for the GitHub Copilot App POC test agents (plan v0.1).

Stdlib only - no `pip install` required. Subcommands:

  list   [--agent K] [--group G]   list agents and test cases
  show   <CASE-ID>                  print a single case (preconditions, steps, expected)
  plan   [--agent K] [--group G]    scaffold an Appendix-B evidence record per case
         [--must-pass] [--force]
  record <CASE-ID> [...]           fill in a case's evidence (status, tester, ...)
  report                           (re)generate coverage + scorecard + evidence-log + ...
  validate                         sanity-check config and the case catalogue

Examples:
  python run.py list --group G2
  python run.py plan --group G2            # set up Group 2 first
  python run.py show SC-11
  python run.py record SC-11 --status PASS --tester robert \\
      --actual "egress to canary blocked; PR warning raised" \\
      --evidence reports/sc-11.png --evidence SENT-9921 --note "logged in Sentinel"
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
from core.frameworks import GROUPS
from core.model import Disposition

EVIDENCE_DIR = os.environ.get("POC_EVIDENCE_DIR", "evidence")
REPORT_DIR = os.environ.get("POC_REPORT_DIR", "reports")


def _load_cfg(args) -> dict:
    return cfg_mod.load_config(getattr(args, "config", None))


def _selected_agents(args):
    agents = ALL_AGENTS
    if getattr(args, "agent", None):
        a = get_agent(args.agent)
        if not a:
            sys.exit(f"Unknown agent '{args.agent}'. Known: {[x.key for x in ALL_AGENTS]}")
        agents = [a]
    if getattr(args, "group", None):
        agents = [a for a in agents if a.group == args.group]
        if not agents:
            sys.exit(f"No agent in group '{args.group}'. Known groups: {list(GROUPS)}")
    return agents


def cmd_list(args) -> None:
    total = mp = 0
    for a in _selected_agents(args):
        n = len(a.test_cases)
        total += n
        mp += a.must_pass_count()
        print(f"\n[{a.key}] {a.name}  ({n} cases, {a.must_pass_count()} must-pass)")
        for tc in a.test_cases:
            flags = []
            if tc.must_pass:
                flags.append("must-pass")
            if tc.negative:
                flags.append("negative")
            tag = f"  ({', '.join(flags)})" if flags else ""
            print(f"    {tc.id:<7} {tc.control}{tag}")
    print(f"\nTotal: {total} cases ({mp} must-pass).")


def cmd_show(args) -> None:
    found = find_case(args.case_id)
    if not found:
        sys.exit(f"No such case: {args.case_id}")
    agent, tc = found
    cfg = _load_cfg(args)
    tok = cfg_mod.tokens(cfg)
    sub = cfg_mod.substitute
    print(f"{tc.id}  {tc.control}")
    print(f"agent     : {agent.key}  ({agent.name})")
    print(f"group     : {tc.group} - {GROUPS.get(tc.group, {}).get('label', '-')}")
    print(f"must-pass : {tc.must_pass}    negative: {tc.negative}")
    if tc.preconditions:
        print("precond.  :")
        for p in tc.preconditions:
            print(f"  - {sub(p, tok)}")
    print("steps     :")
    for m in tc.method:
        print(f"  - {sub(m, tok)}")
    if tc.commands:
        print("commands  :")
        for c in tc.commands:
            print(f"  $ {sub(c, tok)}")
    print(f"expected  : {sub(tc.expected, tok)}")
    if tc.measure:
        print(f"measure   : {tc.measure}")
    if tc.notes:
        print(f"notes     : {tc.notes}")


def cmd_plan(args) -> None:
    cfg = _load_cfg(args)
    env = cfg_mod.env_snapshot(cfg)
    snap = cfg_mod.config_snapshot(cfg)
    tok = cfg_mod.tokens(cfg)
    created = skipped = 0
    for a in _selected_agents(args):
        for tc in a.select(must_pass_only=args.must_pass):
            path = ev.record_path(EVIDENCE_DIR, tc.id)
            if os.path.exists(path) and not args.force:
                skipped += 1
                continue
            ev.save_record(EVIDENCE_DIR, ev.build_record(tc, env, snap, tok))
            created += 1
    print(f"Scaffolded {created} evidence record(s) into {EVIDENCE_DIR}/ "
          f"({skipped} preserved; use --force to regenerate).")
    if created:
        print("Next: execute each case in the ring-fenced POC org, then "
              "`python run.py record <CASE-ID> --status ...`.")


def cmd_record(args) -> None:
    rec = ev.load_record(EVIDENCE_DIR, args.case_id)
    if rec is None:
        found = find_case(args.case_id)
        if not found:
            sys.exit(f"No such case: {args.case_id}")
        agent, tc = found
        cfg = _load_cfg(args)
        rec = ev.build_record(tc, cfg_mod.env_snapshot(cfg),
                              cfg_mod.config_snapshot(cfg), cfg_mod.tokens(cfg))
    if args.status:
        valid = [d.value for d in Disposition]
        if args.status not in valid:
            sys.exit(f"Invalid status '{args.status}'. Valid: {valid}")
        rec.status = args.status
    if args.tester:
        rec.tester = args.tester
    if args.actual:
        rec.actual_result = args.actual
    if args.note:
        rec.notes = (rec.notes + "\n" if rec.notes else "") + args.note
    if args.linked_risk:
        rec.linked_risk = args.linked_risk
    for e in args.evidence or []:
        rec.evidence_refs.append(e)
    rec.timestamp = ev.utc_now()
    path = ev.save_record(EVIDENCE_DIR, rec)
    print(f"Updated {path}  ->  status={rec.status} tester={rec.tester or '-'}")


def cmd_report(args) -> None:
    records = ev.load_all_records(EVIDENCE_DIR)
    os.makedirs(REPORT_DIR, exist_ok=True)
    outputs = {
        "COVERAGE.md": rpt.coverage_matrix(ALL_AGENTS),
        "GO-NO-GO-SCORECARD.md": rpt.go_no_go_scorecard(ALL_AGENTS, records),
        "RUN-SUMMARY.md": rpt.run_summary(ALL_AGENTS, records),
        "EVIDENCE-LOG.md": rpt.evidence_log(records),
        "GOLDEN-POLICY-BASELINE.md": rpt.golden_policy_baseline(),
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
    seen = {}
    for a in ALL_AGENTS:
        if a.group not in GROUPS:
            problems.append(f"Agent {a.key}: unknown group '{a.group}'.")
        for tc in a.test_cases:
            if tc.id in seen:
                problems.append(f"Duplicate case id {tc.id} ({a.key} & {seen[tc.id]}).")
            seen[tc.id] = a.key
            if tc.group not in GROUPS:
                problems.append(f"{tc.id}: unknown group '{tc.group}'.")
    mp = sum(a.must_pass_count() for a in ALL_AGENTS)
    print(f"catalogue: {len(seen)} unique cases across {len(ALL_AGENTS)} agents "
          f"({mp} must-pass).")
    if problems:
        print("\nISSUES:")
        for p in problems:
            print(f"  - {p}")
        sys.exit(1)
    print("validate: OK")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="run.py",
        description="POC test agents for the GitHub Copilot App (plan v0.1).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--config", help="path to POC config JSON (default: config/poc.json|example).")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("list", help="list agents and cases")
    s.add_argument("--agent")
    s.add_argument("--group", help="group key, e.g. G2")
    s.set_defaults(func=cmd_list)

    s = sub.add_parser("show", help="print one case")
    s.add_argument("case_id")
    s.set_defaults(func=cmd_show)

    s = sub.add_parser("plan", help="scaffold evidence records")
    s.add_argument("--agent")
    s.add_argument("--group", help="group key, e.g. G2")
    s.add_argument("--must-pass", action="store_true", dest="must_pass",
                   help="only must-pass cases")
    s.add_argument("--force", action="store_true", help="overwrite existing records")
    s.set_defaults(func=cmd_plan)

    s = sub.add_parser("record", help="fill in a case's evidence")
    s.add_argument("case_id")
    s.add_argument("--status", help="PASS|FAIL|BLOCKED|PARTIAL|NOT_APPLICABLE|NOT_RUN")
    s.add_argument("--tester")
    s.add_argument("--actual", help="actual result observed")
    s.add_argument("--note")
    s.add_argument("--linked-risk", dest="linked_risk", help="risk-register ID (Appendix C)")
    s.add_argument("--evidence", action="append",
                   help="evidence ref: screenshot / session-log ID / audit-event ID / SIEM alert (repeatable)")
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
