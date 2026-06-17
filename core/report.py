"""Report generators (plan v0.1): coverage, go/no-go, evidence log, golden policy.

All outputs are Markdown built from (a) the agent test-case definitions and
(b) whatever evidence records currently exist. No network calls.
"""

from __future__ import annotations

from .evidence import EvidenceRecord
from .frameworks import (
    DECISION,
    GOLDEN_POLICY_BASELINE,
    GROUPS,
    SUCCESS_CRITERIA,
    group_label,
)
from .model import BLOCKING_DISPOSITIONS, RUN_DISPOSITIONS, Disposition


def coverage_matrix(agents: list) -> str:
    lines = [
        "# Coverage Matrix",
        "",
        "Every test case mapped to its plan group, with must-pass / negative flags.",
        "",
        "| Case | Group | Control under test | Must-pass | Negative |",
        "|---|---|---|---|---|",
    ]
    for agent in agents:
        for tc in agent.test_cases:
            mp = "YES" if tc.must_pass else "-"
            neg = "YES" if tc.negative else "-"
            lines.append(
                f"| {tc.id} | {group_label(tc.group)} | {tc.control} | {mp} | {neg} |"
            )
    return "\n".join(lines) + "\n"


def _disp(rec: EvidenceRecord | None) -> Disposition:
    return Disposition(rec.status) if rec else Disposition.NOT_RUN


def go_no_go_scorecard(agents: list, records: list[EvidenceRecord]) -> str:
    by_id = {r.test_id: r for r in records}

    lines = [
        "# Go / No-Go Scorecard",
        "",
        "Gate per B.2 / B.12: **100% of must-pass cases must pass; 0 critical "
        "bypasses; every negative test blocked AND logged.**",
        "",
        "| Group | Must-pass (pass/total) | FAIL | BLOCKED | Outstanding | Status |",
        "|---|---|---|---|---|---|",
    ]

    total_mp = total_mp_pass = total_mp_fail = total_mp_blocked = total_mp_out = 0
    for gkey, g in GROUPS.items():
        members = [tc for a in agents for tc in a.test_cases
                   if tc.group == gkey and tc.must_pass]
        if not members:
            continue
        mp = len(members)
        passed = failed = blocked = outstanding = 0
        for tc in members:
            d = _disp(by_id.get(tc.id))
            if d == Disposition.PASS:
                passed += 1
            elif d == Disposition.FAIL:
                failed += 1
            elif d == Disposition.BLOCKED:
                blocked += 1
            elif d not in RUN_DISPOSITIONS:
                outstanding += 1
        total_mp += mp
        total_mp_pass += passed
        total_mp_fail += failed
        total_mp_blocked += blocked
        total_mp_out += outstanding
        if failed or blocked:
            status = ":x: NO-GO trend"
        elif outstanding:
            status = ":hourglass: incomplete"
        else:
            status = ":white_check_mark: pass"
        lines.append(
            f"| {g['label']} | {passed}/{mp} | {failed} | {blocked} | "
            f"{outstanding} | {status} |"
        )

    # negative-test discipline
    neg_cases = [tc for a in agents for tc in a.test_cases if tc.negative]
    neg_ok = 0
    for tc in neg_cases:
        rec = by_id.get(tc.id)
        if rec and rec.status == Disposition.PASS.value and rec.evidence_refs:
            neg_ok += 1

    lines += [
        "",
        f"**Must-pass overall:** {total_mp_pass}/{total_mp} pass · "
        f"{total_mp_fail} FAIL · {total_mp_blocked} BLOCKED · {total_mp_out} outstanding.",
        f"**Negative tests blocked AND logged:** {neg_ok}/{len(neg_cases)} "
        "(PASS with evidence refs).",
        "",
        "## Decision logic (B.12)",
        f"- **GO** - {DECISION['GO']}",
        f"- **GO WITH CONDITIONS** - {DECISION['GO_WITH_CONDITIONS']}",
        f"- **NO-GO** - {DECISION['NO_GO']}",
        "",
    ]
    if total_mp_fail or total_mp_blocked:
        failing = sorted({
            tc.id for a in agents for tc in a.test_cases
            if tc.must_pass and _disp(by_id.get(tc.id)) in BLOCKING_DISPOSITIONS
        })
        lines.append(
            f"> :rotating_light: **Provisional: NO-GO.** Must-pass FAIL/BLOCKED: "
            f"{', '.join(failing)}. A critical control bypass blocks adoption (B.12)."
        )
    elif total_mp_out:
        lines.append(
            "> :hourglass: **Provisional: INCOMPLETE.** Run the remaining must-pass "
            "cases before deciding; compliance items (B.9) gate GO vs GO-WITH-CONDITIONS."
        )
    else:
        lines.append(
            "> :white_check_mark: **Provisional: GO / GO-WITH-CONDITIONS.** All must-pass "
            "cases pass. Confirm residency/retention acceptance (B.9) and the golden "
            "policy baseline (Appendix A) for an unconditional GO."
        )
    return "\n".join(lines) + "\n"


def run_summary(agents: list, records: list[EvidenceRecord]) -> str:
    by_id = {r.test_id: r for r in records}
    counts = {d.value: 0 for d in Disposition}
    for r in records:
        counts[r.status] = counts.get(r.status, 0) + 1
    total = sum(len(a.test_cases) for a in agents)
    mp_total = sum(a.must_pass_count() for a in agents)

    lines = [
        "# Run Summary",
        "",
        f"- Test cases defined: **{total}** across **{len(agents)}** agents "
        f"(**{mp_total}** must-pass)",
        f"- Evidence records present: **{len(records)}**",
        "",
        "## Status counts",
        "| Status | Count |",
        "|---|---|",
    ]
    for d in Disposition:
        lines.append(f"| {d.value} | {counts.get(d.value, 0)} |")

    outstanding = []
    for a in agents:
        for tc in a.test_cases:
            if not tc.must_pass:
                continue
            rec = by_id.get(tc.id)
            st = rec.status if rec else Disposition.NOT_RUN.value
            if st != Disposition.PASS.value:
                outstanding.append(f"{tc.id} ({st})")
    lines += ["", "## Must-pass cases not yet PASS", ""]
    if outstanding:
        lines += [f"- {x}" for x in outstanding]
    else:
        lines.append("All must-pass cases PASS. :white_check_mark:")
    lines.append("")
    return "\n".join(lines) + "\n"


def evidence_log(records: list[EvidenceRecord]) -> str:
    """Appendix C - one row per executed test case."""
    lines = [
        "# Evidence Log (Appendix C)",
        "",
        "| Case ID | Date | Tester | Result | Evidence ref(s) | Linked risk | Notes |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in sorted(records, key=lambda x: x.test_id):
        refs = "; ".join(r.evidence_refs) if r.evidence_refs else "-"
        date = (r.timestamp or "-")[:10] if r.timestamp else "-"
        note = (r.notes or "-").splitlines()[0] if r.notes else "-"
        lines.append(
            f"| {r.test_id} | {date} | {r.tester or '-'} | {r.status} | "
            f"{refs} | {r.linked_risk or '-'} | {note} |"
        )
    return "\n".join(lines) + "\n"


def golden_policy_baseline() -> str:
    lines = [
        "# Golden Policy Baseline (Appendix A)",
        "",
        "Reproducible enterprise/org policy set required for any production rollout. "
        "Finalise values from POC evidence; lock and export.",
        "",
    ]
    lines += [f"- [ ] {item}" for item in GOLDEN_POLICY_BASELINE]
    lines += ["", "## Success criteria (B.2)", ""]
    for k, v in SUCCESS_CRITERIA.items():
        lines.append(f"- **{k.capitalize()}:** {v}")
    return "\n".join(lines) + "\n"
