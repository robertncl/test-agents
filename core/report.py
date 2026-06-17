"""Report generators: traceability matrix, go/no-go scorecard, run summary.

All outputs are Markdown built from (a) the agent test-case definitions and
(b) whatever evidence records currently exist. Nothing here makes a network call.
"""

from __future__ import annotations

from .evidence import EvidenceRecord
from .frameworks import CRITERIA, THEMES
from .model import Disposition, RUN_DISPOSITIONS

_FRAMEWORK_COLS = [
    "BNM RMiT",
    "MAS TRM/FEAT",
    "NIST AI RMF",
    "OWASP Agentic Top 10",
    "MITRE ATLAS",
    "ISO/IEC",
]


def traceability_matrix(agents: list) -> str:
    """section 7 mapping, expanded to one row per test case."""
    lines = [
        "# Regulatory Traceability Matrix",
        "",
        "Generated from the test-agent definitions. Maps every test case to its "
        "control theme (POC plan s.7) and applicable framework clauses.",
        "",
        "| Test | Pri | Surface | Theme | " + " | ".join(_FRAMEWORK_COLS) + " |",
        "|---|---|---|---|" + "|".join(["---"] * len(_FRAMEWORK_COLS)) + "|",
    ]
    for agent in agents:
        for tc in agent.test_cases:
            theme = THEMES.get(tc.theme, {})
            cells = [theme.get(col, "-") for col in _FRAMEWORK_COLS]
            lines.append(
                f"| {tc.id} | {tc.priority.value} | {agent.surface} | "
                f"{theme.get('label', '-')} | " + " | ".join(cells) + " |"
            )
    return "\n".join(lines) + "\n"


def _disp_counts(records: list[EvidenceRecord]) -> dict[str, int]:
    counts = {d.value: 0 for d in Disposition}
    for r in records:
        counts[r.disposition] = counts.get(r.disposition, 0) + 1
    return counts


def go_no_go_scorecard(agents: list, records: list[EvidenceRecord]) -> str:
    by_id = {r.test_id: r for r in records}
    lines = [
        "# Go / No-Go Scorecard",
        "",
        "Weighted criteria from POC plan s.9. 'Readiness' = PASS / (run cases) per "
        "criterion. Criteria with any P1 FAIL/BLOCKED are flagged for the decision logic.",
        "",
        "| Criterion | Weight | Cases (run/total) | PASS | FAIL | Other | P1 fails | Readiness |",
        "|---|---|---|---|---|---|---|---|",
    ]
    weighted_ready = 0.0
    p1_failures: list[str] = []
    for ckey, c in CRITERIA.items():
        members = []
        for agent in agents:
            for tc in agent.test_cases:
                if tc.criterion == ckey:
                    members.append(tc)
        total = len(members)
        run = passed = failed = other = p1f = 0
        for tc in members:
            rec = by_id.get(tc.id)
            disp = Disposition(rec.disposition) if rec else Disposition.NOT_RUN
            if disp in RUN_DISPOSITIONS:
                run += 1
            if disp == Disposition.PASS:
                passed += 1
            elif disp == Disposition.FAIL:
                failed += 1
                if tc.priority.value == "P1":
                    p1f += 1
                    p1_failures.append(tc.id)
            elif disp == Disposition.BLOCKED:
                other += 1
                if tc.priority.value == "P1":
                    p1f += 1
                    p1_failures.append(tc.id)
            elif disp != Disposition.NOT_RUN:
                other += 1
        readiness = (passed / run) if run else 0.0
        weighted_ready += readiness * c["weight"]
        flag = f"**{p1f}**" if p1f else "0"
        lines.append(
            f"| {ckey} {c['label']} | {int(c['weight']*100)}% | {run}/{total} | "
            f"{passed} | {failed} | {other} | {flag} | {readiness*100:.0f}% |"
        )
    lines += [
        "",
        f"**Weighted readiness (run-weighted):** {weighted_ready*100:.0f}%",
        "",
        "## Decision logic (POC plan s.9)",
        "- **GO** - every P1 passes; adversarial impacts fully contained and detected.",
        "- **CONDITIONAL GO** - minor/P2 gaps with documented compensating controls.",
        "- **NO-GO** - any P1 isolation/governance/guardrail failure without a "
        "compensating control, or undetectable exfiltration.",
        "",
    ]
    if p1_failures:
        lines.append(
            "> :rotating_light: **P1 failures present** "
            f"({', '.join(sorted(set(p1_failures)))}). "
            "Per decision logic this trends NO-GO unless each has a documented "
            "compensating control (then CONDITIONAL GO)."
        )
    else:
        lines.append(
            "> No P1 FAIL/BLOCKED recorded yet. Provisional reading depends on how "
            "many P1 cases remain NOT_RUN - run them before deciding."
        )
    return "\n".join(lines) + "\n"


def run_summary(agents: list, records: list[EvidenceRecord]) -> str:
    counts = _disp_counts(records)
    total_defined = sum(len(a.test_cases) for a in agents)
    lines = [
        "# Run Summary",
        "",
        f"- Test cases defined: **{total_defined}** across **{len(agents)}** agents",
        f"- Evidence records present: **{len(records)}**",
        "",
        "## Dispositions",
        "| Disposition | Count |",
        "|---|---|",
    ]
    for d in Disposition:
        lines.append(f"| {d.value} | {counts.get(d.value, 0)} |")

    # P1 outstanding
    by_id = {r.test_id: r for r in records}
    p1_outstanding = []
    for agent in agents:
        for tc in agent.test_cases:
            if tc.priority.value != "P1":
                continue
            rec = by_id.get(tc.id)
            disp = rec.disposition if rec else Disposition.NOT_RUN.value
            if disp not in (Disposition.PASS.value,):
                p1_outstanding.append(f"{tc.id} ({disp})")
    lines += [
        "",
        "## P1 cases not yet PASS",
        "",
    ]
    if p1_outstanding:
        for item in p1_outstanding:
            lines.append(f"- {item}")
    else:
        lines.append("All P1 cases PASS. :white_check_mark:")
    lines.append("")
    return "\n".join(lines) + "\n"


def evidence_index(records: list[EvidenceRecord]) -> str:
    lines = [
        "# Evidence Pack Index",
        "",
        "| Test | Pri | Surface | Disposition | Tester | Timestamp | Sentinel alerts |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in sorted(records, key=lambda x: x.test_id):
        alerts = ", ".join(r.sentinel_alert_ids) if r.sentinel_alert_ids else "-"
        lines.append(
            f"| {r.test_id} | {r.priority} | {r.surface} | {r.disposition} | "
            f"{r.tester or '-'} | {r.timestamp or '-'} | {alerts} |"
        )
    return "\n".join(lines) + "\n"
