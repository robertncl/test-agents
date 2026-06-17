"""Evidence records aligned to the Appendix B test-case template + Appendix C log.

Appendix B template fields: ID, Group, Control under test, Preconditions, Steps,
Expected (pass) result, Actual result, Status, Evidence refs (screenshot /
session-log ID / audit-event ID / SIEM alert), Notes / residual risk, Tester / date.
"""

from __future__ import annotations

import datetime
import json
import os
from dataclasses import asdict, dataclass, field

from .config import substitute
from .frameworks import group_label
from .model import Disposition, TestCase


def utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


@dataclass
class EvidenceRecord:
    # --- definition (copied from the TestCase) ---
    test_id: str
    group: str = ""
    group_label: str = ""
    control: str = ""                       # control under test
    preconditions: list = field(default_factory=list)
    method: list = field(default_factory=list)            # steps
    command_or_prompt: list = field(default_factory=list)
    expected: str = ""                      # expected (pass) result
    must_pass: bool = False
    negative: bool = False
    measure: str = ""
    # --- capture fields (filled in at execution) ---
    timestamp: str = ""
    tester: str = ""
    environment_snapshot: dict = field(default_factory=dict)
    config_snapshot: dict = field(default_factory=dict)
    actual_result: str = ""
    status: str = Disposition.NOT_RUN.value
    evidence_refs: list = field(default_factory=list)      # screenshots/session/audit/SIEM
    linked_risk: str = ""                   # Appendix C: linked risk-register ID
    notes: str = ""                         # notes / residual risk

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=False)


def build_record(tc: TestCase, env: dict, cfg_snap: dict, tok: dict[str, str]) -> EvidenceRecord:
    sub = lambda s: substitute(s, tok)  # noqa: E731
    return EvidenceRecord(
        test_id=tc.id,
        group=tc.group,
        group_label=group_label(tc.group),
        control=tc.control,
        preconditions=[sub(p) for p in tc.preconditions],
        method=[sub(m) for m in tc.method],
        command_or_prompt=[sub(c) for c in tc.commands],
        expected=sub(tc.expected),
        must_pass=tc.must_pass,
        negative=tc.negative,
        measure=tc.measure,
        environment_snapshot=env,
        config_snapshot=cfg_snap,
        status=Disposition.NOT_RUN.value,
        notes=tc.notes,
    )


def record_path(evidence_dir: str, test_id: str) -> str:
    return os.path.join(evidence_dir, f"{test_id}.json")


def save_record(evidence_dir: str, rec: EvidenceRecord) -> str:
    os.makedirs(evidence_dir, exist_ok=True)
    path = record_path(evidence_dir, rec.test_id)
    with open(path, "w", encoding="utf-8") as f:
        f.write(rec.to_json())
    return path


def load_record(evidence_dir: str, test_id: str) -> EvidenceRecord | None:
    path = record_path(evidence_dir, test_id)
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return EvidenceRecord(**json.load(f))


def load_all_records(evidence_dir: str) -> list[EvidenceRecord]:
    if not os.path.isdir(evidence_dir):
        return []
    out = []
    for name in sorted(os.listdir(evidence_dir)):
        if name.endswith(".json"):
            with open(os.path.join(evidence_dir, name), encoding="utf-8") as f:
                out.append(EvidenceRecord(**json.load(f)))
    return out
