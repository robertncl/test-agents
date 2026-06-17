"""Appendix B evidence records: build, load, save.

Appendix B (Evidence Capture Standard) requires, for every case:
environment + config snapshot, exact command/prompt, agent action and tool calls,
artifacts (screenshots/log excerpts), Sentinel alert IDs, pass/fail disposition,
tester, timestamp. This module is the canonical representation of that record.
"""

from __future__ import annotations

import datetime
import json
import os
from dataclasses import asdict, dataclass, field

from .config import substitute
from .frameworks import THEMES
from .model import Disposition, TestCase


def utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


@dataclass
class EvidenceRecord:
    # --- identity / definition (copied from the TestCase) ---
    test_id: str
    title: str = ""
    priority: str = ""
    surface: str = ""
    control: str = ""
    pass_criteria: str = ""
    method: list = field(default_factory=list)
    command_or_prompt: list = field(default_factory=list)
    threat: str = ""
    theme: str = ""
    criterion: str = ""
    frameworks: dict = field(default_factory=dict)
    # --- Appendix B capture fields (filled in at execution) ---
    timestamp: str = ""
    tester: str = ""
    environment_snapshot: dict = field(default_factory=dict)
    config_snapshot: dict = field(default_factory=dict)
    agent_action: str = ""
    artifacts: list = field(default_factory=list)
    sentinel_alert_ids: list = field(default_factory=list)
    disposition: str = Disposition.NOT_RUN.value
    notes: str = ""

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=False)


def build_record(
    tc: TestCase,
    surface: str,
    env: dict,
    cfg_snapshot: dict,
    tok: dict[str, str],
) -> EvidenceRecord:
    """Pre-populate an evidence record from a test-case definition."""
    return EvidenceRecord(
        test_id=tc.id,
        title=tc.title,
        priority=tc.priority.value,
        surface=surface,
        control=tc.control,
        pass_criteria=substitute(tc.pass_criteria, tok),
        method=[substitute(m, tok) for m in tc.method],
        command_or_prompt=[substitute(c, tok) for c in tc.commands],
        threat=tc.threat,
        theme=tc.theme,
        criterion=tc.criterion,
        frameworks=THEMES.get(tc.theme, {}),
        environment_snapshot=env,
        config_snapshot=cfg_snapshot,
        notes=tc.notes,
        disposition=Disposition.NOT_RUN.value,
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
        data = json.load(f)
    return EvidenceRecord(**data)


def load_all_records(evidence_dir: str) -> list[EvidenceRecord]:
    if not os.path.isdir(evidence_dir):
        return []
    out = []
    for name in sorted(os.listdir(evidence_dir)):
        if name.endswith(".json"):
            with open(os.path.join(evidence_dir, name), encoding="utf-8") as f:
                out.append(EvidenceRecord(**json.load(f)))
    return out
