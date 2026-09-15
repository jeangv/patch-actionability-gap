"""Week 3 task (W3.4), runner: score the 200-record NVD pilot slice
(data/pilot_20260905_v2/) with identifiability_scorer.py and report the
score distribution, per dimension, per era. This is the evidence that the
rubric anchors in docs/scoring_rubric_v0.1.md are actually computable, not
just specified.

Output: docs/identifiability_scores_pilot.md
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from identifiability_scorer import score_fix_availability_nvd, score_identifiability_nvd

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = REPO_ROOT / "data" / "pilot_20260905_v2"
OUT_PATH = REPO_ROOT / "docs" / "identifiability_scores_pilot.md"

ERA_FILES = {
    "pre-2024": "pre-2024.json",
    "backlog era": "backlog.json",
    "triage era": "triage.json",
}


def main() -> None:
    lines = ["# Identifiability + Fix-Availability Scores -- 200-Record Pilot Slice (NVD path)\n"]
    lines.append(
        "Dimensions 1 (identifiability) and 2 (fix availability) of "
        "`docs/scoring_rubric_v0.1.md`, scored against the same "
        "`data/pilot_20260905_v2/` slice reported in `docs/pilot_report_v2.md`. "
        "Dimension 3 (fix obtainability) is not scored here -- it requires the "
        "Week 6 retrievability checker.\n"
    )

    overall_id: Counter = Counter()
    overall_fa: Counter = Counter()
    examples: dict[int, str] = {}

    lines.append("## Identifiability -- score distribution\n")
    lines.append("| Era | n | Score 0 | Score 1 | Score 2 | Mean |")
    lines.append("|---|---:|---:|---:|---:|---:|")
    era_id_counts = {}
    for era, filename in ERA_FILES.items():
        records = json.loads((DATA_DIR / filename).read_text(encoding="utf-8"))
        counts = Counter()
        total = 0
        for r in records:
            score, reason = score_identifiability_nvd(r)
            counts[score] += 1
            overall_id[score] += 1
            total += score
            examples.setdefault(score, f"{r['id']}: {reason}")
        n = len(records)
        mean = total / n if n else 0
        era_id_counts[era] = counts
        lines.append(f"| {era} | {n} | {counts[0]} | {counts[1]} | {counts[2]} | {mean:.2f} |")
    n_all = sum(overall_id.values())
    mean_all = sum(k * v for k, v in overall_id.items()) / n_all if n_all else 0
    lines.append(f"| **Overall** | **{n_all}** | **{overall_id[0]}** | **{overall_id[1]}** | **{overall_id[2]}** | **{mean_all:.2f}** |")

    lines.append("\n## Fix availability -- score distribution\n")
    lines.append("| Era | n | Score 0 | Score 1 | Score 2 | Mean |")
    lines.append("|---|---:|---:|---:|---:|---:|")
    for era, filename in ERA_FILES.items():
        records = json.loads((DATA_DIR / filename).read_text(encoding="utf-8"))
        counts = Counter()
        total = 0
        for r in records:
            score, reason = score_fix_availability_nvd(r)
            counts[score] += 1
            overall_fa[score] += 1
            total += score
        n = len(records)
        mean = total / n if n else 0
        lines.append(f"| {era} | {n} | {counts[0]} | {counts[1]} | {counts[2]} | {mean:.2f} |")
    n_all_fa = sum(overall_fa.values())
    mean_all_fa = sum(k * v for k, v in overall_fa.items()) / n_all_fa if n_all_fa else 0
    lines.append(f"| **Overall** | **{n_all_fa}** | **{overall_fa[0]}** | **{overall_fa[1]}** | **{overall_fa[2]}** | **{mean_all_fa:.2f}** |")

    lines.append("\n## Worked examples, one per identifiability score (first match found)\n")
    for score in (0, 1, 2):
        if score in examples:
            lines.append(f"- **Score {score}:** {examples[score]}")

    OUT_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {OUT_PATH}")
    print("Identifiability overall:", dict(overall_id), f"mean={mean_all:.2f}")
    print("Fix availability overall:", dict(overall_fa), f"mean={mean_all_fa:.2f}")


if __name__ == "__main__":
    main()
