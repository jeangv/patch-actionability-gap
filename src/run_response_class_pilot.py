"""Provisional run of response_class.classify_response() against the
200-record pilot slice, using fix_availability scores from
identifiability_scorer.py. fix_obtainability=None and eol=None throughout
(Dimension 3 and EOL detection are not implemented yet -- Week 6 and
beyond), so every record lands in FIX_OBTAINABLE (provisional) or
NO_FIX_EOL_UNKNOWN. This is NOT the response-routing evaluation (PR1
Evaluation #6, due Week 9) -- it is a computability check, showing the
mapping runs end to end on real records, with the provisionality stated
plainly in the output.

Output: docs/response_class_pilot_provisional.md
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from identifiability_scorer import score_fix_availability_nvd
from response_class import classify_response

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = REPO_ROOT / "data" / "pilot_20260905_v2"
OUT_PATH = REPO_ROOT / "docs" / "response_class_pilot_provisional.md"

ERA_FILES = {
    "pre-2024": "pre-2024.json",
    "backlog era": "backlog.json",
    "triage era": "triage.json",
}


def main() -> None:
    lines = ["# Response-Class Mapping -- Provisional Pilot Run\n"]
    lines.append(
        "**Provisional, not the response-routing evaluation.** Dimension 3 "
        "(fix obtainability) is not implemented until Week 6, and end-of-life "
        "detection is not implemented at all yet (PR1 already names this as "
        "the hardest input). Every record here is scored with "
        "`fix_obtainability_score=None, eol=None`, so results collapse to two "
        "classes: `FIX_OBTAINABLE` (provisional -- fix availability scored 2, "
        "obtainability not yet verified) and `NO_FIX_EOL_UNKNOWN`. This run "
        "exists to show `response_class.classify_response()` runs end to end "
        "against real records, not to report a response-routing finding.\n"
    )

    overall: Counter = Counter()
    lines.append("| Era | n | FIX_OBTAINABLE (provisional) | NO_FIX_EOL_UNKNOWN |")
    lines.append("|---|---:|---:|---:|")
    for era, filename in ERA_FILES.items():
        records = json.loads((DATA_DIR / filename).read_text(encoding="utf-8"))
        counts = Counter()
        for r in records:
            fa_score, _ = score_fix_availability_nvd(r)
            response = classify_response(fa_score, None, None)
            counts[response.name] += 1
            overall[response.name] += 1
        n = len(records)
        lines.append(f"| {era} | {n} | {counts.get('FIX_OBTAINABLE', 0)} | {counts.get('NO_FIX_EOL_UNKNOWN', 0)} |")
    n_all = sum(overall.values())
    lines.append(f"| **Overall** | **{n_all}** | **{overall.get('FIX_OBTAINABLE', 0)}** | **{overall.get('NO_FIX_EOL_UNKNOWN', 0)}** |")

    non_patch = overall.get("NO_FIX_EOL_UNKNOWN", 0)
    lines.append(
        f"\n**{non_patch} of {n_all} records ({non_patch/n_all*100:.1f}%) would route to a "
        f"non-patch response under this provisional mapping** -- read as an "
        f"upper bound before Dimension 3 and EOL detection exist, since some of "
        f"the {overall.get('FIX_OBTAINABLE', 0)} provisional FIX_OBTAINABLE "
        f"records will likely fail obtainability once Dimension 3 is scored, "
        f"which would move them into a non-patch class too. The real "
        f"response-routing evaluation (PR1 Evaluation #6) is scheduled Week 9."
    )

    OUT_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {OUT_PATH}")
    print(dict(overall))


if __name__ == "__main__":
    main()
