"""Week 4 task (W4.1): report the ambiguity-list count the soft exclusion
categories produce.

Re-classifies the already-collected v2 pilot slice (data/pilot_20260905_v2/
*.json, 200 records -- see docs/pilot_report_v2.md) through the current
corpus_filter.classify(), which now evaluates the six soft-exclusion
categories (src/soft_exclusions.py) and the curated-vendor-gated Include B.
No new NVD API calls -- this only re-runs the existing collected records
through the updated rule, which is exactly what PR1 flagged as expected: "the
pilot slice produced zero ambiguous records, which is expected while the
soft exclusion categories remain unimplemented and is not evidence that the
tiebreaker is unnecessary" (Appendix B). This script is the empirical check
of that statement.

Note on scope: this can only show records that FLIP from included to
excluded (soft exclusion never adds new inclusions, and Include B's
marginal contribution requires re-scanning the vendor-list-gated part:o/
part:a records NVD holds, which the original v2 pilot collector stopped
scanning as soon as its era quota was met -- see pilot_pull.py). The
Include-B marginal-catch question is answered separately by the corpus
freeze pass (W4.2), which does re-scan.

Output: docs/w4_soft_exclusion_recheck.md
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from corpus_filter import classify

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = REPO_ROOT / "data" / "pilot_20260905_v2"
OUT_PATH = REPO_ROOT / "docs" / "w4_soft_exclusion_recheck.md"

ERA_FILES = {
    "pre-2024": "pre-2024.json",
    "backlog era": "backlog.json",
    "triage era": "triage.json",
}


def main() -> None:
    lines = [
        "# W4.1 Soft Exclusion Recheck\n",
        "Re-classification of the already-collected v2 pilot slice "
        "(`data/pilot_20260905_v2/`, 200 records, see `docs/pilot_report_v2.md`) "
        "through the current `corpus_filter.classify()`, which now evaluates "
        "the six Appendix B soft-exclusion categories and the curated-"
        "vendor-gated Include B. No new NVD API calls were made.\n",
    ]

    total_records = 0
    total_flipped = 0
    total_ambiguous = 0
    category_counts: Counter = Counter()
    flipped_examples: list[str] = []

    lines.append("| Era | n | Still included | Flipped to excluded (soft exclusion) | Ambiguous (ties) |")
    lines.append("|---|---:|---:|---:|---:|")

    for era, filename in ERA_FILES.items():
        path = DATA_DIR / filename
        records = json.loads(path.read_text(encoding="utf-8"))
        still_included = 0
        flipped = 0
        ambiguous = 0
        for cve in records:
            decision = classify(cve)
            total_records += 1
            if decision.included:
                still_included += 1
            else:
                flipped += 1
                total_flipped += 1
                if len(flipped_examples) < 15:
                    flipped_examples.append(
                        f"{decision.cve_id}: {'; '.join(decision.exclude_reasons)}"
                    )
            if decision.ambiguous:
                ambiguous += 1
                total_ambiguous += 1
            category_counts.update(decision.soft_exclusion_tags)
        lines.append(f"| {era} | {len(records)} | {still_included} | {flipped} | {ambiguous} |")

    lines.append(f"| **Total** | **{total_records}** | **{total_records - total_flipped}** | **{total_flipped}** | **{total_ambiguous}** |")

    lines.append("\n## Soft-exclusion category breakdown (records where the category fired)\n")
    lines.append("| Category | Count |")
    lines.append("|---|---:|")
    for cat, count in category_counts.most_common():
        lines.append(f"| `{cat}` | {count} |")
    if not category_counts:
        lines.append("| (none fired) | 0 |")

    lines.append("\n## Flipped records (up to 15 shown)\n")
    if flipped_examples:
        for ex in flipped_examples:
            lines.append(f"- {ex}")
    else:
        lines.append("- None. Zero of the 200 pilot records match a soft-exclusion "
                      "category on their English description text.")

    lines.append(
        f"\n**Result: {total_flipped} of {total_records} previously-included pilot "
        f"records are excluded once soft-exclusion categories are evaluated "
        f"({total_flipped/total_records*100:.1f}%).** "
        f"{total_ambiguous} of those are logged to the ambiguity list "
        f"(matched an inclusion rule and an exclusion rule; the Appendix B "
        f"tiebreaker resolves ties to excluded)."
    )

    OUT_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {OUT_PATH}")
    print(f"Flipped: {total_flipped}/{total_records}, ambiguous: {total_ambiguous}")
    print(dict(category_counts))


if __name__ == "__main__":
    main()
