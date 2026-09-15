"""Week 3 task (W3.5), part 3: the NVD-side half of the exclusion-count
comparison. Scans the NVD API for the identical date window as
v5_corpus_pass.py (2024-01-01 onward) and applies the existing CPE-based
corpus_filter.classify(), so the two counts are comparable: same date range,
same curated vendor list and soft-exclusion categories, different corpus
source.

This is the number the CVE List V5 pivot exists to produce: the count NVD's
`configurations`-gated (i.e. enrichment-dependent) path finds vs. the count
CVE List V5's CNA-container-based path finds, for the exact same window.

Output: docs/nvd_2024_onward_pass.md
"""
from __future__ import annotations

import json
import time
from collections import Counter
from datetime import datetime
from pathlib import Path

from corpus_filter import classify
from nvd_client import NvdClient, date_windows

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT_PATH = REPO_ROOT / "docs" / "nvd_2024_onward_pass.md"
IDS_PATH = REPO_ROOT / "data" / "nvd_2024_onward_included_ids.json"

START = datetime(2024, 1, 1)


def main() -> None:
    client = NvdClient()
    now = datetime.now()
    started = time.monotonic()

    total_scanned = 0
    total_included = 0
    per_window_stats = []
    included_ids: list[str] = []
    reason_tag_counts: Counter = Counter()

    for w in date_windows(START, now):
        w_scanned = 0
        w_included = 0
        for cve in client.iter_cves(w.as_params()):
            total_scanned += 1
            w_scanned += 1
            decision = classify(cve)
            if decision.included:
                total_included += 1
                w_included += 1
                included_ids.append(decision.cve_id)
                for tag in decision.rule_tags:
                    reason_tag_counts[tag] += 1
        per_window_stats.append((w.start, w.end, w_scanned, w_included))
        elapsed = time.monotonic() - started
        print(
            f"  window {w.start.date()}..{w.end.date()}: scanned {w_scanned:,}, "
            f"included {w_included:,} | total scanned {total_scanned:,} | elapsed {elapsed:,.0f}s",
            flush=True,
        )

    elapsed = time.monotonic() - started
    print(f"Done: {total_scanned:,} scanned, {total_included:,} included, {elapsed:,.0f}s")

    lines = []
    lines.append("# NVD API Pass -- 2024-01-01 Onward (comparison window for the V5 corpus pass)\n")
    lines.append(
        f"{total_scanned:,} CVEs scanned via the NVD CVE API 2.0, "
        f"{total_included:,} included by `corpus_filter.classify()` (CPE-based, "
        f"curated vendor list + soft exclusions applied), {elapsed:,.0f}s.\n"
    )
    lines.append(
        "**Comparable directly to `docs/v5_corpus_pass_2024_2026.md`** -- same "
        "2024-01-01 onward date range, same curated vendor list, same soft-"
        "exclusion categories. The difference between the two totals is the "
        "NVD-enrichment-dependent path's exclusion count.\n"
    )
    lines.append(f"**NVD-path result: {total_included:,} included of {total_scanned:,} scanned.**\n")

    lines.append("\n## Per-window\n")
    lines.append("| Window | Scanned | Included |")
    lines.append("|---|---:|---:|")
    for start, end, scanned, inc in per_window_stats:
        lines.append(f"| {start.date()} .. {end.date()} | {scanned:,} | {inc:,} |")

    lines.append("\n## Rule-tag breakdown\n")
    lines.append("| Tag | Count |")
    lines.append("|---|---:|")
    for tag, count in reason_tag_counts.most_common():
        lines.append(f"| `{tag}` | {count:,} |")

    OUT_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    IDS_PATH.write_text(json.dumps(sorted(included_ids)), encoding="utf-8")
    print(f"Wrote {OUT_PATH}")
    print(f"Wrote {IDS_PATH}")


if __name__ == "__main__":
    main()
