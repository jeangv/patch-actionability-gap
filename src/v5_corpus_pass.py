"""Week 3 task (W3.5), part 2: run the CVE List V5 corpus filter
(corpus_filter_v5.classify()) over the local V5 sparse checkout and quantify
what the NVD-API path was excluding.

Scope decision (stated explicitly, not hidden): this pass covers the
backlog era (2024 - Feb 2026) and triage era (Mar 2026 onward) in full --
142,781 CVE List V5 records, sparse-checked-out locally via
`git clone --filter=blob:none --sparse` (see data/v5_repo/, gitignored).
It does NOT re-run pre-2024 (1999-2023), which would require a much larger
sparse checkout (25 more year-directories) for a period that predates the
policy problem this pass exists to quantify: NVD's April 2026 enrichment
restriction only affects triage-era records, and the backlog-era comparison
is the control for "was this already a problem before the policy," so
2024-2026 is the decision-relevant window. Pre-2024 individual records are
still checked against V5 at the record level by v5_pilot_recheck.py (fetches
the exact 67 pre-2024 pilot CVE IDs from CVE List V5 directly), just not at
full-population scale.

For the NVD-side comparison over the identical date window, see
nvd_2024_onward_pass.py, which scans the NVD API for the same 2024-01-01
onward range using the existing (CPE-based) corpus_filter.classify().

Output: docs/v5_corpus_pass_2024_2026.md
"""
from __future__ import annotations

import json
import time
from collections import Counter
from pathlib import Path

from corpus_filter_v5 import classify

REPO_ROOT = Path(__file__).resolve().parent.parent
V5_REPO = REPO_ROOT / "data" / "v5_repo" / "cves"
OUT_PATH = REPO_ROOT / "docs" / "v5_corpus_pass_2024_2026.md"
YEARS = ["2024", "2025", "2026"]


def iter_records():
    for year in YEARS:
        year_dir = V5_REPO / year
        if not year_dir.exists():
            continue
        for path in year_dir.glob("*/*.json"):
            with open(path, encoding="utf-8") as f:
                try:
                    yield year, json.load(f)
                except json.JSONDecodeError:
                    continue


def main() -> None:
    started = time.monotonic()
    total = 0
    included = 0
    ambiguous = 0
    had_cpe = 0
    reason_tag_counts: Counter = Counter()
    soft_excl_counts: Counter = Counter()
    per_year_scanned: Counter = Counter()
    per_year_included: Counter = Counter()
    vendor_counts: Counter = Counter()
    included_ids: list[str] = []

    for year, record in iter_records():
        total += 1
        per_year_scanned[year] += 1
        decision = classify(record)
        if decision.had_cpe_applicability:
            had_cpe += 1
        if decision.ambiguous:
            ambiguous += 1
        if decision.include_reasons:
            # Only records that also matched an inclusion signal, matching
            # the "among records that also matched inclusion" report label
            # below -- previously counted soft-exclusion hits across every
            # scanned record regardless of inclusion, which produced large,
            # misleading counts (e.g. hundreds of ICS/medical hits) even
            # when `ambiguous` -- the actually-relevant tiebreaker count --
            # was 0. Found while verifying an unrelated bug report (Sep 2026).
            soft_excl_counts.update(decision.soft_exclusion_tags)
        if decision.included:
            included += 1
            per_year_included[year] += 1
            included_ids.append(decision.cve_id)
            for reason in decision.include_reasons:
                tag = reason.split(":", 1)[0]
                reason_tag_counts[tag] += 1
                if tag == "v5_vendor_and_category":
                    vendor = reason.split(":", 2)[1].strip()
                    vendor_counts[vendor] += 1
        if total % 20000 == 0:
            print(f"  scanned {total:,} | included {included:,} | elapsed {time.monotonic()-started:,.0f}s", flush=True)

    elapsed = time.monotonic() - started
    print(f"Done: {total:,} scanned, {included:,} included, {elapsed:,.0f}s")

    lines = []
    lines.append("# CVE List V5 Corpus Pass -- Backlog + Triage Eras (2024-2026)\n")
    lines.append(
        f"Local sparse checkout of `cves/2024`, `cves/2025`, `cves/2026` from "
        f"`github.com/CVEProject/cvelistV5` (git filter=blob:none, sparse-checkout; "
        f"see `data/v5_repo/`, gitignored). {total:,} CVE List V5 records scanned in "
        f"{elapsed:,.0f}s using `corpus_filter_v5.classify()`.\n"
    )
    lines.append(
        "**Scope:** backlog era (2024-Feb 2026) + triage era (Mar 2026-) only. "
        "See module docstring in `src/v5_corpus_pass.py` for why pre-2024 is out "
        "of scope for this population-level pass.\n"
    )
    lines.append(f"**Result: {included:,} of {total:,} records ({included/total*100:.2f}%) "
                  f"match the V5-based embedded/IoT inclusion rule.**\n")
    lines.append(f"- `cpeApplicability` present in either container: {had_cpe:,} of {total:,} "
                  f"({had_cpe/total*100:.2f}%) -- confirms this is rare, per module docstring.\n"
                  f"- Ambiguous (matched inclusion and a soft-exclusion category): {ambiguous:,}\n")

    lines.append("\n## Per-year\n")
    lines.append("| Year | Scanned | Included | % |")
    lines.append("|---|---:|---:|---:|")
    for year in YEARS:
        s = per_year_scanned.get(year, 0)
        i = per_year_included.get(year, 0)
        pct = f"{i/s*100:.2f}%" if s else "n/a"
        lines.append(f"| {year} | {s:,} | {i:,} | {pct} |")

    lines.append("\n## Inclusion-reason breakdown (a record can match more than one)\n")
    lines.append("| Reason | Count |")
    lines.append("|---|---:|")
    for tag, count in reason_tag_counts.most_common():
        lines.append(f"| `{tag}` | {count:,} |")

    lines.append("\n## Soft-exclusion category breakdown (among records that also matched inclusion)\n")
    lines.append("| Category | Count |")
    lines.append("|---|---:|")
    for cat, count in soft_excl_counts.most_common():
        lines.append(f"| `{cat}` | {count:,} |")
    if not soft_excl_counts:
        lines.append("| (none) | 0 |")

    lines.append("\n## Top 30 vendors by V5-based vendor-match count\n")
    lines.append("| Vendor | Count |")
    lines.append("|---|---:|")
    for vendor, count in vendor_counts.most_common(30):
        lines.append(f"| {vendor} | {count:,} |")

    OUT_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {OUT_PATH}")

    ids_path = REPO_ROOT / "data" / "v5_corpus_2024_2026_included_ids.json"
    ids_path.write_text(json.dumps(sorted(included_ids)), encoding="utf-8")
    print(f"Wrote {ids_path} ({len(included_ids):,} ids)")


if __name__ == "__main__":
    main()
