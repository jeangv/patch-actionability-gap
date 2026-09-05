"""Pull a 200-record embedded/IoT pilot slice from NVD, stratified across three
disclosure eras, and report schema-field population rates.

v2: fixes v1's sampling bias. v1 scanned each era's 120-day windows
most-recent-first and stopped as soon as the quota was met, which meant
every era's "collected" sample was clustered into a single narrow date
range rather than spread across the era (measured with src/date_span.py:
v1's pre-2024 sample spanned only 2023-10-06..2023-10-11, backlog only
2025-12-15..2025-12-22, triage only 2026-06-29..2026-07-14). v2 instead
distributes each era's quota across its 120-day API windows and samples
every window, so the collected records are spread across the era's full
date range:
  - backlog era & triage era: quota distributed proportionally (by window
    length in days) across every 120-day window in the era.
  - pre-2024: spans 25 calendar years (1999-2023) as ~76 full 120-day
    windows -- scanning all of them is impractical for a pilot slice, so
    one representative 120-day window per calendar year is sampled instead
    (Jan 1 .. Jan 1 + 119 days of that year), with an EQUAL quota share per
    year (not proportional to day count). This is a documented sampling
    compromise, not full-year-uniform coverage -- see the "Sampling method"
    section of the generated report.
Windows that can't fill their allocated share are reported as per-window
shortfalls, not padded from elsewhere.

v1's outputs (docs/pilot_report_v1.md, data/pilot_<date>_v1/) and v0's
outputs (docs/pilot_report.md, data/pilot_<date>/) are left untouched.

IMPORTANT SELECTION-EFFECT LIMITATION (also stated in the generated report):
every collected record has `configurations` present by construction (the
inclusion rule requires a CPE match). Since 2026-04-15 NIST only routinely
enriches CISA KEV / federal-government / EO 14028 software with
`configurations` data. So the triage-era stratum is selected by NVD's
enrichment priority list, not by device type -- this is almost certainly
why triage-era field-population percentages beat backlog-era on every
metric. That comparison is a selection artifact, not a finding about
triage-era CVE quality, and must not be reported as one.

Eras (per project design):
  - pre-2024          : before 2024-01-01
  - backlog era       : 2024-01-01 through 2026-02-28
  - triage era        : 2026-03-01 onward (NIST's routine-enrichment cutback)

Corpus membership uses corpus_filter.classify() (see that module's docstring
for which parts of the Appendix B rule are implemented vs. still pending).

Outputs:
  - data/pilot_<YYYYMMDD>_v2/<era>.json  (raw NVD CVE records actually included)
  - docs/pilot_report_v2.md              (methodology + population percentages)
"""
from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from corpus_filter import classify, extract_part_matches
from date_span import date_span_stats
from nvd_client import DateWindow, MAX_DATE_WINDOW_DAYS, NvdClient, date_windows

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS_PATH = REPO_ROOT / "docs" / "pilot_report_v2.md"

NVD_SOURCE = "nvd@nist.gov"
RULE_TAGS = ("h_any", "h_vulnerable_true", "o_firmware", "include_b_vendor_pattern")
PRE_2024_ERA_NAME = "pre-2024"


@dataclass(frozen=True)
class Era:
    name: str
    start: datetime
    end: datetime
    quota: int


def build_eras(now: datetime) -> list[Era]:
    return [
        Era(PRE_2024_ERA_NAME, datetime(1999, 1, 1), datetime(2023, 12, 31, 23, 59, 59), 67),
        Era("backlog era (2024-Feb 2026)", datetime(2024, 1, 1), datetime(2026, 2, 28, 23, 59, 59), 67),
        Era("triage era (Mar 2026-)", datetime(2026, 3, 1), now, 66),
    ]


# ---- v2 window-distributed sampling ---------------------------------------

def build_windows_for_era(era: Era) -> list[DateWindow]:
    """Return the 120-day windows to sample for this era.

    pre-2024 spans 25 calendar years as ~76 full windows; scanning all of
    them is impractical for a pilot slice, so one representative window per
    calendar year is sampled instead (see module docstring). Other eras use
    every window in their (much shorter) date range.
    """
    if era.name == PRE_2024_ERA_NAME:
        windows = []
        for year in range(era.start.year, era.end.year + 1):
            year_start = max(datetime(year, 1, 1), era.start)
            window_end = min(year_start + timedelta(days=MAX_DATE_WINDOW_DAYS - 1), era.end)
            windows.append(DateWindow(year_start, window_end))
        return windows
    return list(date_windows(era.start, era.end))


def window_weights(era: Era, windows: list[DateWindow]) -> list[float]:
    """pre-2024: equal share per sampled year. Other eras: proportional to
    window length in days, since the final window in a range is often
    shorter than the 120-day cap."""
    if era.name == PRE_2024_ERA_NAME:
        return [1.0] * len(windows)
    return [float((w.end - w.start).days + 1) for w in windows]


def allocate_quota(quota: int, weights: list[float]) -> list[int]:
    """Largest-remainder allocation of an integer quota across weighted buckets."""
    if not weights:
        return []
    total_weight = sum(weights) or 1.0
    raw = [quota * w / total_weight for w in weights]
    base = [int(x) for x in raw]
    remainder = quota - sum(base)
    order = sorted(range(len(raw)), key=lambda i: raw[i] - base[i], reverse=True)
    for i in order[:remainder]:
        base[i] += 1
    return base


# ---- field-population checks (the 7 report metrics) -----------------------

def has_configurations(cve: dict) -> bool:
    return bool(cve.get("configurations"))


def _cpe_match_entries(cve: dict):
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for m in node.get("cpeMatch", []):
                yield m


def has_version_end(cve: dict) -> bool:
    return any(
        m.get("versionEndExcluding") or m.get("versionEndIncluding")
        for m in _cpe_match_entries(cve)
    )


def has_version_start(cve: dict) -> bool:
    return any(
        m.get("versionStartExcluding") or m.get("versionStartIncluding")
        for m in _cpe_match_entries(cve)
    )


def has_part_h(cve: dict) -> bool:
    return bool(extract_part_matches(cve, "h"))


def has_references(cve: dict) -> bool:
    return bool(cve.get("references"))


def has_patch_or_advisory_tag(cve: dict) -> bool:
    for ref in cve.get("references", []):
        tags = ref.get("tags", []) or []
        if "Patch" in tags or "Vendor Advisory" in tags:
            return True
    return False


def cvss_sources(cve: dict) -> tuple[bool, bool]:
    """Return (cna_supplied_present, nvd_added_present)."""
    cna = False
    nvd = False
    metrics = cve.get("metrics", {})
    for entries in metrics.values():
        for entry in entries:
            source = (entry.get("source") or "").strip().lower()
            if source == NVD_SOURCE:
                nvd = True
            elif source:
                cna = True
    return cna, nvd


METRICS = [
    ("cpeMatch/configurations present", has_configurations),
    ("versionEndExcluding/Including present", has_version_end),
    ("versionStartExcluding/Including present", has_version_start),
    ("CPE part:h present", has_part_h),
    ("references non-empty", has_references),
    ("Patch/Vendor Advisory reference tag present", has_patch_or_advisory_tag),
]


def percentages(records: list[dict]) -> dict:
    n = len(records)
    out = {}
    if n == 0:
        for label, _ in METRICS:
            out[label] = None
        out["CVSS: CNA-supplied present"] = None
        out["CVSS: NVD-added present"] = None
        return out
    for label, fn in METRICS:
        out[label] = 100.0 * sum(1 for r in records if fn(r)) / n
    cna_count = sum(1 for r in records if cvss_sources(r)[0])
    nvd_count = sum(1 for r in records if cvss_sources(r)[1])
    out["CVSS: CNA-supplied present"] = 100.0 * cna_count / n
    out["CVSS: NVD-added present"] = 100.0 * nvd_count / n
    return out


def fmt_pct(v) -> str:
    return "n/a (0 records)" if v is None else f"{v:.1f}%"


def main() -> None:
    client = NvdClient()
    retrieved_at = datetime.now(timezone.utc)
    eras = build_eras(retrieved_at.replace(tzinfo=None))

    era_records: dict[str, list[dict]] = {}
    era_scanned: dict[str, int] = {}
    era_rule_tag_counts: dict[str, Counter] = {}
    era_window_reports: dict[str, list[dict]] = {}
    ambiguous_log: list[dict] = []

    for era in eras:
        windows = build_windows_for_era(era)
        weights = window_weights(era, windows)
        window_quotas = allocate_quota(era.quota, weights)
        print(
            f"=== {era.name}: target {era.quota} records across "
            f"{len(windows)} sampled window(s) ===",
            flush=True,
        )

        matched: list[dict] = []
        rule_tag_counts: Counter = Counter()
        scanned = 0
        window_reports: list[dict] = []

        for w, w_quota in zip(windows, window_quotas):
            if w_quota == 0:
                continue
            w_matched = 0
            w_scanned = 0
            print(f"  window {w.start.date()} .. {w.end.date()} (target {w_quota})", flush=True)
            for cve in client.iter_cves(w.as_params()):
                scanned += 1
                w_scanned += 1
                decision = classify(cve)
                if decision.ambiguous:
                    ambiguous_log.append(
                        {
                            "id": decision.cve_id,
                            "include_reasons": decision.include_reasons,
                            "exclude_reasons": decision.exclude_reasons,
                        }
                    )
                if decision.included:
                    matched.append(cve)
                    w_matched += 1
                    for tag in decision.rule_tags:
                        rule_tag_counts[tag] += 1
                    if w_matched >= w_quota:
                        break
            window_reports.append(
                {
                    "start": w.start,
                    "end": w.end,
                    "target": w_quota,
                    "collected": w_matched,
                    "scanned": w_scanned,
                }
            )
            if w_matched < w_quota:
                print(
                    f"    shortfall: {w_matched}/{w_quota} collected, "
                    f"window exhausted ({w_scanned} scanned)",
                    flush=True,
                )

        era_records[era.name] = matched
        era_scanned[era.name] = scanned
        era_rule_tag_counts[era.name] = rule_tag_counts
        era_window_reports[era.name] = window_reports
        print(
            f"  -> {len(matched)}/{era.quota} collected, {scanned} CVEs scanned "
            f"across {len(windows)} windows",
            flush=True,
        )

    # --- persist raw JSON per era ---
    data_dir = REPO_ROOT / "data" / f"pilot_{retrieved_at.strftime('%Y%m%d')}_v2"
    data_dir.mkdir(parents=True, exist_ok=True)
    for era in eras:
        out_path = data_dir / f"{era.name.split(' ')[0].replace('/', '-')}.json"
        out_path.write_text(
            json.dumps(era_records[era.name], indent=2), encoding="utf-8"
        )
        print(f"Wrote {out_path} ({len(era_records[era.name])} records)")

    ambiguity_path = data_dir / "ambiguous.json"
    ambiguity_path.write_text(json.dumps(ambiguous_log, indent=2), encoding="utf-8")

    overall_rule_tag_counts: Counter = Counter()
    for c in era_rule_tag_counts.values():
        overall_rule_tag_counts.update(c)

    # --- report ---
    all_records = [r for era in eras for r in era_records[era.name]]
    overall_pct = percentages(all_records)

    lines = []
    lines.append("# Pilot Slice Report v2 (window-distributed sampling)\n")
    lines.append(
        f"Retrieved: {retrieved_at.isoformat(timespec='seconds')} from the NVD CVE API 2.0.\n"
    )
    lines.append(
        "## \u26a0 Selection-effect limitation (read before interpreting per-era percentages)\n"
    )
    lines.append(
        "Every record in this report has `configurations` present **by construction** "
        "-- the corpus inclusion rule (`corpus_filter.classify()`) requires a CPE match, "
        "which lives inside `configurations`. Since 2026-04-15 NIST has only routinely "
        "enriched CVEs on the CISA KEV list, federal-government software, and EO 14028 "
        "critical software with `configurations` data (NVD's stated triage-era policy). "
        "**The triage-era stratum here is therefore selected by NVD's enrichment "
        "priority list, not by device type.** This is almost certainly why triage-era "
        "field-population percentages beat backlog-era percentages on every metric below "
        "-- it is a selection artifact of the sampling method, not a finding about "
        "triage-era CVE quality or about vendors being more forthcoming post-triage. "
        "**Do not report \"triage era looks better than backlog era\" as a substantive "
        "result.**\n"
    )
    lines.append(
        "**v2 vs v1 sampling fix:** v1 scanned each era's date windows most-recent-first "
        "and stopped once the quota was met, which clustered every era's sample into a "
        "single narrow date range instead of spreading it across the era (measured with "
        "`src/date_span.py` against the v1 data: pre-2024 spanned only "
        "2023-10-06..2023-10-11, backlog only 2025-12-15..2025-12-22, triage only "
        "2026-06-29..2026-07-14 -- see `docs/pilot_report_v1.md`). v2 fixes this by "
        "distributing each era's quota across its sampled 120-day windows and drawing "
        "from every window -- see \"Sampling method\" below.\n"
    )
    lines.append(
        "**v1 vs v0 rule fix (unchanged in v2):** v0 required `part:h` marked "
        "`vulnerable: true`, a convention NVD stopped using for embedded devices around "
        "2011. v1/v2 match `part:h` anywhere regardless of the `vulnerable` flag "
        "(Include A), plus `part:o` CPEs whose product ends in `_firmware` (Include C). "
        "See `src/corpus_filter.py`.\n"
    )
    lines.append(
        "**Still not applied:** Include B (part:o/part:a + curated vendor + "
        "model-designator pattern) -- no curated vendor list yet. Soft exclusion "
        "categories (enterprise datacenter networking/server platforms, ICS, "
        "medical devices, automotive, mobile handsets, general-purpose computers) "
        "-- explicitly deferred to Week 4 by the project owner, not a blocker. "
        "Numbers below may still include some of those categories.\n"
    )
    lines.append(
        f"**Ambiguity list** (matched both an inclusion and the implemented "
        f"exclusion criteria, resolved as excluded per the tiebreaker rule): "
        f"{len(ambiguous_log)} record(s). Full list: "
        f"`data/pilot_{retrieved_at.strftime('%Y%m%d')}_v2/ambiguous.json`.\n"
    )

    lines.append("## Sampling method\n")
    lines.append(
        "- **backlog era & triage era:** every 120-day window in the era's date range "
        "is sampled; the era's quota is distributed across windows proportionally to "
        "window length in days (largest-remainder allocation), then each window is "
        "scanned for its own allocated share.\n"
        "- **pre-2024:** spans 25 calendar years (1999-2023) as ~76 full 120-day "
        "windows -- scanning all of them was judged impractical for a pilot slice. "
        "Instead, one representative 120-day window per calendar year is sampled "
        "(Jan 1 through Jan 1 + 119 days of that year), and the quota is split into an "
        "**equal** share per year (not proportional to day count, since every sampled "
        "window is the same length). This means pre-2024 coverage is Jan-Apr-biased "
        "within each year, not full-year-uniform -- a documented compromise, not a "
        "claim of uniform annual coverage.\n"
        "- A window that can't fill its allocated share is a per-window shortfall, "
        "reported below, not padded from another window.\n"
    )
    lines.append("### Sampling windows, per era\n")
    for era in eras:
        lines.append(f"\n**{era.name}**\n")
        lines.append("| Window | Target | Collected | Scanned |")
        lines.append("|---|---:|---:|---:|")
        for wr in era_window_reports[era.name]:
            lines.append(
                f"| {wr['start'].date()} .. {wr['end'].date()} | {wr['target']} | "
                f"{wr['collected']} | {wr['scanned']} |"
            )

    lines.append("\n## Date span, per era (post-fix check)\n")
    lines.append("| Era | n | Min published | Max published | Distinct months |")
    lines.append("|---|---:|---|---|---:|")
    for era in eras:
        stats = date_span_stats(era_records[era.name])
        if stats["count"]:
            lines.append(
                f"| {era.name} | {stats['count']} | {stats['min_published'].date()} | "
                f"{stats['max_published'].date()} | {stats['distinct_months']} |"
            )
        else:
            lines.append(f"| {era.name} | 0 | n/a | n/a | 0 |")

    lines.append("\n## Rule-tag breakdown (before/after comparison)\n")
    lines.append(
        "A CVE can match more than one tag; counts are of collected (included) "
        "records only and do not need to sum to the totals above.\n"
    )
    lines.append("| Rule tag | pre-2024 | backlog era | triage era | Overall |")
    lines.append("|---|---:|---:|---:|---:|")
    for tag in RULE_TAGS:
        row = [str(era_rule_tag_counts[era.name].get(tag, 0)) for era in eras]
        row.append(str(overall_rule_tag_counts.get(tag, 0)))
        lines.append(f"| `{tag}` | " + " | ".join(row) + " |")

    lines.append("\n## Target vs. achieved, per era\n")
    lines.append("| Era | Target | Collected | CVEs scanned to find them |")
    lines.append("|---|---:|---:|---:|")
    for era in eras:
        lines.append(
            f"| {era.name} | {era.quota} | {len(era_records[era.name])} | {era_scanned[era.name]} |"
        )
    total_target = sum(e.quota for e in eras)
    total_collected = len(all_records)
    lines.append(f"| **Total** | **{total_target}** | **{total_collected}** | |")
    if total_collected < total_target:
        lines.append(
            f"\n**Shortfall:** collected {total_collected}/{total_target}. This "
            f"is reported as-is, not padded.\n"
        )

    lines.append("\n## Field population -- overall\n")
    lines.append("| Field | % of collected records |")
    lines.append("|---|---:|")
    for label, val in overall_pct.items():
        lines.append(f"| {label} | {fmt_pct(val)} |")

    lines.append("\n## Field population -- by era\n")
    for era in eras:
        pct = percentages(era_records[era.name])
        lines.append(f"\n### {era.name} (n={len(era_records[era.name])})\n")
        lines.append("| Field | % |")
        lines.append("|---|---:|")
        for label, val in pct.items():
            lines.append(f"| {label} | {fmt_pct(val)} |")

    DOCS_PATH.parent.mkdir(parents=True, exist_ok=True)
    DOCS_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\nWrote {DOCS_PATH}")


if __name__ == "__main__":
    main()
