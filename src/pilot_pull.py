"""Pull a 200-record embedded/IoT pilot slice from NVD, stratified across three
disclosure eras, and report schema-field population rates.

v1: uses corpus_filter's corrected inclusion rule (part:h anywhere, plus
part:o firmware-named products -- see corpus_filter.py for why v0's
h+vulnerable-true-only rule was wrong). Outputs go to new v1 paths;
docs/pilot_report.md and data/pilot_<date>/ from the v0 run are left
untouched for a before/after comparison.

Eras (per project design):
  - pre-2024          : before 2024-01-01
  - backlog era       : 2024-01-01 through 2026-02-28
  - triage era        : 2026-03-01 onward (NIST's routine-enrichment cutback)

Corpus membership uses corpus_filter.classify() (see that module's docstring
for which parts of the Appendix B rule are implemented vs. still pending).

Within each era, date-chunked windows (<=120 days, the NVD API's hard cap) are
scanned most-recent-first until the era's quota is met or the era's date
range is exhausted -- whichever comes first. Shortfalls are reported, not
padded.

Outputs:
  - data/pilot_<YYYYMMDD>_v1/<era>.json  (raw NVD CVE records actually included)
  - docs/pilot_report_v1.md              (methodology + population percentages)
"""
from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from corpus_filter import classify, extract_part_matches
from nvd_client import NvdClient, date_windows

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS_PATH = REPO_ROOT / "docs" / "pilot_report_v1.md"

NVD_SOURCE = "nvd@nist.gov"
RULE_TAGS = ("h_any", "h_vulnerable_true", "o_firmware", "include_b_vendor_pattern")


@dataclass(frozen=True)
class Era:
    name: str
    start: datetime
    end: datetime
    quota: int


def build_eras(now: datetime) -> list[Era]:
    return [
        Era("pre-2024", datetime(1999, 1, 1), datetime(2023, 12, 31, 23, 59, 59), 67),
        Era("backlog era (2024-Feb 2026)", datetime(2024, 1, 1), datetime(2026, 2, 28, 23, 59, 59), 67),
        Era("triage era (Mar 2026-)", datetime(2026, 3, 1), now, 66),
    ]


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
    ambiguous_log: list[dict] = []

    for era in eras:
        print(f"=== {era.name}: target {era.quota} records ===", flush=True)
        windows = list(date_windows(era.start, era.end))
        windows.reverse()  # most recent first: IoT/embedded CVEs skew recent
        matched: list[dict] = []
        rule_tag_counts: Counter = Counter()
        scanned = 0
        for w in windows:
            if len(matched) >= era.quota:
                break
            print(
                f"  window {w.start.date()} .. {w.end.date()} "
                f"(have {len(matched)}/{era.quota})",
                flush=True,
            )
            for cve in client.iter_cves(w.as_params()):
                scanned += 1
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
                    for tag in decision.rule_tags:
                        rule_tag_counts[tag] += 1
                    if len(matched) >= era.quota:
                        break
        era_records[era.name] = matched
        era_scanned[era.name] = scanned
        era_rule_tag_counts[era.name] = rule_tag_counts
        print(
            f"  -> {len(matched)}/{era.quota} collected, {scanned} CVEs scanned",
            flush=True,
        )

    # --- persist raw JSON per era ---
    data_dir = REPO_ROOT / "data" / f"pilot_{retrieved_at.strftime('%Y%m%d')}_v1"
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
    lines.append("# Pilot Slice Report v1 (corrected inclusion rule)\n")
    lines.append(
        f"Retrieved: {retrieved_at.isoformat(timespec='seconds')} from the NVD CVE API 2.0.\n"
    )
    lines.append(
        "**v1 vs v0:** the original run (`docs/pilot_report.md`) required `part:h` "
        "marked `vulnerable: true`, a convention NVD stopped using for embedded "
        "devices around 2011. v1 matches `part:h` anywhere in `configurations` "
        "regardless of the `vulnerable` flag (Include A), plus `part:o` CPEs whose "
        "product ends in `_firmware` (Include C). See `src/corpus_filter.py`.\n"
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
        f"`data/pilot_{retrieved_at.strftime('%Y%m%d')}_v1/ambiguous.json`.\n"
    )
    lines.append("## Rule-tag breakdown (before/after comparison)\n")
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
