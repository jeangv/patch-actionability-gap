"""Discover candidate embedded/IoT vendors from NVD, data-driven (no hand-picked list).

v1: fixes the v0 bug of requiring `part:h` + `vulnerable: true` (NVD stopped
typing embedded devices that way around 2011 -- see corpus_filter.py). Now
uses corpus_filter.find_inclusion_matches(): part:h anywhere (any vulnerable
state) OR part:o with a `_firmware`-suffixed product. Output goes to
docs/vendor_candidates_v1.md; the original (buggy) docs/vendor_candidates.md
is left untouched for a before/after comparison.

Crawls the full NVD CVE corpus, keeps CVEs that both:
  (a) match corpus_filter's inclusion rule, and
  (b) have an English description mentioning a consumer/small-business network
      equipment, broadband gateway, IP camera, or NAS category term,
then ranks vendors by CVE count.

Output: docs/vendor_candidates_v1.md -- a candidate list for manual pruning.
This is a discovery aid, not the final curated vendor list.
"""
from __future__ import annotations

import re
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from corpus_filter import find_inclusion_matches
from nvd_client import NvdClient

REPO_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_PATH = REPO_ROOT / "docs" / "vendor_candidates_v1.md"

# Category scope per project instructions: consumer/small-business network
# equipment, broadband gateways, IP cameras, NAS. Matched against the CVE's
# English description text (CPE product fields are usually model numbers,
# e.g. "r7000", and rarely contain these words).
CATEGORY_PATTERN = re.compile(
    r"\b("
    r"router|access point|wireless extender|wi-?fi extender|range extender|repeater|"
    r"network switch|modem|gateway|broadband router|"
    r"ip camera|network camera|surveillance camera|webcam|camera|dvr|nvr|"
    r"nas|network[- ]attached storage|network storage"
    r")\b",
    re.IGNORECASE,
)

PROGRESS_EVERY = 20_000


def get_english_description(cve: dict) -> str:
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def main() -> None:
    client = NvdClient()
    vendor_cve_ids: dict[str, set] = defaultdict(set)
    vendor_products: dict[str, Counter] = defaultdict(Counter)

    total_scanned = 0
    total_with_inclusion_match = 0
    total_matched = 0
    rule_tag_totals: Counter = Counter()  # CVE counts per rule tag (overlapping)
    started_at = time.monotonic()
    retrieved_at = datetime.now(timezone.utc)

    print("Starting full NVD CVE corpus crawl (this covers all publication dates)...")
    for cve in client.iter_cves():
        total_scanned += 1
        rule_matches = find_inclusion_matches(cve)
        if rule_matches:
            total_with_inclusion_match += 1
            rule_tags = {m.rule for m in rule_matches}
            for tag in rule_tags:
                rule_tag_totals[tag] += 1
            desc = get_english_description(cve)
            if CATEGORY_PATTERN.search(desc):
                total_matched += 1
                cve_id = cve.get("id", "")
                for m in rule_matches:
                    vendor_cve_ids[m.vendor].add(cve_id)
                    vendor_products[m.vendor][m.product] += 1

        if total_scanned % PROGRESS_EVERY == 0:
            elapsed = time.monotonic() - started_at
            print(
                f"  scanned {total_scanned:,} CVEs | inclusion hits {total_with_inclusion_match:,} | "
                f"category matches {total_matched:,} | elapsed {elapsed:,.0f}s",
                flush=True,
            )

    elapsed_total = time.monotonic() - started_at
    print(
        f"Done. Scanned {total_scanned:,} CVEs in {elapsed_total:,.0f}s; "
        f"{total_with_inclusion_match:,} matched the inclusion rule; "
        f"{total_matched:,} also matched a category keyword; "
        f"{len(vendor_cve_ids):,} distinct vendors found.",
        flush=True,
    )

    ranked = sorted(vendor_cve_ids.items(), key=lambda kv: len(kv[1]), reverse=True)

    lines = []
    lines.append("# Embedded/IoT Vendor Candidates v1 (data-driven discovery, corrected inclusion rule)\n")
    lines.append(
        f"Retrieved: {retrieved_at.isoformat(timespec='seconds')} "
        f"from NVD CVE API 2.0 (full corpus, no date filter).\n"
    )
    lines.append(
        "**v1 vs v0:** v0 (`docs/vendor_candidates.md`) required `part:h` marked "
        "`vulnerable: true`, which excludes nearly every embedded CVE published "
        "after ~2011 (NVD moved to an AND-node pair: firmware as `part:o` "
        "`..._firmware` marked vulnerable, hardware as `part:h` marked "
        "`vulnerable: false` as the running-on target). v1 matches `part:h` "
        "regardless of the `vulnerable` flag, plus `part:o` products ending in "
        "`_firmware`. See `src/corpus_filter.py` for the rule.\n"
    )
    lines.append(
        "**Rule-tag breakdown across the full corpus** (a CVE can match more than "
        "one tag, so these do not sum to the inclusion-hit total):\n\n"
        f"| Rule tag | CVE count |\n|---|---:|\n"
        f"| `h_any` (v1 Include A) | {rule_tag_totals.get('h_any', 0):,} |\n"
        f"| `h_vulnerable_true` (old v0 rule, subset of h_any) | {rule_tag_totals.get('h_vulnerable_true', 0):,} |\n"
        f"| `o_firmware` (v1 Include C) | {rule_tag_totals.get('o_firmware', 0):,} |\n"
    )
    lines.append(
        "**Method:** a CVE is counted if it matches corpus_filter's inclusion rule "
        "(v1), AND its English description matches a category keyword restricting "
        "scope to consumer/small-business network equipment, broadband gateways, IP "
        "cameras, or NAS. Vendor names are taken verbatim from the CPE `criteria` "
        "vendor field (not normalized/deduplicated across spelling variants). Include "
        "B (curated vendor + model-designator pattern) is not applied here -- no "
        "curated vendor list yet.\n"
    )
    lines.append(
        "**This is a candidate list for manual pruning, not the final curated vendor "
        "list.** Known limitations:\n"
        "- Vendor spelling variants are not merged (e.g. `tp-link` vs `tplink` would "
        "appear as separate rows if both occur).\n"
        "- Description-keyword category matching is a heuristic and can miss or "
        "miscategorize records.\n"
        "- Since April 15, 2026 NIST limits routine NVD enrichment (and therefore "
        "`configurations` population) to CISA KEV / federal-government / EO 14028 "
        "software. Triage-era (post-2026-03-01) CVEs are structurally under-"
        "represented here regardless of vendor — this list skews toward vendors with "
        "a long pre-2026 history and should not be read as current market share.\n"
        "- Soft exclusion categories (enterprise/ICS/medical/automotive/mobile/"
        "general-purpose computer) are deferred to Week 4 -- entries like enterprise "
        "gateway appliances may still appear here.\n"
    )
    lines.append(
        f"**Corpus:** {total_scanned:,} CVEs scanned; {total_with_inclusion_match:,} "
        f"matched the inclusion rule; {total_matched:,} matched the category filter; "
        f"{len(ranked):,} distinct vendors.\n"
    )
    lines.append("| Rank | Vendor (CPE field, verbatim) | CVE count | Distinct products | Example products |")
    lines.append("|---:|---|---:|---:|---|")
    for rank, (vendor, cve_ids) in enumerate(ranked, start=1):
        products = vendor_products[vendor]
        examples = ", ".join(p for p, _ in products.most_common(5))
        lines.append(
            f"| {rank} | {vendor} | {len(cve_ids)} | {len(products)} | {examples} |"
        )

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {OUTPUT_PATH}")


if __name__ == "__main__":
    sys.exit(main())
