"""Discover candidate embedded/IoT vendors from NVD, data-driven (no hand-picked list).

Crawls the full NVD CVE corpus, keeps CVEs that both:
  (a) have an NVD `configurations` entry with a vulnerable `part:h` CPE, and
  (b) have an English description mentioning a consumer/small-business network
      equipment, broadband gateway, IP camera, or NAS category term,
then ranks vendors (from the part:h CPE `criteria` string) by CVE count.

Output: docs/vendor_candidates.md -- a candidate list for manual pruning.
This is a discovery aid, not the final curated vendor list.
"""
from __future__ import annotations

import re
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from nvd_client import NvdClient

REPO_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_PATH = REPO_ROOT / "docs" / "vendor_candidates.md"

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


def extract_hardware_matches(cve: dict) -> list[tuple[str, str]]:
    """Return (vendor, product) pairs from vulnerable part:h CPE criteria."""
    matches = []
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if not m.get("vulnerable", True):
                    continue
                criteria = m.get("criteria", "")
                parts = criteria.split(":")
                if len(parts) > 4 and parts[2] == "h":
                    matches.append((parts[3], parts[4]))
    return matches


def main() -> None:
    client = NvdClient()
    vendor_cve_ids: dict[str, set] = defaultdict(set)
    vendor_products: dict[str, Counter] = defaultdict(Counter)

    total_scanned = 0
    total_with_hw_cpe = 0
    total_matched = 0
    started_at = time.monotonic()
    retrieved_at = datetime.now(timezone.utc)

    print("Starting full NVD CVE corpus crawl (this covers all publication dates)...")
    for cve in client.iter_cves():
        total_scanned += 1
        hw_matches = extract_hardware_matches(cve)
        if hw_matches:
            total_with_hw_cpe += 1
            desc = get_english_description(cve)
            if CATEGORY_PATTERN.search(desc):
                total_matched += 1
                cve_id = cve.get("id", "")
                for vendor, product in hw_matches:
                    vendor_cve_ids[vendor].add(cve_id)
                    vendor_products[vendor][product] += 1

        if total_scanned % PROGRESS_EVERY == 0:
            elapsed = time.monotonic() - started_at
            print(
                f"  scanned {total_scanned:,} CVEs | part:h hits {total_with_hw_cpe:,} | "
                f"category matches {total_matched:,} | elapsed {elapsed:,.0f}s",
                flush=True,
            )

    elapsed_total = time.monotonic() - started_at
    print(
        f"Done. Scanned {total_scanned:,} CVEs in {elapsed_total:,.0f}s; "
        f"{total_with_hw_cpe:,} had a vulnerable part:h CPE; "
        f"{total_matched:,} also matched a category keyword; "
        f"{len(vendor_cve_ids):,} distinct vendors found.",
        flush=True,
    )

    ranked = sorted(vendor_cve_ids.items(), key=lambda kv: len(kv[1]), reverse=True)

    lines = []
    lines.append("# Embedded/IoT Vendor Candidates (data-driven discovery)\n")
    lines.append(
        f"Retrieved: {retrieved_at.isoformat(timespec='seconds')} "
        f"from NVD CVE API 2.0 (full corpus, no date filter).\n"
    )
    lines.append(
        "**Method:** a CVE is counted if NVD's `configurations` contain at least one "
        "CPE `criteria` string with `part:h` marked `vulnerable: true`, AND the CVE's "
        "English description matches a category keyword restricting scope to consumer/"
        "small-business network equipment, broadband gateways, IP cameras, or NAS. "
        "Vendor names are taken verbatim from the CPE `criteria` vendor field "
        "(not normalized/deduplicated across spelling variants).\n"
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
    )
    lines.append(
        f"**Corpus:** {total_scanned:,} CVEs scanned; {total_with_hw_cpe:,} had a "
        f"vulnerable part:h CPE; {total_matched:,} matched the category filter; "
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
