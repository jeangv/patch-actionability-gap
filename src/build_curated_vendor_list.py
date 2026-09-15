"""Week 3 task (W3.6): prune the data-driven vendor candidate list
(docs/vendor_candidates_v1.md, 553 vendors) into the curated list that gates
corpus_filter's Include B rule (part:o/part:a + curated vendor + model-
designator pattern).

This does NOT decide overall corpus membership. Include A (h_any) and
Include C (o_firmware) already admit a CVE independent of any vendor list --
they fire on CPE structure alone. Include B only adds part:o/part:a records
that lack the `_firmware` suffix but do match a hyphenated model-designator
product string (e.g. `dir-825`) for a vendor known to make embedded/IoT
devices. So a vendor left off this list does not lose its CVEs that are
already caught by Include A/C -- it only loses Include B's narrower
supplemental catch. This keeps the stakes of any individual vendor
inclusion/exclusion judgment call low, which is what makes automated,
reproducible pruning defensible here instead of a hand-curated list.

Pruning rule, applied per vendor against its "Example products" column in
vendor_candidates_v1.md (the 5 most frequent product strings for that
vendor):

  - EXCLUDE if every example product matches a soft-exclusion category
    pattern (src/soft_exclusions.py) -- i.e. the vendor's visible product
    mix in this corpus looks entirely enterprise-datacenter/ICS/medical/
    automotive/general-purpose-computer.
  - EXCLUDE (manual override list below) for vendors identifiable by name as
    predominantly out-of-scope under Appendix B's soft-exclusion categories
    (silicon/chipset, enterprise datacenter/carrier networking, or ICS),
    where the example-product strings are bare part/model numbers that
    contain no keyword a text pattern could match (`wcd9380`, `mx2020`,
    `sz-300`) -- the discovery pass already required the CVE *description*
    to mention a router/camera/gateway/NAS keyword (see
    discover_vendor_candidates.py's CATEGORY_PATTERN), so most of the 553
    are long-tail device vendors by construction; this override list is only
    for the handful of large, recognizable vendors whose enterprise/ICS/
    silicon business is large enough to show up here anyway (e.g. a CVE
    description calling a Juniper MX carrier router a "gateway"). Vendor
    identity here is domain knowledge (Georgia Tech OMS Cybersecurity
    coursework + public vendor product-line knowledge), not a text match,
    and is the reason this one part of an otherwise-automated pruning step
    is a maintained list rather than a regex:
      * silicon/chipset (Include B targets device model numbers, not chip
        part numbers -- see note above): Qualcomm, MediaTek, Unisoc,
        Realtek, Intel, Broadcom, Samsung (Exynos).
      * enterprise/carrier networking (Appendix B "enterprise datacenter
        networking and server platforms"): Cisco (ASR/Nexus/Catalyst
        carrier and campus-core lines dominate this vendor's CVE count),
        Juniper, Citrix, Symantec (F5-class ADC/gateway appliances, not
        consumer/SMB devices).
      * ICS (Appendix B "industrial control systems"): Siemens, Schneider
        Electric, ABB, Moxa, Pepperl+Fuchs.
    A vendor NOT on this list keeps its Include-A/C coverage regardless
    (e.g. Bosch and Lenovo also sell enterprise/ICS lines, but their listed
    example products here -- Bosch `cpp7` IP-camera firmware, Lenovo/
    LenovoEMC `storcenter` NAS -- are the in-scope product, so they are left
    on the curated list rather than added to this override).
  - INCLUDE otherwise. This is deliberately permissive: a vendor with a
    mixed enterprise+SMB catalog (e.g. Cisco, D-Link enterprise switches)
    stays in, because Include B still requires the model-designator pattern
    AND per-record soft exclusion still applies on top at classify() time --
    over-inclusion here is caught downstream, not compounded.

Output:
  - docs/curated_vendor_list.md   -- full 553-row decision table + rule text
  - data/curated_vendor_list.json -- {"vendors": [...]} consumed by
    corpus_filter.classify(vendor_list=...)
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from soft_exclusions import classify_soft_exclusions

REPO_ROOT = Path(__file__).resolve().parent.parent
SOURCE_MD = REPO_ROOT / "docs" / "vendor_candidates_v1.md"
OUT_MD = REPO_ROOT / "docs" / "curated_vendor_list.md"
OUT_JSON = REPO_ROOT / "data" / "curated_vendor_list.json"

ROW_RE = re.compile(r"^\|\s*\d+\s*\|")

# Manual override: vendors identifiable by name/business as predominantly
# out-of-scope, where example products are bare part/model numbers no regex
# can categorize. See module docstring for the full rationale per group.
# Excludes from Include B only -- see module docstring.
MANUAL_VENDOR_DENYLIST = {
    # silicon/chipset
    "qualcomm": "silicon/chipset vendor, not a device vendor",
    "mediatek": "silicon/chipset vendor, not a device vendor",
    "unisoc": "silicon/chipset vendor, not a device vendor",
    "realtek": "silicon/chipset vendor, not a device vendor",
    "intel": "silicon/chipset vendor, not a device vendor",
    "broadcom": "silicon/chipset vendor, not a device vendor",
    "samsung": "silicon/chipset vendor (Exynos) dominates this vendor's listed products",
    # enterprise / carrier networking (Appendix B soft exclusion)
    "cisco": "carrier/campus-core networking (ASR/Nexus/Catalyst) dominates this vendor's CVE count",
    "juniper": "carrier/service-provider networking, not consumer/SMB",
    "citrix": "enterprise application delivery controller / gateway appliances",
    "symantec": "enterprise gateway security appliances",
    # ICS (Appendix B soft exclusion)
    "siemens": "industrial control systems",
    "schneider-electric": "industrial control systems",
    "abb": "industrial control systems",
    "moxa": "industrial Ethernet / ICS networking",
    "pepperl-fuchs": "industrial control systems",
}


def parse_rows(md_path: Path) -> list[dict]:
    rows = []
    for line in md_path.read_text(encoding="utf-8").splitlines():
        if ROW_RE.match(line):
            parts = [p.strip() for p in line.strip().strip("|").split("|")]
            rank, vendor, cve_count, distinct_products, examples = parts
            rows.append(
                {
                    "rank": int(rank),
                    "vendor": vendor,
                    "cve_count": int(cve_count),
                    "distinct_products": int(distinct_products),
                    "examples": examples,
                }
            )
    return rows


def decide(row: dict) -> tuple[bool, str]:
    vendor = row["vendor"].lower()
    if vendor in MANUAL_VENDOR_DENYLIST:
        return False, f"manual override: {MANUAL_VENDOR_DENYLIST[vendor]}"

    examples = [e.strip() for e in row["examples"].split(",") if e.strip()]
    if not examples:
        return True, "no example products to test against; default include"

    categorized = [bool(classify_soft_exclusions(e)) for e in examples]
    if categorized and all(categorized):
        matched = classify_soft_exclusions(examples[0])
        cat = matched[0].category if matched else "soft_exclusion"
        return False, f"all sampled example products match a soft-exclusion category ({cat})"

    return True, "default include"


def main() -> None:
    rows = parse_rows(SOURCE_MD)
    included: list[dict] = []
    excluded: list[dict] = []
    for row in rows:
        ok, reason = decide(row)
        row["decision"] = "include" if ok else "exclude"
        row["reason"] = reason
        (included if ok else excluded).append(row)

    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(
        json.dumps(
            {"vendors": sorted(r["vendor"] for r in included)},
            indent=2,
        ),
        encoding="utf-8",
    )

    lines = []
    lines.append("# Curated Vendor List (Week 3, W3.6)\n")
    lines.append(
        f"Pruned from `docs/vendor_candidates_v1.md` (553 data-driven candidates, "
        f"full-corpus discovery pass 2026-09-04). Gates **Include B** only -- see "
        f"module docstring in `src/build_curated_vendor_list.py` for why a vendor "
        f"excluded here does not lose CVEs already caught by Include A (`h_any`) "
        f"or Include C (`o_firmware`).\n"
    )
    lines.append(
        f"**Result:** {len(included)} included / {len(excluded)} excluded of "
        f"{len(rows)} candidate vendors.\n"
    )
    lines.append(
        "**Rule:** exclude if (a) the vendor is on the manual override list -- "
        "16 vendors identifiable by name as predominantly silicon/chipset, "
        "enterprise/carrier networking, or ICS, where example products are "
        "bare part/model numbers no text pattern can categorize (see rationale "
        "in `src/build_curated_vendor_list.py`) -- or (b) every one of the "
        "vendor's top-5 example products (from the discovery pass) matches a "
        "soft-exclusion category pattern (`src/soft_exclusions.py`: enterprise "
        "datacenter/server, ICS, medical, automotive, mobile handset, "
        "general-purpose computer). Include otherwise.\n"
    )
    lines.append(
        "**Machine-checkable:** re-running `python src/build_curated_vendor_list.py` "
        "reproduces this table and `data/curated_vendor_list.json` byte-for-byte "
        "from `docs/vendor_candidates_v1.md` -- no manual edits are made to either "
        "output file.\n"
    )

    lines.append("## Excluded vendors\n")
    lines.append("| Rank | Vendor | CVE count | Reason |")
    lines.append("|---:|---|---:|---|")
    for row in sorted(excluded, key=lambda r: r["rank"]):
        lines.append(f"| {row['rank']} | {row['vendor']} | {row['cve_count']} | {row['reason']} |")

    lines.append("\n## Included vendors (curated list, gates Include B)\n")
    lines.append("| Rank | Vendor | CVE count | Distinct products |")
    lines.append("|---:|---|---:|---:|")
    for row in sorted(included, key=lambda r: r["rank"]):
        lines.append(f"| {row['rank']} | {row['vendor']} | {row['cve_count']} | {row['distinct_products']} |")

    OUT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Included {len(included)}, excluded {len(excluded)} of {len(rows)} vendors")
    print(f"Wrote {OUT_MD}")
    print(f"Wrote {OUT_JSON}")


if __name__ == "__main__":
    main()
