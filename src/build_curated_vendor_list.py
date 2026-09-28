"""Week 3 task (W3.6): prune the data-driven vendor candidate list
(docs/vendor_candidates_v1.md, 553 vendors) into the curated list that gates
corpus_filter's Include B rule (part:o/part:a + curated vendor + model-
designator pattern) on the NVD path, AND corpus_filter_v5's vendor+category
rule on the CVE List V5 path (see that module's docstring).

IMPORTANT -- the stakes of this list are NOT symmetric across the two
paths that consume it, and that asymmetry is why the general-purpose-
software override below exists. On the NVD path, Include A (h_any) and
Include C (o_firmware) already admit a CVE independent of any vendor list
-- they fire on CPE structure alone -- so a vendor left off this list only
loses Include B's narrower supplemental catch there, which is genuinely
low-stakes. On the V5 path there is no CPE-structural fallback: a vendor
on this list is *directly* eligible for inclusion (paired with a
description category-keyword match) with no second structural check. Peer
review (Monika Schrenk, Sep 23 2026) found this had let Microsoft become
the single largest V5-path vendor match (61,660 hits) before the v5 rule
itself was tightened to require vendor+category jointly (see
corpus_filter_v5.py); even after that fix, spot-checking the top general-
purpose vendors' remaining matches (Microsoft 285, IBM 103, Dell 27,
Google 16, Apple 7, all after the fix) found every sampled record was a
false positive -- "Remote Desktop Gateway," "IBM Sterling File Gateway,"
"Dell Secure Connect Gateway," Android/iOS camera-permission and modem
bugs -- enterprise software features and mobile-OS components whose
product names or descriptions happen to contain a category keyword, not
embedded/IoT hardware. So this list's exclusions are NOT symmetric-risk
housekeeping the way they are on the NVD path; excluding a vendor here
measurably protects the V5-path corpus.

This asymmetry is also why the general-purpose-software vendors below are
now on the same manual override list as the silicon/enterprise/ICS
vendors, even though Include A/C coverage for any of their genuine
hardware CVEs (a CPE-tagged Google Nest device, say) is unaffected on the
NVD path.

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
      * general-purpose software/cloud (Appendix B "general-purpose
        computers" -- extended here to these vendors' server/cloud/mobile-OS
        product lines specifically, per the V5-path evidence above):
        Microsoft, IBM, Dell, Google, Apple. Each does also sell genuine
        embedded/IoT hardware in some corner of its catalog (a Google Nest
        thermostat, an Apple AirPort router, a Dell embedded gateway
        appliance), but on the V5 text/vendor path those products were not
        what the vendor-match rule was actually catching -- 100% of the
        sampled post-fix matches (Microsoft, IBM, Dell, Google, Apple) were
        enterprise-software or mobile-OS records. Excluded here rather than
        left in on the theory that a real hit might slip through: false
        positives at this vendor's CVE volume overwhelm the handful of
        genuine hardware CVEs these vendors might contribute either way.
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
# The list lives in scope_denylist.py, which both corpus filters also use.
from scope_denylist import VENDOR_SCOPE_DENYLIST as MANUAL_VENDOR_DENYLIST  # noqa: E402


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
        f"{len(MANUAL_VENDOR_DENYLIST)} vendors identifiable by name as predominantly silicon/chipset, "
        "enterprise/carrier networking, ICS, or general-purpose computing and software, where example products are "
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
