"""Week 3 task (W3.5): corpus membership determined from CVE List V5 instead
of the NVD API -- the pivot that removes NVD's own enrichment-triage
decisions from the sampling frame (see PR1 Preliminary Finding #2 and
Video 1 slide 7: "A corpus built through the NVD API is selected on NVD's
own triage decisions").

Schema difference that drives this module's design: a CVE List V5 record's
CNA container (`containers.cna`) almost never carries a CPE (`cpeApplicability`
appears on 5/1000 sampled 2024 records, all from CNAs that happen to supply
their own CPE data, e.g. Microsoft -- see PR2 working notes). Confirmed by
direct inspection: no ADP entry with `shortName: "nvd@nist.gov"` was found
anywhere in the 2024-2026 CVE List V5 corpus -- NVD's own enrichment is
*not* republished back into V5. So CVE List V5 corpus membership cannot be
CPE-based the way the NVD-path corpus_filter.py is; it has to run on the
same signal discover_vendor_candidates.py already used to build the curated
vendor list: vendor/product strings plus a category-keyword match against
the English description.

This means the CNA-vs-NVD split (PR1 "Third methodological commitment") is
architecturally forced, not just a scoring convenience: V5 supplies the
CNA-side corpus and CNA-side identifiability signal; the NVD API
(src/nvd_client.py, src/corpus_filter.py) remains the only source for the
enrichment-side (CPE-based) signal. There is no single file that carries
both, so they cannot be scored from one record the way PR1's original design
sketch assumed.

Inclusion rule (V5 path) -- v2, corrected after peer review (Monika
Schrenk, Sep 23 2026) found that v1's rule let general-purpose-software
vendors (Microsoft top V5 vendor-match at 61,660 hits; also Google, Apple,
IBM, Dell on the curated list) flood the corpus, because v1 treated vendor
membership and description-keyword matching as *independent* triggers --
either alone was sufficient. That is looser than the NVD path, where
Include B requires vendor membership AND a model-designator product-name
match together. v2 requires the same kind of combined signal on the V5
path:
  - any `affected[].product` string ends in `_firmware`/`_Firmware` --
    sufficient alone, parity with Include C on the NVD path (rare in V5,
    but a strong single signal when present), OR
  - vendor (from any `affected[].vendor`) is on the curated vendor list
    (data/curated_vendor_list.json, same list Include B uses on the NVD
    path) **AND** the English description matches the category keyword
    pattern (discover_vendor_candidates.CATEGORY_PATTERN: router/access
    point/gateway/IP camera/NAS/etc.) -- neither signal alone is enough,
    exactly like Include B.
  - If a record DOES carry `cpeApplicability` (either in the CNA container
    or an ADP container), it is also run through corpus_filter.classify()'s
    CPE-based rule and included if that matches -- this is a strict OR with
    the text-based rule above, not a replacement for it.

v1's unconditional `CATEGORY_PATTERN.search(desc)` branch (no vendor
constraint at all) is removed in v2 for the same reason: a description
merely containing a word like "gateway" (e.g. an API gateway or payment
gateway product) admitted the record regardless of vendor, which is even
looser than the vendor-match-alone issue Monika found.

Exclusion: same soft-exclusion categories (src/soft_exclusions.py) applied
to the description text, plus `state != "PUBLISHED"` (V5's equivalent of
NVD's Rejected/Disputed -- a REJECTED CVE's own record replaces its
containers with a rejection notice).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from corpus_filter import FIRMWARE_SUFFIX_RE, classify as classify_nvd, load_default_vendor_list
from discover_vendor_candidates import CATEGORY_PATTERN
from soft_exclusions import classify_soft_exclusions


@dataclass
class V5Decision:
    cve_id: str
    included: bool
    include_reasons: list = field(default_factory=list)
    exclude_reasons: list = field(default_factory=list)
    ambiguous: bool = False
    soft_exclusion_tags: set = field(default_factory=set)
    had_cpe_applicability: bool = False


def _all_descriptions_text(record: dict) -> str:
    parts = []
    cna = record.get("containers", {}).get("cna", {})
    for d in cna.get("descriptions", []):
        if d.get("lang", "").startswith("en"):
            parts.append(d.get("value", ""))
    for a in record.get("containers", {}).get("adp", []):
        for d in a.get("descriptions", []):
            if d.get("lang", "").startswith("en"):
                parts.append(d.get("value", ""))
    return " ".join(parts)


def _affected_vendor_products(record: dict) -> list[tuple[str, str]]:
    out = []
    cna = record.get("containers", {}).get("cna", {})
    for a in cna.get("affected", []):
        vendor = (a.get("vendor") or "").strip()
        product = (a.get("product") or "").strip()
        if vendor or product:
            out.append((vendor, product))
    return out


def _find_cpe_applicability_node(record: dict) -> list[dict]:
    """Return any cpeApplicability blocks found in the CNA or ADP containers
    (rare -- see module docstring). Empty list is the common case."""
    blocks = []
    cna = record.get("containers", {}).get("cna", {})
    if "cpeApplicability" in cna:
        blocks.append(cna)
    for a in record.get("containers", {}).get("adp", []):
        if "cpeApplicability" in a:
            blocks.append(a)
    return blocks


def _as_nvd_shaped(record: dict, cpe_container: dict) -> dict:
    """Wrap a V5 cpeApplicability block into the minimal shape
    corpus_filter.classify() expects (configurations/cpeMatch), so the CPE
    path can be reused verbatim rather than duplicated."""
    return {
        "id": record.get("cveMetadata", {}).get("cveId", ""),
        "vulnStatus": "Analyzed",  # V5 published records are equivalent to NVD "Analyzed" for this purpose
        "descriptions": [{"lang": "en", "value": _all_descriptions_text(record)}],
        "configurations": cpe_container["cpeApplicability"],
    }


def classify(record: dict, vendor_list=None) -> V5Decision:
    cve_id = record.get("cveMetadata", {}).get("cveId", "")
    state = record.get("cveMetadata", {}).get("state", "")

    if vendor_list is None:
        vendor_list = load_default_vendor_list()

    include_reasons: list[str] = []
    had_cpe = False

    # Text/vendor path (the common case -- see module docstring).
    # v2: vendor membership and category-keyword match must both be present
    # together (mirrors Include B on the NVD path) -- neither is sufficient
    # alone. See module docstring "Inclusion rule (V5 path) -- v2" for why.
    desc = _all_descriptions_text(record)
    desc_matches_category = bool(CATEGORY_PATTERN.search(desc))
    for vendor, product in _affected_vendor_products(record):
        if FIRMWARE_SUFFIX_RE.search(product):
            include_reasons.append(f"v5_firmware_suffix: {vendor}:{product}")
        elif vendor.lower() in vendor_list and desc_matches_category:
            include_reasons.append(f"v5_vendor_and_category: {vendor}:{product}")

    # CPE path (rare -- only fires when a CNA or ADP happened to supply CPE).
    for cpe_container in _find_cpe_applicability_node(record):
        had_cpe = True
        nvd_shaped = _as_nvd_shaped(record, cpe_container)
        nvd_decision = classify_nvd(nvd_shaped, vendor_list=vendor_list)
        if nvd_decision.included:
            include_reasons.append(
                f"v5_cpe_applicability: {'; '.join(nvd_decision.include_reasons)}"
            )

    exclude_reasons: list[str] = []
    if state != "PUBLISHED":
        exclude_reasons.append(f"cveMetadata.state={state!r} (not PUBLISHED)")

    soft_matches = classify_soft_exclusions(desc)
    soft_exclusion_tags = {m.category for m in soft_matches}
    for m in soft_matches:
        exclude_reasons.append(f"{m.category}: matched {m.matched_text!r}")

    ambiguous = bool(include_reasons) and bool(exclude_reasons)
    included = bool(include_reasons) and not exclude_reasons

    return V5Decision(
        cve_id=cve_id,
        included=included,
        include_reasons=include_reasons,
        exclude_reasons=exclude_reasons,
        ambiguous=ambiguous,
        soft_exclusion_tags=soft_exclusion_tags,
        had_cpe_applicability=had_cpe,
    )
