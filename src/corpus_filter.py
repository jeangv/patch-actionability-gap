"""Appendix B embedded/IoT corpus inclusion/exclusion rule -- v1.

v1 fixes a bug in v0: NVD stopped typing embedded devices as a single
`part:h` CPE marked `vulnerable: true` around 2011. The current convention
is an AND-node pair -- firmware as `cpe:2.3:o:vendor:product_firmware:version`
marked `vulnerable: true`, and hardware as `cpe:2.3:h:vendor:product:-`
marked `vulnerable: false` as the "runs on" target. Requiring h + vulnerable
excluded nearly every modern embedded CVE by construction.

Implemented in v1:

  - Include A ("h_any"): any CVE with a `part:h` CPE anywhere in
    `configurations`, regardless of the `vulnerable` flag. The subset that
    would have matched the old, overly strict v0 rule is separately tagged
    "h_vulnerable_true" for before/after comparison.
  - Include C ("o_firmware"): any CVE with a `part:o` CPE whose product
    string ends in `_firmware` or contains `_firmware_`.
  - Hard exclude: CVE record state is Rejected or Disputed (NVD `vulnStatus`,
    or the traditional `** REJECT **` / `** DISPUTED **` description markers
    used for older records).
  - Tiebreaker: a record matching both an inclusion and an exclusion
    criterion resolves in favor of exclusion, and is logged as ambiguous.

Appendix B device-firmware naming pattern, v0 (first definition supplied
2026-09-04): a product string qualifies as device firmware if it ends in
`_firmware`, OR if the vendor is on the curated list AND the product matches
a model-designator pattern (hyphenated alphanumeric, e.g. `dir-825`,
`tl-wr841n`, `rt-n56u`). The `_firmware` clause is covered by Include C
above; the vendor+model-designator clause is Include B below.

NOT YET IMPLEMENTED (pending inputs that haven't been provided):
  - Include B ("include_b_vendor_pattern"): part:o/part:a CVEs where the
    vendor is on the curated list AND the product matches the model-
    designator pattern. Needs the pruned curated vendor list -- pass
    `vendor_list` in once available; until then this branch is skipped and
    logged as pending, never silently applied against a guessed vendor list.
  - Soft exclusion categories (enterprise datacenter networking/server
    platforms, ICS, medical devices, automotive, mobile handsets,
    general-purpose computers). Explicitly deferred to Week 4 by the
    project owner (2026-09-04) -- not a missing input, a scheduling
    decision. Logged as pending regardless.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

REJECT_MARKER = re.compile(r"^\*\*\s*reject", re.IGNORECASE)
DISPUTED_MARKER = re.compile(r"^\*\*\s*disputed", re.IGNORECASE)

# Include C: product string ends in "_firmware" or contains "_firmware_".
FIRMWARE_SUFFIX_RE = re.compile(r"_firmware(_|$)", re.IGNORECASE)

# Appendix B v0 model-designator pattern: hyphenated alphanumeric, e.g.
# dir-825, tl-wr841n, rt-n56u. Used only by Include B (vendor-list-gated).
MODEL_DESIGNATOR_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)+$", re.IGNORECASE)

PENDING_SOFT_EXCLUSION_NOTE = (
    "soft exclusion categories (enterprise datacenter networking/server "
    "platforms, ICS, medical devices, automotive, mobile handsets, "
    "general-purpose computers) deferred to Week 4 per project owner "
    "(2026-09-04), not yet evaluated"
)
PENDING_INCLUDE_B_NOTE = (
    "Include-B (part:o/part:a + curated vendor + model-designator pattern) "
    "not evaluated: curated vendor list not supplied yet"
)


@dataclass
class RuleMatch:
    rule: str  # "h_any" | "h_vulnerable_true" | "o_firmware" | "include_b_vendor_pattern"
    vendor: str
    product: str


@dataclass
class CorpusDecision:
    cve_id: str
    included: bool
    include_reasons: list = field(default_factory=list)
    exclude_reasons: list = field(default_factory=list)
    ambiguous: bool = False
    pending_notes: list = field(default_factory=list)
    rule_tags: set = field(default_factory=set)


def get_english_description(cve: dict) -> str:
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def extract_part_matches(cve: dict, part: str) -> list[tuple[str, str, bool]]:
    """Return (vendor, product, vulnerable) for ALL CPE criteria of the given
    part ('h', 'o', or 'a'), regardless of the `vulnerable` flag."""
    matches = []
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for m in node.get("cpeMatch", []):
                parts = m.get("criteria", "").split(":")
                if len(parts) > 4 and parts[2] == part:
                    matches.append((parts[3], parts[4], bool(m.get("vulnerable", False))))
    return matches


def find_inclusion_matches(
    cve: dict,
    vendor_list: set[str] | None = None,
    firmware_pattern: "re.Pattern" = MODEL_DESIGNATOR_RE,
) -> list[RuleMatch]:
    matches: list[RuleMatch] = []

    for vendor, product, vulnerable in extract_part_matches(cve, "h"):
        matches.append(RuleMatch("h_any", vendor, product))
        if vulnerable:
            matches.append(RuleMatch("h_vulnerable_true", vendor, product))

    for part in ("o", "a"):
        for vendor, product, _vulnerable in extract_part_matches(cve, part):
            if part == "o" and FIRMWARE_SUFFIX_RE.search(product):
                matches.append(RuleMatch("o_firmware", vendor, product))
            elif vendor_list is not None and vendor in vendor_list and firmware_pattern.match(product):
                matches.append(RuleMatch("include_b_vendor_pattern", vendor, product))

    return matches


def classify(
    cve: dict,
    vendor_list: set[str] | None = None,
    firmware_pattern: "re.Pattern" = MODEL_DESIGNATOR_RE,
) -> CorpusDecision:
    cve_id = cve.get("id", "")

    rule_matches = find_inclusion_matches(cve, vendor_list, firmware_pattern)
    rule_tags = {m.rule for m in rule_matches}
    include_reasons = [f"{m.rule}: {m.vendor}:{m.product}" for m in rule_matches]

    pending_notes: list[str] = []
    if vendor_list is None and (extract_part_matches(cve, "o") or extract_part_matches(cve, "a")):
        pending_notes.append(PENDING_INCLUDE_B_NOTE)

    # Hard exclude: Rejected / Disputed
    exclude_reasons: list[str] = []
    status = (cve.get("vulnStatus") or "").strip().lower()
    if status == "rejected":
        exclude_reasons.append("vulnStatus=Rejected")
    desc = get_english_description(cve)
    if REJECT_MARKER.match(desc):
        exclude_reasons.append("description marked ** REJECT **")
    if DISPUTED_MARKER.match(desc):
        exclude_reasons.append("description marked ** DISPUTED **")

    # Soft exclusion categories: deferred to Week 4, always pending for now
    pending_notes.append(PENDING_SOFT_EXCLUSION_NOTE)

    ambiguous = bool(rule_matches) and bool(exclude_reasons)
    included = bool(rule_matches) and not exclude_reasons

    return CorpusDecision(
        cve_id=cve_id,
        included=included,
        include_reasons=include_reasons,
        exclude_reasons=exclude_reasons,
        ambiguous=ambiguous,
        pending_notes=pending_notes,
        rule_tags=rule_tags,
    )
