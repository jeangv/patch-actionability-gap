"""Appendix B embedded/IoT corpus inclusion/exclusion rule.

Implements only the parts of the rule that are fully specified today:

  - Include A: any CVE whose `configurations` contain a CPE `criteria` with
    `part:h` marked `vulnerable: true`.
  - Hard exclude: CVE record state is Rejected or Disputed (NVD `vulnStatus`,
    or the traditional `** REJECT **` / `** DISPUTED **` description markers
    used for older records).
  - Tiebreaker: a record matching both an inclusion and an exclusion
    criterion resolves in favor of exclusion, and is logged as ambiguous.

NOT YET IMPLEMENTED (pending inputs that haven't been provided):
  - Include B: part:o/part:a CVEs where the vendor is on the curated list AND
    the product string matches a "device-firmware naming pattern". Needs the
    pruned curated vendor list and the exact naming-pattern definition from
    the Appendix B document -- pass `vendor_list` / `firmware_pattern` in
    once available; until then this branch is skipped and logged as pending,
    never silently applied with a guessed pattern.
  - Soft exclusion categories (enterprise datacenter networking/server
    platforms, ICS, medical devices, automotive, mobile handsets,
    general-purpose computers). Needs the Appendix B classification rule
    text (e.g. which CPE fields / keyword lists identify these categories).
    Until supplied, this branch is skipped and logged as pending.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

REJECT_MARKER = re.compile(r"^\*\*\s*reject", re.IGNORECASE)
DISPUTED_MARKER = re.compile(r"^\*\*\s*disputed", re.IGNORECASE)

PENDING_SOFT_EXCLUSION_NOTE = (
    "soft exclusion categories (enterprise datacenter networking/server "
    "platforms, ICS, medical devices, automotive, mobile handsets, "
    "general-purpose computers) not evaluated: awaiting Appendix B "
    "classification rule text"
)
PENDING_INCLUDE_B_NOTE = (
    "Include-B (part:o/part:a + curated vendor + device-firmware naming "
    "pattern) not evaluated: vendor list and/or naming pattern not supplied"
)


@dataclass
class CorpusDecision:
    cve_id: str
    included: bool
    include_reasons: list = field(default_factory=list)
    exclude_reasons: list = field(default_factory=list)
    ambiguous: bool = False
    pending_notes: list = field(default_factory=list)


def get_english_description(cve: dict) -> str:
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def extract_part_matches(cve: dict, part: str) -> list[tuple[str, str]]:
    """Return (vendor, product) for vulnerable CPE criteria of the given part
    ('h', 'o', or 'a')."""
    matches = []
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if not m.get("vulnerable", True):
                    continue
                parts = m.get("criteria", "").split(":")
                if len(parts) > 4 and parts[2] == part:
                    matches.append((parts[3], parts[4]))
    return matches


def classify(
    cve: dict,
    vendor_list: set[str] | None = None,
    firmware_pattern: "re.Pattern | None" = None,
) -> CorpusDecision:
    cve_id = cve.get("id", "")
    include_reasons: list[str] = []
    exclude_reasons: list[str] = []
    pending_notes: list[str] = []

    # Include A
    if extract_part_matches(cve, "h"):
        include_reasons.append("part:h CPE present (vulnerable)")

    # Include B (only if caller supplied both required inputs)
    oa_matches = extract_part_matches(cve, "o") + extract_part_matches(cve, "a")
    if vendor_list is not None and firmware_pattern is not None:
        for vendor, product in oa_matches:
            if vendor in vendor_list and firmware_pattern.search(product):
                include_reasons.append(
                    f"part:o/a firmware-pattern match ({vendor}:{product})"
                )
                break
    elif oa_matches:
        pending_notes.append(PENDING_INCLUDE_B_NOTE)

    # Hard exclude: Rejected / Disputed
    status = (cve.get("vulnStatus") or "").strip().lower()
    if status == "rejected":
        exclude_reasons.append("vulnStatus=Rejected")
    desc = get_english_description(cve)
    if REJECT_MARKER.match(desc):
        exclude_reasons.append("description marked ** REJECT **")
    if DISPUTED_MARKER.match(desc):
        exclude_reasons.append("description marked ** DISPUTED **")

    # Soft exclusion categories: always pending until Appendix B text is supplied
    pending_notes.append(PENDING_SOFT_EXCLUSION_NOTE)

    ambiguous = bool(include_reasons) and bool(exclude_reasons)
    included = bool(include_reasons) and not exclude_reasons

    return CorpusDecision(
        cve_id=cve_id,
        included=included,
        include_reasons=include_reasons,
        exclude_reasons=exclude_reasons,
        ambiguous=ambiguous,
        pending_notes=pending_notes,
    )
