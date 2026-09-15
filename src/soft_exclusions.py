"""Week 4 soft exclusion categories (Appendix B), implemented in code.

PR1 Appendix B named six soft-exclusion categories and deferred implementing
them to Week 4: enterprise datacenter/server platforms, industrial control
systems (ICS), medical devices, automotive systems, mobile handsets, and
general-purpose computers. Excluding ICS/medical/automotive is a scope
decision, not an oversight -- those categories run under different
disclosure and regulatory regimes and would confound the vendor comparison
(see PR1 Problem Statement / Appendix B).

This module is keyword- and vendor-pattern-based, run against the English
CVE description text (and, for the CVE List V5 path, the `affected[].product`
/ `platforms` strings too -- see cve_list_v5_filter.py). It is deliberately a
soft filter: a match here does not silently drop a record. In
corpus_filter.classify(), a soft-exclusion match is logged with its own
category tag and, per the Appendix B tiebreaker (a record matching both an
inclusion and an exclusion rule resolves to excluded and is logged as
ambiguous), only takes effect when the record also matched an inclusion
rule -- so every soft exclusion that actually changes a record's outcome is
visible in the ambiguity log, not silently applied.

Design choice on scope: chipset/SoC vendors (Qualcomm, MediaTek, Unisoc,
Realtek) are NOT globally excluded here, because the same silicon vendors
supply both mobile-handset SoCs (out of scope) and embedded/IoT SoCs used in
routers, cameras, and gateways (in scope) -- the distinction lives in the
product string, not the vendor, so mobile-handset exclusion is a
product-pattern match, not a vendor-pattern match.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# Word-boundary category patterns, matched against description text (and,
# where noted, product/platform strings). Deliberately conservative: a
# pattern that would also catch legitimate embedded/IoT language is left out
# even if it would improve recall for the excluded category, because a false
# soft-exclusion is harder to catch downstream than a false inclusion (the
# tiebreaker already logs every case where both fire).

ENTERPRISE_DATACENTER_RE = re.compile(
    r"\b("
    r"data ?center|blade server|rack server|hyperconverged|"
    r"storage area network|\bsan\b switch|fibre channel switch|"
    r"core router|backbone router|carrier[- ]grade|service provider router|"
    r"load balancer appliance|application delivery controller|"
    r"enterprise firewall|next-generation firewall|"
    r"hypervisor|virtual machine manager|vsphere|esxi|"
    r"mainframe"
    r")\b",
    re.IGNORECASE,
)

ICS_RE = re.compile(
    r"\b("
    r"industrial control system|\bics\b|scada|\bplc\b|programmable logic controller|"
    r"\brtu\b|remote terminal unit|distributed control system|\bdcs\b|"
    r"human[- ]machine interface|\bhmi\b|safety instrumented system|"
    r"building automation|building management system|\bbms\b controller|"
    r"industrial automation|industrial ethernet switch|fieldbus|"
    r"modbus|profinet|profibus|ethercat|bacnet"
    r")\b",
    re.IGNORECASE,
)

MEDICAL_RE = re.compile(
    r"\b("
    r"medical device|patient monitor|infusion pump|insulin pump|"
    r"defibrillator|pacemaker|ventilator|dialysis|"
    r"diagnostic imaging|magnetic resonance|\bmri\b scanner|\bct\b scanner|"
    r"picture archiving|\bpacs\b|electronic health record|\behr\b system|"
    r"clinical information system|in vitro diagnostic|\bivd\b device|"
    r"implantable"
    r")\b",
    re.IGNORECASE,
)

AUTOMOTIVE_RE = re.compile(
    r"\b("
    r"automotive|in-vehicle|\becu\b|engine control unit|"
    r"can bus|controller area network|vehicle telematics|"
    r"infotainment system|advanced driver[- ]assistance|\badas\b|"
    r"electric vehicle charg|\bevse\b"
    r")\b",
    re.IGNORECASE,
)

# Product-string pattern only (never vendor-wide -- see module docstring).
MOBILE_HANDSET_PRODUCT_RE = re.compile(
    r"\b("
    r"smartphone|smart ?phone|android phone|\biphone\b|\bipad\b|tablet pc|"
    r"galaxy_s\d|galaxy_note|galaxy_tab|galaxy_a\d|pixel_\d|"
    r"mobile handset|cellular handset"
    r")\b",
    re.IGNORECASE,
)

GENERAL_PURPOSE_COMPUTER_RE = re.compile(
    r"\b("
    r"desktop computer|laptop computer|notebook computer|personal computer\b|"
    r"workstation pc|"
    r"windows (?:10|11) (?:home|pro|enterprise)|macos (?:desktop|laptop)|"
    r"ubuntu desktop|linux desktop distribution"
    r")\b",
    re.IGNORECASE,
)

CATEGORY_PATTERNS: dict[str, "re.Pattern"] = {
    "soft_excl_enterprise_datacenter": ENTERPRISE_DATACENTER_RE,
    "soft_excl_ics": ICS_RE,
    "soft_excl_medical": MEDICAL_RE,
    "soft_excl_automotive": AUTOMOTIVE_RE,
    "soft_excl_mobile_handset": MOBILE_HANDSET_PRODUCT_RE,
    "soft_excl_general_purpose_computer": GENERAL_PURPOSE_COMPUTER_RE,
}


@dataclass(frozen=True)
class SoftExclusionMatch:
    category: str  # key into CATEGORY_PATTERNS
    matched_text: str


def classify_soft_exclusions(text: str) -> list[SoftExclusionMatch]:
    """Run every soft-exclusion category pattern against ``text`` (typically
    the English CVE description, optionally concatenated with product/
    platform strings for the V5 path). Returns every category that fired --
    a record can match more than one category."""
    if not text:
        return []
    matches: list[SoftExclusionMatch] = []
    for category, pattern in CATEGORY_PATTERNS.items():
        m = pattern.search(text)
        if m:
            matches.append(SoftExclusionMatch(category=category, matched_text=m.group(0)))
    return matches
