"""Vendor scope denylist, applied to BOTH corpus paths (Week 6, C4).

These vendors are identifiable by name as predominantly out of scope:
silicon/chipset, enterprise or carrier networking, industrial control, or
general-purpose computing and software. Two things use the list:

  - build_curated_vendor_list.py keeps them off the curated vendor list,
    which gates Include B on the NVD path and the vendor clauses on the V5
    path.
  - corpus_filter.classify and corpus_filter_v5.classify exclude a record
    whose matched vendors are ALL on this list. A record that also names a
    device vendor (a TP-Link router built on a Qualcomm chip) stays.

Until Week 6 the list only fed the curated vendor list. The NVD path's
Include A (any part:h CPE) and Include C (firmware-suffixed part:o) do not
consult the vendor list, so the corpus freeze admitted about 10,000 records
from these vendors (Qualcomm 2,438, Cisco 2,156, MediaTek 1,067, Intel 827,
Siemens 657, ...). A hand check of 30 random NVD-only records found 15 out
of scope (docs/v5_nvd_characterization_sample.md, first draw). Applying the
list to both paths makes the two follow one scope rule.

The last block (AMD through HPE) was added at the same time, after the
first what-if showed those vendors topping the NVD path once the others
were removed; sampled records were CPU, BIOS/BMC, GPU, and enterprise
storage/server firmware.
"""
from __future__ import annotations

import re

VENDOR_SCOPE_DENYLIST = {
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
    "rockwellautomation": "industrial control systems (added Week 6 with C4: in the NVD top 20 after the first C4 pass)",
    "phoenixcontact": "industrial control systems (added Week 6 with C4: in the NVD top 20 after the first C4 pass)",
    # general-purpose software/cloud/mobile OS (V5-path evidence, Sep 2026)
    "microsoft": "general-purpose/enterprise software (e.g. Remote Desktop Gateway, Windows) dominates this vendor's CVE count",
    "ibm": "general-purpose enterprise software (e.g. Sterling File Gateway, Security Verify) dominates this vendor's CVE count",
    "dell": "general-purpose enterprise software and PC/server firmware dominate this vendor's CVE count",
    "google": "mobile OS (Android/Chrome) components dominate this vendor's CVE count",
    "apple": "mobile/desktop OS (iOS/iPadOS/macOS) components dominate this vendor's CVE count",
    # general-purpose computing / datacenter (NVD-path evidence, Week 6)
    "amd": "CPU and platform security processor firmware",
    "lenovo": "PC and server BIOS/BMC firmware dominates this vendor's CVE count",
    "nvidia": "GPU drivers and compute modules dominate this vendor's CVE count",
    "netapp": "enterprise storage appliances",
    "hpe": "enterprise servers, storage, and datacenter networking",
}


def norm(vendor: str) -> str:
    """Letters and digits only, lowercase: 'Schneider Electric' == 'schneider_electric'."""
    return re.sub(r"[^a-z0-9]", "", vendor.lower())


_DENIED = frozenset(norm(v) for v in VENDOR_SCOPE_DENYLIST)


def scope_denied(vendors) -> bool:
    """True when every named vendor is on the denylist (and at least one is named)."""
    vs = {norm(v) for v in vendors if v}
    return bool(vs) and vs <= _DENIED
