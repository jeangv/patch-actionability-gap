# Pilot Slice Report

Retrieved: 2026-09-04T22:46:42+00:00 from the NVD CVE API 2.0.

**Corpus filter applied:** `corpus_filter.classify()` -- Include A (part:h CPE present) and the hard Rejected/Disputed exclusion only. Include B (part:o/part:a + curated vendor + device-firmware naming pattern) and the soft exclusion categories (enterprise datacenter networking/server platforms, ICS, medical devices, automotive, mobile handsets, general-purpose computers) are **not yet applied**: they need the pruned curated vendor list and the Appendix B classification/naming-pattern text, neither of which has been supplied yet. Numbers below reflect Include-A-only membership.

**Ambiguity list** (matched both an inclusion and the implemented exclusion criteria, resolved as excluded per the tiebreaker rule): 0 record(s). Full list: `data/pilot_20260904/ambiguous.json`.

## Target vs. achieved, per era

| Era | Target | Collected | CVEs scanned to find them |
|---|---:|---:|---:|
| pre-2024 | 67 | 67 | 40732 |
| backlog era (2024-Feb 2026) | 67 | 19 | 100627 |
| triage era (Mar 2026-) | 66 | 1 | 51522 |
| **Total** | **200** | **87** | |

**Shortfall:** collected 87/200. This is reported as-is, not padded.


## Field population -- overall

| Field | % of collected records |
|---|---:|
| cpeMatch/configurations present | 100.0% |
| versionEndExcluding/Including present | 52.9% |
| versionStartExcluding/Including present | 41.4% |
| CPE part:h present | 100.0% |
| references non-empty | 100.0% |
| Patch/Vendor Advisory reference tag present | 87.4% |
| CVSS: CNA-supplied present | 89.7% |
| CVSS: NVD-added present | 85.1% |

## Field population -- by era


### pre-2024 (n=67)

| Field | % |
|---|---:|
| cpeMatch/configurations present | 100.0% |
| versionEndExcluding/Including present | 56.7% |
| versionStartExcluding/Including present | 50.7% |
| CPE part:h present | 100.0% |
| references non-empty | 100.0% |
| Patch/Vendor Advisory reference tag present | 89.6% |
| CVSS: CNA-supplied present | 86.6% |
| CVSS: NVD-added present | 95.5% |

### backlog era (2024-Feb 2026) (n=19)

| Field | % |
|---|---:|
| cpeMatch/configurations present | 100.0% |
| versionEndExcluding/Including present | 42.1% |
| versionStartExcluding/Including present | 10.5% |
| CPE part:h present | 100.0% |
| references non-empty | 100.0% |
| Patch/Vendor Advisory reference tag present | 78.9% |
| CVSS: CNA-supplied present | 100.0% |
| CVSS: NVD-added present | 47.4% |

### triage era (Mar 2026-) (n=1)

| Field | % |
|---|---:|
| cpeMatch/configurations present | 100.0% |
| versionEndExcluding/Including present | 0.0% |
| versionStartExcluding/Including present | 0.0% |
| CPE part:h present | 100.0% |
| references non-empty | 100.0% |
| Patch/Vendor Advisory reference tag present | 100.0% |
| CVSS: CNA-supplied present | 100.0% |
| CVSS: NVD-added present | 100.0% |
