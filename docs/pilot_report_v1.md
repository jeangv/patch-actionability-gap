# Pilot Slice Report v1 (corrected inclusion rule)

Retrieved: 2026-09-05T00:01:39+00:00 from the NVD CVE API 2.0.

**v1 vs v0:** the original run (`docs/pilot_report.md`) required `part:h` marked `vulnerable: true`, a convention NVD stopped using for embedded devices around 2011. v1 matches `part:h` anywhere in `configurations` regardless of the `vulnerable` flag (Include A), plus `part:o` CPEs whose product ends in `_firmware` (Include C). See `src/corpus_filter.py`.

**Still not applied:** Include B (part:o/part:a + curated vendor + model-designator pattern) -- no curated vendor list yet. Soft exclusion categories (enterprise datacenter networking/server platforms, ICS, medical devices, automotive, mobile handsets, general-purpose computers) -- explicitly deferred to Week 4 by the project owner, not a blocker. Numbers below may still include some of those categories.

**Ambiguity list** (matched both an inclusion and the implemented exclusion criteria, resolved as excluded per the tiebreaker rule): 0 record(s). Full list: `data/pilot_20260905_v1/ambiguous.json`.

## Rule-tag breakdown (before/after comparison)

A CVE can match more than one tag; counts are of collected (included) records only and do not need to sum to the totals above.

| Rule tag | pre-2024 | backlog era | triage era | Overall |
|---|---:|---:|---:|---:|
| `h_any` | 67 | 67 | 66 | 200 |
| `h_vulnerable_true` | 0 | 0 | 0 | 0 |
| `o_firmware` | 43 | 63 | 30 | 136 |
| `include_b_vendor_pattern` | 0 | 0 | 0 | 0 |

## Target vs. achieved, per era

| Era | Target | Collected | CVEs scanned to find them |
|---|---:|---:|---:|
| pre-2024 | 67 | 67 | 479 |
| backlog era (2024-Feb 2026) | 67 | 67 | 1300 |
| triage era (Mar 2026-) | 66 | 66 | 4535 |
| **Total** | **200** | **200** | |

## Field population -- overall

| Field | % of collected records |
|---|---:|
| cpeMatch/configurations present | 100.0% |
| versionEndExcluding/Including present | 45.0% |
| versionStartExcluding/Including present | 11.5% |
| CPE part:h present | 100.0% |
| references non-empty | 100.0% |
| Patch/Vendor Advisory reference tag present | 64.5% |
| CVSS: CNA-supplied present | 99.5% |
| CVSS: NVD-added present | 58.5% |

## Field population -- by era


### pre-2024 (n=67)

| Field | % |
|---|---:|
| cpeMatch/configurations present | 100.0% |
| versionEndExcluding/Including present | 46.3% |
| versionStartExcluding/Including present | 1.5% |
| CPE part:h present | 100.0% |
| references non-empty | 100.0% |
| Patch/Vendor Advisory reference tag present | 58.2% |
| CVSS: CNA-supplied present | 98.5% |
| CVSS: NVD-added present | 97.0% |

### backlog era (2024-Feb 2026) (n=67)

| Field | % |
|---|---:|
| cpeMatch/configurations present | 100.0% |
| versionEndExcluding/Including present | 26.9% |
| versionStartExcluding/Including present | 4.5% |
| CPE part:h present | 100.0% |
| references non-empty | 100.0% |
| Patch/Vendor Advisory reference tag present | 44.8% |
| CVSS: CNA-supplied present | 100.0% |
| CVSS: NVD-added present | 26.9% |

### triage era (Mar 2026-) (n=66)

| Field | % |
|---|---:|
| cpeMatch/configurations present | 100.0% |
| versionEndExcluding/Including present | 62.1% |
| versionStartExcluding/Including present | 28.8% |
| CPE part:h present | 100.0% |
| references non-empty | 100.0% |
| Patch/Vendor Advisory reference tag present | 90.9% |
| CVSS: CNA-supplied present | 100.0% |
| CVSS: NVD-added present | 51.5% |
