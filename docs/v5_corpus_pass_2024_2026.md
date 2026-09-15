# CVE List V5 Corpus Pass -- Backlog + Triage Eras (2024-2026)

Local sparse checkout of `cves/2024`, `cves/2025`, `cves/2026` from `github.com/CVEProject/cvelistV5` (git filter=blob:none, sparse-checkout; see `data/v5_repo/`, gitignored). 142,779 CVE List V5 records scanned in 141s using `corpus_filter_v5.classify()`.

**Scope:** backlog era (2024-Feb 2026) + triage era (Mar 2026-) only. See module docstring in `src/v5_corpus_pass.py` for why pre-2024 is out of scope for this population-level pass.

**Result: 21,528 of 142,779 records (15.08%) match the V5-based embedded/IoT inclusion rule.**

- `cpeApplicability` present in either container: 25,142 of 142,779 (17.61%) -- confirms this is rare, per module docstring.
- Ambiguous (matched inclusion and a soft-exclusion category): 103


## Per-year

| Year | Scanned | Included | % |
|---|---:|---:|---:|
| 2024 | 39,246 | 4,959 | 12.64% |
| 2025 | 45,266 | 5,715 | 12.63% |
| 2026 | 58,267 | 10,854 | 18.63% |

## Inclusion-reason breakdown (a record can match more than one)

| Reason | Count |
|---|---:|
| `v5_vendor_match` | 87,189 |
| `v5_category_keyword` | 2,463 |
| `v5_cpe_applicability` | 225 |
| `v5_firmware_suffix` | 3 |

## Soft-exclusion category breakdown (among records that also matched inclusion)

| Category | Count |
|---|---:|
| `soft_excl_ics` | 306 |
| `soft_excl_enterprise_datacenter` | 241 |
| `soft_excl_medical` | 81 |
| `soft_excl_automotive` | 50 |
| `soft_excl_mobile_handset` | 20 |
| `soft_excl_general_purpose_computer` | 6 |

## Top 30 vendors by V5-based vendor-match count

| Vendor | Count |
|---|---:|
| Microsoft | 61,660 |
| Apple | 5,181 |
| Google | 4,167 |
| IBM | 2,234 |
| Dell | 2,061 |
| Lenovo | 1,863 |
| D-Link | 1,497 |
| NVIDIA | 926 |
| Tenda | 867 |
| Gigabyte | 648 |
| Huawei | 601 |
| Milesight | 475 |
| NETGEAR | 455 |
| Linksys | 387 |
| TOTOLINK | 334 |
| F5 | 332 |
| WAGO | 314 |
| Hikvision | 205 |
| Totolink | 193 |
| WatchGuard | 168 |
| ASUS | 157 |
| Advantech | 151 |
| Wavlink | 140 |
| Zyxel | 133 |
| UTT | 108 |
| H3C | 104 |
| Edimax | 96 |
| Synology | 94 |
| SonicWall | 85 |
| Hitachi | 77 |
