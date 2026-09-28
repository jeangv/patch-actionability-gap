# CVE List V5 Corpus Pass -- Backlog + Triage Eras (2024-2026)

Local sparse checkout of `cves/2024`, `cves/2025`, `cves/2026` from `github.com/CVEProject/cvelistV5` (git filter=blob:none, sparse-checkout; see `data/v5_repo/`, gitignored). 142,779 CVE List V5 records scanned in 95s using `corpus_filter_v5.classify()`.

**Scope:** backlog era (2024-Feb 2026) + triage era (Mar 2026-) only. See module docstring in `src/v5_corpus_pass.py` for why pre-2024 is out of scope for this population-level pass.

**Result: 2,808 of 142,779 records (1.97%) match the V5-based embedded/IoT inclusion rule.**

- `cpeApplicability` present in either container: 25,142 of 142,779 (17.61%) -- confirms this is rare, per module docstring.
- Ambiguous (matched inclusion and a soft-exclusion category): 22


## Per-year

| Year | Scanned | Included | % |
|---|---:|---:|---:|
| 2024 | 39,246 | 624 | 1.59% |
| 2025 | 45,266 | 1,036 | 2.29% |
| 2026 | 58,267 | 1,148 | 1.97% |

## Inclusion-reason breakdown (a record can match more than one)

| Reason | Count |
|---|---:|
| `v5_vendor_and_model` | 4,700 |
| `v5_vendor_and_category` | 854 |
| `v5_cpe_applicability` | 220 |
| `v5_firmware_suffix` | 3 |

## Soft-exclusion category breakdown (among records that also matched inclusion)

| Category | Count |
|---|---:|
| `soft_excl_ics` | 22 |

## Top 30 vendors by V5-based vendor-match count

| Vendor | Count |
|---|---:|
| D-Link | 1,430 |
| Tenda | 828 |
| NETGEAR | 448 |
| Milesight | 421 |
| Linksys | 386 |
| TOTOLINK | 314 |
| Gigabyte | 221 |
| Totolink | 191 |
| Hikvision | 177 |
| Advantech | 103 |
| Wavlink | 91 |
| Edimax | 85 |
| TRENDnet | 73 |
| ASUS | 71 |
| Belkin | 42 |
| Netgear | 37 |
| PTZOptics | 32 |
| Honeywell | 30 |
| LB-LINK | 30 |
| Sony | 25 |
| Sapido | 25 |
| SonicWall | 23 |
| Netentsec | 21 |
| Huawei | 21 |
| Synology | 20 |
| Comfast | 20 |
| GeoVision | 19 |
| H3C | 17 |
| WAVLINK | 16 |
| WatchGuard | 16 |
