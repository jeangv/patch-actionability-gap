# CVE List V5 Corpus Pass -- Backlog + Triage Eras (2024-2026)

Local sparse checkout of `cves/2024`, `cves/2025`, `cves/2026` from `github.com/CVEProject/cvelistV5` (git filter=blob:none, sparse-checkout; see `data/v5_repo/`, gitignored). 142,779 CVE List V5 records scanned in 103s using `corpus_filter_v5.classify()`.

**Scope:** backlog era (2024-Feb 2026) + triage era (Mar 2026-) only. See module docstring in `src/v5_corpus_pass.py` for why pre-2024 is out of scope for this population-level pass.

**Result: 492 of 142,779 records (0.34%) match the V5-based embedded/IoT inclusion rule.**

- `cpeApplicability` present in either container: 25,142 of 142,779 (17.61%) -- confirms this is rare, per module docstring.
- Ambiguous (matched inclusion and a soft-exclusion category): 0


## Per-year

| Year | Scanned | Included | % |
|---|---:|---:|---:|
| 2024 | 39,246 | 131 | 0.33% |
| 2025 | 45,266 | 140 | 0.31% |
| 2026 | 58,267 | 221 | 0.38% |

## Inclusion-reason breakdown (a record can match more than one)

| Reason | Count |
|---|---:|
| `v5_vendor_and_category` | 854 |
| `v5_cpe_applicability` | 220 |
| `v5_firmware_suffix` | 3 |

## Soft-exclusion category breakdown (among records that also matched inclusion)

| Category | Count |
|---|---:|
| (none) | 0 |

## Top 30 vendors by V5-based vendor-match count

| Vendor | Count |
|---|---:|
| NETGEAR | 271 |
| Hikvision | 115 |
| Milesight | 82 |
| D-Link | 56 |
| ASUS | 32 |
| Sapido | 24 |
| Netentsec | 21 |
| Advantech | 21 |
| Synology | 20 |
| Wavlink | 18 |
| WatchGuard | 16 |
| Huawei | 15 |
| Linksys | 13 |
| SyroTech | 9 |
| AVTECH | 9 |
| checkpoint | 8 |
| Digisol | 8 |
| F5 | 8 |
| Brickcom | 8 |
| Vivotek | 7 |
| Tenda | 6 |
| Enphase | 5 |
| Four-Faith | 4 |
| Tesla | 4 |
| TP-Link | 4 |
| TVT | 4 |
| PTZOptics | 4 |
| Pix-Link | 4 |
| LB-LINK | 4 |
| Alcatel-Lucent | 4 |
