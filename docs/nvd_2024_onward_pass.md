# NVD API Pass -- 2024-01-01 Onward (comparison window for the V5 corpus pass)

157,109 CVEs scanned via the NVD CVE API 2.0, 8,663 included by `corpus_filter.classify()` (CPE-based, curated vendor list + soft exclusions applied), 1,306s.

**Comparable directly to `docs/v5_corpus_pass_2024_2026.md`** -- same 2024-01-01 onward date range, same curated vendor list, same soft-exclusion categories. The difference between the two totals is the NVD-enrichment-dependent path's exclusion count.

**NVD-path result: 8,663 included of 157,109 scanned.**


## Per-window

| Window | Scanned | Included |
|---|---:|---:|
| 2024-01-01 .. 2024-04-29 | 12,414 | 1,239 |
| 2024-04-29 .. 2024-08-26 | 14,108 | 1,120 |
| 2024-08-26 .. 2024-12-23 | 13,432 | 991 |
| 2024-12-23 .. 2025-04-21 | 16,400 | 808 |
| 2025-04-21 .. 2025-08-18 | 14,890 | 1,185 |
| 2025-08-18 .. 2025-12-15 | 16,398 | 1,147 |
| 2025-12-15 .. 2026-04-13 | 21,795 | 1,468 |
| 2026-04-13 .. 2026-08-10 | 30,367 | 587 |
| 2026-08-10 .. 2026-09-15 | 17,305 | 118 |

## Rule-tag breakdown

| Tag | Count |
|---|---:|
| `h_any` | 8,493 |
| `o_firmware` | 7,492 |
| `include_b_vendor_pattern` | 175 |
| `h_vulnerable_true` | 20 |
