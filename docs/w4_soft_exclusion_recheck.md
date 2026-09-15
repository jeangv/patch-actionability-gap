# W4.1 Soft Exclusion Recheck

Re-classification of the already-collected v2 pilot slice (`data/pilot_20260905_v2/`, 200 records, see `docs/pilot_report_v2.md`) through the current `corpus_filter.classify()`, which now evaluates the six Appendix B soft-exclusion categories and the curated-vendor-gated Include B. No new NVD API calls were made.

| Era | n | Still included | Flipped to excluded (soft exclusion) | Ambiguous (ties) |
|---|---:|---:|---:|---:|
| pre-2024 | 67 | 64 | 3 | 3 |
| backlog era | 67 | 66 | 1 | 1 |
| triage era | 66 | 65 | 1 | 1 |
| **Total** | **200** | **195** | **5** | **5** |

## Soft-exclusion category breakdown (records where the category fired)

| Category | Count |
|---|---:|
| `soft_excl_mobile_handset` | 3 |
| `soft_excl_ics` | 2 |

## Flipped records (up to 15 shown)

- CVE-2008-0034: soft_excl_mobile_handset: matched 'iPhone'
- CVE-2012-2898: soft_excl_mobile_handset: matched 'iPad'
- CVE-2014-9517: soft_excl_ics: matched 'DCS'
- CVE-2020-9080: soft_excl_mobile_handset: matched 'smart phone'
- CVE-2026-13545: soft_excl_ics: matched 'DCS'

**Result: 5 of 200 previously-included pilot records are excluded once soft-exclusion categories are evaluated (2.5%).** 5 of those are logged to the ambiguity list (matched an inclusion rule and an exclusion rule; the Appendix B tiebreaker resolves ties to excluded).
