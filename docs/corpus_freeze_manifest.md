# Corpus Freeze Manifest (Week 4, W4.2) -- DESIGN LOCK

**As of this document, the corpus membership rule (with corrections C1 to C4), era boundaries, vendor
list, and scoring rubric (`docs/scoring_rubric_v0.1.md`) are frozen.**
Anything found wrong after this point is a documented limitation, not a
revision -- per the Week 4 milestone stated in PR1's timeline.

## Membership rule (frozen)

A CVE is in the corpus if **either**:

- `corpus_filter.classify()` (NVD API path, CPE-based: Include A `h_any`,
  Include B `include_b_vendor_pattern` gated on the curated vendor list,
  Include C `o_firmware`) returns `included=True`, **or**
- `corpus_filter_v5.classify()` (CVE List V5 path, CNA-text-based) returns
  `included=True`,

evaluated independently, per `docs/cna_vs_nvd_scoring_split.md`. Both apply
the same soft-exclusion categories (`src/soft_exclusions.py`), the same
curated vendor list (`data/curated_vendor_list.json`, 527 of 553 candidate
vendors, see `docs/curated_vendor_list.md`), and, since C4, the same vendor
scope denylist (`src/scope_denylist.py`, 28 vendors): a record is excluded
when every vendor that triggered it is on the list. The V5 rule is v3 (C3).
Post-lock corrections C1 to C4 are in `docs/design_decisions.md`.

## Era boundaries (frozen, unchanged from PR1)

| Era | Range |
|---|---|
| pre-2024 | before 2024-01-01 |
| backlog era | 2024-01-01 through 2026-02-28 |
| triage era | 2026-03-01 onward |

Per D1, pre-2024 is **retained** in the corpus (not dropped), with the CPE
AND-node convention era (pre-2011 vs. 2011+) carried as an explicit
covariate, and **excluded from the pooled RQ3 vendor ranking only** (reported
as a separate pre-2011 ranking there).

## Vendor list (frozen)

`data/curated_vendor_list.json` -- 527 vendors, pruned from the 553-vendor
data-driven candidate list by `src/build_curated_vendor_list.py`. Full
decision table: `docs/curated_vendor_list.md`.

## Corpus N -- frozen 2026-09-28

**21,990 CVEs**: 2,878 admitted by both paths, 18,182 by NVD only, 930 by CVE List V5 only. NVD path: 21,060 of 397,944 CVEs crawled from 1999 to 2026-09-28 (`src/freeze_nvd_pass.py`). V5 path: 3,808 of 391,971 records (`src/freeze_v5_pass.py`). Published before 2011: 1,403. Per-era counts and V5-only shares: `docs/corpus_freeze_results.md`.

The first freeze that day gave 33,684 CVEs. The source characterization showed the NVD path admitting chipset, enterprise, industrial, and general-purpose vendors, so C4 applied the vendor scope denylist to both paths before the lock (11,665 NVD records removed; the NVD crawl output is filtered in `src/freeze_manifest.py`, which gives the same set a re-crawl would because each record's `vendors` field is exactly the vendors that triggered it; the V5 pass was re-run). A post-C4 sample still finds about a third of NVD-only records out of scope; that rate is stated as a limitation and the Week 8 results add a description-based screen (`docs/characterization_hand_check.md`).

## Verifiability (D9)

- `data/corpus_manifest.json` -- counts, the sorted list of every included CVE ID, the rule string, and the scope denylist counts.
- SHA-256 over the sorted, newline-joined ID list: `b8d8b34f29225332a823beb14d3980cb0974ea914e04e700c77a98cdf271be4e`.
- CVE List V5 source commit: `0fb6651236ba3f33f5a6416447cde620a4842716`.

## Control corpus matching variables (D7, added to the freeze)

The general-purpose software control corpus (not yet built -- Week 7 per
timeline) will be matched to the frozen embedded/IoT corpus on:

1. **Publication-date distribution across the three eras** -- same
   pre-2024/backlog/triage proportions.
2. **CVSS severity distribution** -- same baseSeverity (or baseScore decile)
   proportions, computed from whichever of CNA-supplied or NVD-added CVSS is
   present per record (see `docs/pilot_report_v2.md` "CVSS field population"
   for why these two fields are read separately, not pooled).
