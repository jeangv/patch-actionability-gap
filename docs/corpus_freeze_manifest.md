# Corpus Freeze Manifest (Week 4, W4.2) -- DESIGN LOCK

**As of this document, the corpus membership rule, era boundaries, vendor
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
the same soft-exclusion categories (`src/soft_exclusions.py`) and the same
curated vendor list (`data/curated_vendor_list.json`, 537 of 553 candidate
vendors, see `docs/curated_vendor_list.md`).

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

`data/curated_vendor_list.json` -- 537 vendors, pruned from the 553-vendor
data-driven candidate list by `src/build_curated_vendor_list.py`. Full
decision table: `docs/curated_vendor_list.md`.

## Corpus N -- status and scope decision

**Not yet re-computed end to end against the frozen rule above, and this
document says so rather than presenting an estimate as final.** What exists:

- The original full-historical NVD discovery pass (`docs/vendor_candidates_v1.md`,
  2026-09-04): 386,755 CVEs scanned, 32,964 matched **the pre-soft-exclusion,
  pre-Include-B rule** (Include A + Include C only).
- The Week 4 soft-exclusion recheck (`docs/w4_soft_exclusion_recheck.md`)
  measured a 2.5% (5/200) flip-to-excluded rate on the already-collected
  pilot sample once soft exclusions are applied.
- The CVE List V5 population pass (`docs/v5_corpus_pass_2024_2026.md`,
  corrected 2026-09-24 after a peer-review-caught corpus-filter bug -- see
  `docs/v5_vs_nvd_exclusion_count.md` for the full correction) found 492
  V5-path matches across 2024-2026 alone (142,779 scanned), against 8,688
  NVD-path matches for the identical window (`docs/nvd_2024_onward_pass.md`,
  162,421 scanned live). The two ID sets overlap on 211 records -- see
  `docs/v5_vs_nvd_exclusion_count.md`: **281 records (3.1% of the
  8,969-record combined corpus for this window alone) would be missed
  entirely under an NVD-only sampling frame.** An earlier version of this
  pass (reported in PR2) had a corpus-filter bug that let general-purpose
  software vendors flood the V5 path and produced a since-retracted 68%
  figure; the corrected 3.1% is a real but far more modest effect than
  originally reported, and is not estimated by scaling the old NVD-only
  number (32,964) either.

**Scope decision (executive call, stated explicitly):** computing the final
frozen N requires one more full pass -- NVD 1999-2023 plus CVE List V5
1999-2023 -- against the now-frozen combined rule. That crawl was not run in
this pass: the 2024-2026 V5 population pass alone took ~2.5 minutes against
a local sparse checkout (142,781 records), but the *pre-2024* V5 population
is ~25 more year-directories with no local checkout yet, and the matching
NVD-side full-historical crawl (see `docs/nvd_2024_onward_pass.md` for the
2024-onward rate) would run roughly 45-50 minutes end to end. Rather than
either block this progress report on that crawl or publish an estimated N
next to numbers that are exact, **the frozen rule, era boundaries, and
vendor list above are locked now; the exact frozen N is a first task of
Week 5**, computed by `src/full_corpus_freeze_pass.py` (to be written) and
committed as `data/corpus_manifest.json` with the SHA-256 and V5 source
commit hash below.

## Verifiability (D9)

Once the full pass runs (Week 5):

- `data/corpus_manifest.json` -- sorted list of every included CVE ID.
- SHA-256 over the sorted, newline-joined ID list, recorded alongside.
- The CVE List V5 source commit hash used for that pass (the V5 repo is a
  live, continuously-updated corpus, so the manifest must pin the exact
  commit it was computed against to be reproducible -- `git -C
  data/v5_repo rev-parse HEAD` at pass time).

## Control corpus matching variables (D7, added to the freeze)

The general-purpose software control corpus (not yet built -- Week 7 per
timeline) will be matched to the frozen embedded/IoT corpus on:

1. **Publication-date distribution across the three eras** -- same
   pre-2024/backlog/triage proportions.
2. **CVSS severity distribution** -- same baseSeverity (or baseScore decile)
   proportions, computed from whichever of CNA-supplied or NVD-added CVSS is
   present per record (see `docs/pilot_report_v2.md` "CVSS field population"
   for why these two fields are read separately, not pooled).
