# V5-vs-NVD Exclusion Count (Week 3, W3.5) -- Corrected

**This finding was wrong in the original PR2 draft, not just imprecise, and
is corrected here after peer review (Monika Schrenk, Travis Carlisle, JP
Valentine -- Sep 23-24, 2026) independently flagged the same symptom (an
implausibly low 11% V5/NVD overlap) and Monika specifically diagnosed the
root cause. See `docs/design_decisions.md` and
`2026-10-04_Progress Report 3/PR3_Feedback_To_Address.md` for the full
review trail.**

## What was wrong

`corpus_filter_v5.classify()`'s vendor-match rule (v1) admitted a record if
its vendor was on the curated list, full stop -- no requirement that the
description also indicate an embedded/IoT product. Because the curated
vendor list included large general-purpose vendors (Microsoft, Google,
Apple, IBM, Dell -- each of which does also sell some genuine embedded/IoT
hardware, which is why they were on the list at all), this let those
vendors' entire CVE volume flood the V5-path corpus: Microsoft alone
matched 61,660 records, nearly all of them unrelated Windows/Remote Desktop
Gateway/Azure records, not embedded devices. A second, independent bug
(`identifiability_scorer.score_fix_availability_v5` scoring 1 for the mere
presence of any reference, not requiring a patch tag or vendor-advisory tag
per the rubric) was found in the same review pass and fixed alongside this
one, though it did not affect the corpus-membership numbers below.

**Fix (v2):** the V5-path text rule now requires vendor membership **and**
a category-keyword match together (mirroring Include B on the NVD path,
which already required vendor membership and a model-designator pattern
together) -- see `corpus_filter_v5.py`. Spot-checking the post-fix matches
for the five general-purpose vendors found 100% were still false positives
("Remote Desktop Gateway," "IBM Sterling File Gateway," "Dell Secure
Connect Gateway," Android/iOS camera and modem permission bugs), so those
five vendors were also added to the manual exclusion list
(`build_curated_vendor_list.py`) that already excluded chipset and
enterprise-networking vendors on the same basis.

## Corrected comparison

Same method as before -- direct comparison of the two corpus-membership
paths over the identical 2024-01-01-onward window -- re-run against the
corrected rule. V5 path: local sparse checkout, 142,779 records
(`docs/v5_corpus_pass_2024_2026.md`). NVD path: live NVD API 2.0 scan,
162,421 CVEs (`docs/nvd_2024_onward_pass.md`, re-run 2026-09-24, 9 days of
new records beyond the original run explains the higher scan count).

| | Original (buggy) | Corrected |
|---|---:|---:|
| V5-path included | 21,528 | **492** |
| NVD-path included | 8,663 | **8,688** |
| Overlap | 3,077 | **211** |
| V5-only (NVD missed these) | 18,451 | **281** |
| NVD-only (V5 text rule missed these) | 5,586 | **8,477** |
| Union (combined OR corpus) | 27,114 | **8,969** |
| **V5-only as % of union (the old "68%" headline)** | **68%** | **3.1%** |

**Corrected finding: for 2024-2026, the CVE List V5 pivot adds 281 records
(3.1% of the combined corpus) that the NVD-only path would have missed --
not 68%.** The NVD-CPE path is the dominant source for this window (8,688
of 8,969 union records, 96.9%), and V5 mostly re-discovers records the NVD
path already has (211 of 492 V5 matches, 42.9%, overlap with NVD) rather
than surfacing a systematically different population.

## What this means for the project

The corrected finding is a much more modest justification for the pivot
than PR2 claimed, and that has to be stated plainly rather than
downplayed: the original 68% number was the report's headline result, cited
by name in Video 2 and praised by multiple peer reviewers as "especially
compelling." It was wrong. The corrected 3.1% figure still supports keeping
V5 in an OR-combined corpus (some genuinely novel records are still
uniquely found there, and the CNA-vs-NVD provenance split remains
architecturally necessary regardless of corpus-size arguments -- see
`docs/cna_vs_nvd_scoring_split.md`, which is unaffected by this bug), but
the *size* of the effect can no longer be the centerpiece argument for the
pivot. The centerpiece argument reverts to the qualitative one from
Preliminary Finding #2 (PR1): an NVD-only corpus is selected on NVD's own
enrichment-triage decisions, which is a bias argument independent of how
many extra records V5 happens to contribute.

**Scope note carried over unchanged:** this comparison still covers
2024-2026 only; the full 1999-2023 comparison remains a Week 5 task
(`docs/corpus_freeze_manifest.md`), and will need to be run against this
corrected rule, not the original one.

## Why the corrected overlap is still not "high"

211 of 492 V5 matches (42.9%) also appear in the NVD path -- a real,
moderate overlap, not the near-total agreement a single well-behaved
signal might produce, but nowhere near the near-total disagreement the
buggy 11% figure implied either. The remaining 281 V5-only records are
plausible genuine discoveries: CVE List V5's CNA-supplied text can name a
vendor and describe a product before NVD has enriched it with a CPE, so
some real lag-driven complementarity is expected and consistent with the
project's own three-era/triage-policy argument (Section I-C of the final
report draft). The 42.9% overlap is left unexplained further here; a
larger, full-history run (Week 5) would give a more stable estimate than
this 2024-2026-only window.
