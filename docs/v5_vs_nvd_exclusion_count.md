# V5-vs-NVD Exclusion Count (Week 3, W3.5) -- Headline Finding

Direct comparison of the two corpus-membership paths over the identical
2024-01-01-onward window, computed from the ID sets in
`docs/v5_corpus_pass_2024_2026.md` (V5 path, 142,779 records scanned locally)
and `docs/nvd_2024_onward_pass.md` (NVD path, 157,109 CVEs scanned live via
the NVD API 2.0 for the same start date through 2026-09-15).

| | Count |
|---|---:|
| V5-path included | 21,528 |
| NVD-path included | 8,663 |
| **Overlap (both paths agree)** | 3,077 |
| **V5-only -- NVD path missed these entirely** | **18,451** |
| NVD-only -- V5 text/vendor rule missed these | 5,586 |
| **Union -- combined OR corpus for this window** | **27,114** |

**This is the number the CVE List V5 pivot exists to produce.** For the
2024-2026 window alone, the NVD-enrichment-dependent path finds less than a
third (8,663 of 27,114, 32%) of the embedded/IoT candidates the combined
corpus contains. 18,451 records -- 68% of the true combined population for
this window -- would never have entered the study at all under PR1's
original NVD-API-only sampling frame. This is a substantially larger effect
than the pilot-scale numbers suggested it might be, and it is the strongest
evidence yet for Mizanur's peer-review argument (D-register MR-1): an
NVD-API-only corpus does not just shrink the sample, it changes *which*
records are in it, in a way that plausibly correlates with exactly the
enrichment-triage factors (KEV membership, federal/critical-software status)
that have nothing to do with a device's actual patch actionability.

## Why the overlap is small (3,077 of 27,114, 11%)

The two paths use genuinely different signals -- CPE structure on the NVD
side, vendor-name/category-keyword text matching on the V5 side -- so a
small intersection is expected, not a bug: a record needs both a
CPE-structured NVD enrichment AND to independently pass the V5 text rule to
land in the overlap. The NVD-only 5,586 is itself worth noting: these are
records where NVD's CPE data was populated but the V5 CNA-side text (vendor
name, product string, description) didn't trip the category-keyword or
curated-vendor match -- most likely CNA-supplied records using non-obvious
product naming that the text heuristic doesn't catch, a known limitation of
a text-based rule (documented in `src/corpus_filter_v5.py`).

## Scope note

This comparison covers 2024-2026 only (the backlog + triage eras), per the
scope decision in `docs/v5_corpus_pass.py`. The corpus freeze
(`docs/corpus_freeze_manifest.md`) applies the same combined OR-membership
rule to the full historical range as a Week 5 task.
