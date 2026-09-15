# CNA-Supplied vs. NVD-Enriched Scoring Split (Week 4, W4.4)

## Why this split exists

Without it, triage-era records (published on or after March 1, 2026, under
NIST's April 15, 2026 enrichment-prioritization policy) would score near
zero on identifiability by construction, because NVD no longer routinely
enriches most of them with `configurations`/CPE data. That would measure
NIST staffing policy, not disclosure quality -- the confound PR1 already
named as the reason for the three-era stratification.

## What the Week 3 V5 pivot changed about this split

The original design sketch (PR1 Methodology Paragraph Summary) assumed a
single frozen HTTP-style record carrying both the CNA-supplied view and the
NVD-enriched view, scored separately from the same file. Building
`src/corpus_filter_v5.py` falsified that assumption: **NVD's own enrichment
is not republished into CVE List V5.** Direct inspection of the 2024-2026
CVE List V5 corpus (142,781 records, `src/v5_corpus_pass.py`) found zero ADP
entries with `providerMetadata.shortName == "nvd@nist.gov"`, and
`cpeApplicability` appears in only ~0.5% of sampled CNA/ADP containers (and
even then, from CNAs who supply their own CPE data, e.g. Microsoft -- not
from NVD). So the split is architecturally forced to be **two separate
sources**, not two views of one file:

| Side | Source | Module | What it scores |
|---|---|---|---|
| **CNA-supplied** | CVE List V5 (`containers.cna`, plus non-NVD ADP entries like CISA-ADP) | `corpus_filter_v5.py`, `identifiability_scorer.score_*_v5()` | What the CNA itself published at disclosure time, present regardless of NVD's enrichment queue |
| **NVD-enriched** | NVD CVE API 2.0 (`configurations`/CPE) | `corpus_filter.py`, `identifiability_scorer.score_*_nvd()` | What NVD's analyst enrichment adds on top -- CPE applicability, version-range bounds, reference tagging |

## Scoring rule

Every corpus record is scored against **both** sides when both are
available (V5 always has a CNA container; NVD enrichment is present only
when `configurations` is non-empty). The two scores are reported **side by
side**, never averaged into one number:

- **Overall/backlog-era headline numbers use the CNA-supplied score.** It is
  present for every published CVE regardless of NVD's triage queue, so it is
  the only score that is comparable across all three eras without the
  triage-era selection artifact PR1's Preliminary Finding #2 already
  documented.
- **The NVD-enriched score is reported as a supplementary comparison**,
  specifically to show how much identifiability NVD's enrichment adds when
  it happens -- this is itself a finding (see `docs/v5_corpus_pass_2024_2026.md`
  and `docs/nvd_2024_onward_pass.md` for the population-level version of this
  comparison).
- **`vulnStatus` (NVD) and `cveMetadata.state` (V5) are recorded per record**
  as supplementary fields (decision D10), not used to gate inclusion --
  inclusion is decided by the CNA-side text/vendor rule
  (`corpus_filter_v5.classify()`) or the NVD-side CPE rule
  (`corpus_filter.classify()`), independently.

## Normalization, deduplication, conflict tiebreaker

- **Normalization:** vendor and product strings are lowercased and
  whitespace-collapsed before any comparison (both CNA `affected[].vendor`
  and NVD CPE vendor fields; CPE fields are already lowercase by
  convention, CNA-supplied strings are not). No cross-spelling-variant
  merge is performed at score time (the curated vendor list's own manual
  overrides are the only deduplication point -- see
  `docs/curated_vendor_list.md`).
- **Deduplication:** a CVE ID is the join key. A record with a CNA-side
  score and an NVD-side score is one row in the results table with two score
  columns, not two rows.
- **Conflict tiebreaker:** the CNA-side and NVD-side scores are allowed to
  disagree and are **not reconciled into a single number** -- disagreement
  itself is data (it is what "how much does NVD enrichment add" measures).
  The only place a single decision is required is corpus *membership*
  (in vs. out), and there the rule is a straight OR: a CVE is in the corpus
  if either `corpus_filter.classify()` (NVD/CPE path) or
  `corpus_filter_v5.classify()` (V5/CNA path) includes it. This is a
  deliberate widening from PR1's original NVD-only membership rule, and is
  the direct fix for the selection effect the V5 pivot targets.
