# Design Decisions D1-D10 (Accepted)

Per `2026-09-20_Progress Report 2/PR2_Working_State.md` Section 3, every
decision's stated recommendation is adopted as the project owner's decision,
effective at this Week 3/4 design-lock pass. This file is the durable record
of that acceptance and where each decision landed in code/docs.

| # | Decision | Accepted resolution | Landed in |
|---|---|---|---|
| **D1** | Pre-2011 handling | Retain in corpus; CPE-convention era carried as an explicit covariate; reported as a separately labeled stratum in every results table; **excluded from the pooled RQ3 vendor ranking** and reported as a separate pre-2011 vendor ranking. Rationale: RQ2 (retrievability decay vs. disclosure age) needs the oldest records as its independent variable -- dropping them removes the thing being measured. RQ3 (vendor ranking) is the only place the like-for-like objection actually bites. | `docs/methodology_note_and_node_convention.md` (existing per-year breakdown is the covariate data); corpus freeze manifest marks the pre-2011/2011+ boundary explicitly (`docs/corpus_freeze_manifest.md`) |
| **D2** | Vendor naming in the scorecard | Publish vendor names, with three guardrails: (1) a "what this does not measure" statement next to the table -- the score grades disclosure metadata, not firmware quality or device engineering; (2) minimum-N suppression with per-vendor sample size shown (D6, N >= 10); (3) ranking-sensitivity-under-reweighting reported (Week 9), a vendor whose rank inverts under reweighting reported as unrankable. | Guardrail 1 stated in this file and to be restated in PR2/final report scorecard section; guardrails 2-3 scheduled per D6 and the Week 9 evaluation plan |
| **D3** | Metric rename | Keep "patch actionability" as the construct name (used in RQ1-RQ4 as already affirmed by faculty). Rename only the published per-vendor artifact if a rename is wanted later -- not decided now, no rename applied at design lock. | No code/doc change; construct name unchanged everywhere |
| **D4** | Archive-recoverable advisories | Obtainability (Dimension 3) scored on live vendor infrastructure only. Archive availability recorded as a separate field, not a passing score. | `docs/http_outcome_taxonomy.md` ("D4 -- archive-recoverable advisories") |
| **D5** | Advisory live, firmware artifact gone | Resolved on the 0/1/2 scale: 2 = advisory live and fixed firmware reachable; 1 = advisory live, firmware unreachable/gated; 0 = advisory unreachable. Reachability only, no firmware downloads. | `docs/http_outcome_taxonomy.md` ("D5"); `docs/scoring_rubric_v0.1.md` Dimension 3 |
| **D6** | Vendor minimum-N threshold | Fixed at design lock, before results are visible: **N >= 10** scored CVEs to appear in the per-vendor ranking; vendors below the threshold reported as an aggregate "insufficient sample" row with the count. | Recorded here; applied at Week 8 scorecard computation (not yet run -- corpus not scored end to end) |
| **D7** | Control corpus matching | Match the general-purpose control corpus on publication-date distribution across the three eras AND on CVSS severity distribution. Added to the Week 4 freeze (the freeze as originally scoped covered only the embedded corpus). | `docs/corpus_freeze_manifest.md` ("Control corpus matching variables") |
| **D8** | Field-level identifiability | Metric unchanged. Routed to the stakeholder scenario table as a new column ("can this class determine its installed firmware version?") and to Threats to Validity. | `docs/stakeholder_scenario_table.md` |
| **D9** | Freeze verifiability | Commit a CVE ID manifest, a SHA-256 over the sorted ID list, and the CVE List V5 source commit hash. | `docs/corpus_freeze_manifest.md` |
| **D10** | Enrichment status | Record `nvd_enriched` (derived: `configurations` non-empty) and `vulnStatus` (NVD) / `cveMetadata.state` (V5) per record at collection, as supplementary fields -- not used to gate inclusion. | `docs/cna_vs_nvd_scoring_split.md` |

## Post-lock corrections (Week 5)

The rule itself was frozen at PR2. What follows are bug fixes in how the
code implemented it, found by peer review on Video 2.

| # | Correction | What changed | Landed in |
|---|---|---|---|
| **C1** | V5-path inclusion rule was looser than the NVD path | v1 admitted a record on a curated-vendor match alone, or on a category keyword alone. v2 needs a firmware-suffixed product, or a curated vendor and a category keyword together, which is what Include B already required on the NVD side. Microsoft, IBM, Dell, Google, and Apple went on the manual exclusion list after every sampled post-fix match from them turned out to be enterprise software or mobile OS records. The 2024 to 2026 V5-only share dropped from the 68% reported in PR2 to 3.1% (281 of 8,969). Raised by Monika Schrenk (Sep 23), with Travis Carlisle, JP Valentine, Albert Dinh, and Mizanur Rahman independently flagging the overlap. | `src/corpus_filter_v5.py`, `src/build_curated_vendor_list.py`, `docs/v5_vs_nvd_exclusion_count.md` |
| **C2** | `score_fix_availability_v5` could never return 0 | Score 1 fired whenever a record had any reference at all. It now needs a `vendor-advisory` tag or fix language, matching the NVD scorer. No published number used this function, so nothing reported had to be restated. Raised by Monika Schrenk. | `src/identifiability_scorer.py` |

## PR1 open questions closed by this pass

Per `PR2_Working_State.md` Section 4:

- **Two-part inclusion rule / pre-2011 exclude-vs-covariate:** closed by
  peers at D1; no reviewer objected to the two-part rule itself.
- **Three-era stratification -- strength or distraction:** closed by peers;
  no reviewer called it a distraction, and Mizanur's RQ4-bias argument
  (differential NVD attention between IoT and general-purpose records would
  bias RQ4 specifically if corpus membership stayed NVD-API-based)
  strengthens the case for it. The V5 pivot (this pass) is the direct
  response to that argument.
- **Per-vendor scorecard -- acceptable deliverable:** closed by peers, 4:1
  for publication with the D2 guardrails.
- **Stakeholder-analysis evidence depth** and **inter-rater reliability
  substitute (no second labeler)**: still open, raised again in PR2 Section 7
  for faculty, since PR4 (Oct 18) is the results deadline and the labeling
  decision affects Week 6 scheduling.
