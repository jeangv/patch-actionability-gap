# The Patch Actionability Gap

Measuring whether public vulnerability disclosure enables remediation on
embedded and IoT devices. Georgia Tech OMS Cybersecurity practicum (CS 6727),
Fall 2026.

When a CVE is published for a home router or an IP camera, the record is
supposed to let the owner answer three questions: is my device affected, is
there a fix, and can I get it? This study scores the public record on those
three dimensions (**identifiability**, **fix availability**, **fix
obtainability**) for a frozen corpus of embedded and IoT CVEs drawn from NVD
and CVE List V5, and compares the results with a matched corpus of
general-purpose software.

## Research questions

- **RQ1.** What proportion of embedded/IoT CVE records contain sufficient
  version precision for a defender to determine affectedness?
- **RQ2.** What proportion of referenced advisories remain retrievable, and
  how does retrievability decay with the age of the disclosure?
- **RQ3.** Do actionability characteristics vary systematically across
  vendors, and can vendors be meaningfully ranked?
- **RQ4.** How does actionability for embedded/IoT vulnerabilities compare
  against a control corpus of general-purpose software vulnerabilities?

## Status (Week 6, October 2026)

| Stage | State |
|---|---|
| Scoring rubric v0.1 (Dimensions 1 to 3, 0/1/2 anchors) | Frozen; [docs/scoring_rubric_v0.1.md](docs/scoring_rubric_v0.1.md) |
| Corpus membership rules, both sources | Frozen, with logged corrections C1 to C4; [docs/design_decisions.md](docs/design_decisions.md) |
| Corpus freeze | Done: **21,990 CVEs**; [docs/corpus_freeze_results.md](docs/corpus_freeze_results.md) |
| Positive-control set | 46 controls; all 25 membership and scoring controls pass; [docs/positive_control_set.md](docs/positive_control_set.md) |
| Dimension 1 and 2 scorers | Implemented for both NVD and CVE List V5 records |
| Retrievability checker and Dimension 3 scorer | Week 7 |
| Crawl passes 1 and 2, control corpus, results script | Weeks 7 and 8 |

## The frozen corpus

Frozen 2026-09-28. A CVE is in the corpus if either source's rule admits it,
evaluated independently and combined by OR.

| | Records |
|---|---:|
| NVD path (CPE-based), of 397,944 CVEs crawled from 1999 on | 21,060 |
| CVE List V5 path (CNA vendor, product, and description text), of 391,971 records | 3,808 |
| Found by both | 2,878 |
| NVD only | 18,182 |
| CVE List V5 only | 930 |
| **Union** | **21,990** |

Results are split into three eras set by NVD policy dates: pre-2024, the
backlog era (2024 to February 2026), and the triage era (March 2026 on). The
CVE List V5-only share is 0.5%, 4.8%, and 37.7% across those eras, which is
why the study draws on both sources: since NIST's April 2026 change, NVD
enriches few consumer-device records, so an NVD-only corpus would be selected
on NVD's own triage decisions.

**Check it yourself.** [data/corpus_manifest.json](data/corpus_manifest.json)
holds the sorted ID list, its SHA-256, and the CVE List V5 commit
(`0fb6651236ba`). This should print `True`:

```powershell
python -c "import json,hashlib;m=json.load(open('data/corpus_manifest.json'));print(hashlib.sha256('\n'.join(m['ids']).encode()).hexdigest()==m['sha256_sorted_ids'])"
```

**Known limitation.** A hand check of random samples (AI-assisted, every call
reviewed; [docs/characterization_hand_check.md](docs/characterization_hand_check.md))
still finds about a third of NVD-only records out of scope, mostly phones and
industrial or medical equipment that vendor-level rules can't reach. Results
will be reported on the full corpus and on a description-screened subset.

## Corrections so far

The rules were locked at Progress Report 2. Everything changed after that is
logged rather than edited quietly:

- **C1.** The first V5 rule admitted a record on a vendor match alone, which
  let Microsoft, Google, Apple, IBM, and Dell in. It produced a headline
  figure (68% of the corpus found only by CVE List V5) that was retracted.
- **C2.** The V5 fix-availability scorer could never return 0.
- **C3.** The positive controls showed the corrected V5 rule missing routers
  whose descriptions never say "router"; a model-number clause fixed it.
- **C4.** The NVD rule's hardware and firmware clauses ignored the vendor
  exclusions, so chipset, enterprise, and industrial vendors got in. One
  28-vendor scope denylist ([src/scope_denylist.py](src/scope_denylist.py))
  now applies to both sources.

## Method in brief

1. **Corpus.** NVD API 2.0 for the CPE-based path; a local checkout of
   [CVE List V5](https://github.com/CVEProject/cvelistV5) for the CNA-text
   path. Soft exclusions keep industrial, medical, automotive, mobile, and
   general-purpose systems out.
2. **Scoring.** Each dimension scored 0, 1, or 2 against frozen anchors.
   NVD and CVE List V5 records are scored separately and reported side by
   side, because NVD does not republish its enrichment into CVE List V5.
3. **Retrievability.** Every reference URL is fetched and classified into a
   fixed outcome taxonomy ([docs/http_outcome_taxonomy.md](docs/http_outcome_taxonomy.md)),
   counting soft 404s and redirects to a site's home page as failures. Every
   response is archived so scores can be recomputed without crawling again.
4. **Validation.** The positive-control set runs before production scoring.
   Blind hand labels are compared with the script (Cohen's kappa, precision
   and recall per dimension), a subset is re-labeled later, and the URL set is
   crawled twice.

### Crawler conduct

The crawler declares an identifying user-agent, respects `robots.txt`, rate
limits per host with exponential backoff, fetches only public URLs already
published in CVE references, never logs in or gets around a WAF, and never
downloads firmware. Vendors that block automated requests are recorded as
their own outcome class, not counted as dead links.

## Repository layout

```
src/    pipeline code
docs/   design decisions, rubric, freeze results, controls, characterization
data/   corpus_manifest.json, curated_vendor_list.json, positive_controls.json,
        freeze/characterization_summary.json are committed; pulled records
        and freeze pass outputs are not (several hundred MB)
```

Main scripts:

| Script | What it does |
|---|---|
| `src/nvd_client.py` | NVD API 2.0 client: rate limits, retries, 120-day date windows |
| `src/corpus_filter.py` | NVD-path membership rule (CPE-based) |
| `src/corpus_filter_v5.py` | CVE List V5-path membership rule (version 3) |
| `src/scope_denylist.py` | Vendor scope denylist used by both rules |
| `src/soft_exclusions.py` | Out-of-scope category patterns |
| `src/identifiability_scorer.py` | Dimension 1 and 2 scorers for both sources |
| `src/response_class.py` | Maps scores to a recommended response (patch, escalate, mitigate, replace) |
| `src/build_positive_controls.py` | Runs the positive-control set |
| `src/freeze_v5_pass.py`, `src/freeze_nvd_pass.py` | Full passes over each source |
| `src/freeze_manifest.py` | Unions the passes and writes the manifest, rankings, and samples |

## Reproducing the freeze

```powershell
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
copy .env.example .env    # set NVD_API_KEY and V5_REPO_DIR
.venv\Scripts\python src\build_positive_controls.py
.venv\Scripts\python src\freeze_v5_pass.py     # about 20 minutes
.venv\Scripts\python src\freeze_nvd_pass.py    # about 2 hours
.venv\Scripts\python src\freeze_manifest.py
```

Python 3.14.3; dependencies pinned in [requirements.txt](requirements.txt).
An NVD API key is free at https://nvd.nist.gov/developers/request-an-api-key.
`V5_REPO_DIR` points at a local clone of CVE List V5 checked out at commit
`0fb6651236ba3f33f5a6416447cde620a4842716`. Re-running the NVD pass on a later
date will pick up newer CVEs, so the manifest above, not a re-run, defines the
study's corpus.
