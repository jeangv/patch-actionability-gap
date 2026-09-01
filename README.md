# The Patch Actionability Gap

Measuring whether public vulnerability disclosure enables remediation on embedded
and IoT devices. Georgia Tech OMS Cybersecurity practicum (CS 6727) capstone
project.

This is a data-driven measurement study that scores embedded/IoT CVE records on
three dimensions — **identifiability**, **fix availability**, and **fix
obtainability** — using a Python pipeline over NVD (National Vulnerability
Database) and CVE List V5 data, compared against a general-purpose-software
control corpus.

## Research questions

- **RQ1.** What proportion of embedded/IoT CVE records contain sufficient version
  precision for a defender to determine affectedness?
- **RQ2.** What proportion of referenced advisories remain retrievable, and how does
  retrievability decay with the age of the disclosure?
- **RQ3.** Do actionability characteristics vary systematically across vendors, and
  can vendors be meaningfully ranked?
- **RQ4.** How does actionability for embedded/IoT vulnerabilities compare against a
  control corpus of general-purpose software vulnerabilities?

## Methodology (summary)

1. **Corpus Collection** — gather NVD bulk JSON feeds and CVE List V5 records,
   filter for embedded/IoT products using CPE hardware designators (`part:h`) plus
   a curated vendor list, build a matched general-purpose control corpus.
2. **Scoring** — computed separately over CNA-supplied data and over NVD-enriched
   data (see note below).
3. **Retrievability checking** — over disclosure references (see note below).
4. **Per-vendor aggregation.**
5. **Cross-corpus comparison** against the general-purpose control corpus.

Results are stratified across three eras: **pre-2024**, **backlog era
(2024–Feb 2026)**, and **triage era (Mar 1 2026 onward)**.

### CNA vs. NVD split

As of April 15, 2026, NIST limits routine NVD enrichment to CVEs in the CISA KEV,
federal-government software, and EO 14028 critical software — nearly all
consumer/SMB embedded-device CVEs fall outside those categories. Without the
CNA-vs-NVD split, records published after March 1, 2026 (the "triage era") would
score near zero on identifiability by construction, which would measure NIST
staffing rather than actual disclosure quality.

### Retrievability checking ground rules

Retrievability checking touches live vendor infrastructure. The crawler declares an
identifying user-agent, respects `robots.txt`, applies conservative rate limiting
with exponential backoff, retrieves only publicly reachable URLs already published
in CVE references, never attempts auth bypass or WAF circumvention, and never
downloads firmware binaries. Blocked/unreachable vendors are logged as a distinct
outcome class, not silently dropped.

## Project structure

```
/src   - pipeline code
/data  - pulled records (gitignored; a decision on committing any subset is pending)
/docs  - documentation
```

## Environment

- Python 3.14.3
- Dependencies pinned in [requirements.txt](requirements.txt)

```powershell
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
```

## Status

Project scaffold only. Pipeline stages are implemented incrementally; see commit
history for progress.
