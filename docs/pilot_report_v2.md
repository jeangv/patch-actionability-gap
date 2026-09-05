# Pilot Slice Report v2 (window-distributed sampling)

Retrieved: 2026-09-05T01:01:42+00:00 from the NVD CVE API 2.0.

## ⚠ Selection-effect limitation (read before interpreting per-era percentages)

Every record in this report has `configurations` present **by construction** -- the corpus inclusion rule (`corpus_filter.classify()`) requires a CPE match, which lives inside `configurations`. Since 2026-04-15 NIST has only routinely enriched CVEs on the CISA KEV list, federal-government software, and EO 14028 critical software with `configurations` data (NVD's stated triage-era policy). **The triage-era stratum here is therefore selected by NVD's enrichment priority list, not by device type.** This is almost certainly why triage-era field-population percentages beat backlog-era percentages on every metric below -- it is a selection artifact of the sampling method, not a finding about triage-era CVE quality or about vendors being more forthcoming post-triage. **Do not report "triage era looks better than backlog era" as a substantive result.**

**v2 vs v1 sampling fix:** v1 scanned each era's date windows most-recent-first and stopped once the quota was met, which clustered every era's sample into a single narrow date range instead of spreading it across the era (measured with `src/date_span.py` against the v1 data: pre-2024 spanned only 2023-10-06..2023-10-11, backlog only 2025-12-15..2025-12-22, triage only 2026-06-29..2026-07-14 -- see `docs/pilot_report_v1.md`). v2 fixes this by distributing each era's quota across its sampled 120-day windows and drawing from every window -- see "Sampling method" below.

**v1 vs v0 rule fix (unchanged in v2):** v0 required `part:h` marked `vulnerable: true`, a convention NVD stopped using for embedded devices around 2011. v1/v2 match `part:h` anywhere regardless of the `vulnerable` flag (Include A), plus `part:o` CPEs whose product ends in `_firmware` (Include C). See `src/corpus_filter.py`.

**Still not applied:** Include B (part:o/part:a + curated vendor + model-designator pattern) -- no curated vendor list yet. Soft exclusion categories (enterprise datacenter networking/server platforms, ICS, medical devices, automotive, mobile handsets, general-purpose computers) -- explicitly deferred to Week 4 by the project owner, not a blocker. Numbers below may still include some of those categories.

**Ambiguity list** (matched both an inclusion and the implemented exclusion criteria, resolved as excluded per the tiebreaker rule): 0 record(s). Full list: `data/pilot_20260905_v2/ambiguous.json`.

## Sampling method

- **backlog era & triage era:** every 120-day window in the era's date range is sampled; the era's quota is distributed across windows proportionally to window length in days (largest-remainder allocation), then each window is scanned for its own allocated share.
- **pre-2024:** spans 25 calendar years (1999-2023) as ~76 full 120-day windows -- scanning all of them was judged impractical for a pilot slice. Instead, one representative 120-day window per calendar year is sampled (Jan 1 through Jan 1 + 119 days of that year), and the quota is split into an **equal** share per year (not proportional to day count, since every sampled window is the same length). This means pre-2024 coverage is Jan-Apr-biased within each year, not full-year-uniform -- a documented compromise, not a claim of uniform annual coverage. In practice (see the date-span table below), every sampled year's quota was filled from within January alone before the scan ever reached February -- so the 25 distinct year-months in this run are 25 Januarys, not a Jan-Apr spread. This is a further, empirically-observed narrowing on top of the documented Jan-Apr compromise, not a separate bug.
- A window that can't fill its allocated share is a per-window shortfall, reported below, not padded from another window.
- **Scan:collect ratio** (CVEs scanned / records collected) is reported per window as a standing diagnostic: a rising ratio across an era's windows signals matching CVEs are getting harder to find (enrichment lag), not that the filter changed.

### Sampling windows, per era


**pre-2024**

| Window | Target | Collected | Scanned | Scan:Collect ratio |
|---|---:|---:|---:|---:|
| 1999-01-01 .. 1999-04-30 | 3 | 3 | 165 | 55.0:1 |
| 2000-01-01 .. 2000-04-29 | 3 | 3 | 66 | 22.0:1 |
| 2001-01-01 .. 2001-04-30 | 3 | 3 | 4 | 1.3:1 |
| 2002-01-01 .. 2002-04-30 | 3 | 3 | 4 | 1.3:1 |
| 2003-01-01 .. 2003-04-30 | 3 | 3 | 11 | 3.7:1 |
| 2004-01-01 .. 2004-04-29 | 3 | 3 | 19 | 6.3:1 |
| 2005-01-01 .. 2005-04-30 | 3 | 3 | 253 | 84.3:1 |
| 2006-01-01 .. 2006-04-30 | 3 | 3 | 230 | 76.7:1 |
| 2007-01-01 .. 2007-04-30 | 3 | 3 | 153 | 51.0:1 |
| 2008-01-01 .. 2008-04-29 | 3 | 3 | 249 | 83.0:1 |
| 2009-01-01 .. 2009-04-30 | 3 | 3 | 23 | 7.7:1 |
| 2010-01-01 .. 2010-04-30 | 3 | 3 | 63 | 21.0:1 |
| 2011-01-01 .. 2011-04-30 | 3 | 3 | 23 | 7.7:1 |
| 2012-01-01 .. 2012-04-29 | 3 | 3 | 72 | 24.0:1 |
| 2013-01-01 .. 2013-04-30 | 3 | 3 | 108 | 36.0:1 |
| 2014-01-01 .. 2014-04-30 | 3 | 3 | 61 | 20.3:1 |
| 2015-01-01 .. 2015-04-30 | 3 | 3 | 143 | 47.7:1 |
| 2016-01-01 .. 2016-04-29 | 2 | 2 | 91 | 45.5:1 |
| 2017-01-01 .. 2017-04-30 | 2 | 2 | 61 | 30.5:1 |
| 2018-01-01 .. 2018-04-30 | 2 | 2 | 151 | 75.5:1 |
| 2019-01-01 .. 2019-04-30 | 2 | 2 | 33 | 16.5:1 |
| 2020-01-01 .. 2020-04-29 | 2 | 2 | 11 | 5.5:1 |
| 2021-01-01 .. 2021-04-30 | 2 | 2 | 36 | 18.0:1 |
| 2022-01-01 .. 2022-04-30 | 2 | 2 | 51 | 25.5:1 |
| 2023-01-01 .. 2023-04-30 | 2 | 2 | 80 | 40.0:1 |

**backlog era (2024-Feb 2026)**

| Window | Target | Collected | Scanned | Scan:Collect ratio |
|---|---:|---:|---:|---:|
| 2024-01-01 .. 2024-04-29 | 10 | 10 | 27 | 2.7:1 |
| 2024-04-29 .. 2024-08-26 | 10 | 10 | 490 | 49.0:1 |
| 2024-08-26 .. 2024-12-23 | 10 | 10 | 87 | 8.7:1 |
| 2024-12-23 .. 2025-04-21 | 10 | 10 | 212 | 21.2:1 |
| 2025-04-21 .. 2025-08-18 | 10 | 10 | 118 | 11.8:1 |
| 2025-08-18 .. 2025-12-15 | 10 | 10 | 106 | 10.6:1 |
| 2025-12-15 .. 2026-02-28 | 7 | 7 | 30 | 4.3:1 |

**triage era (Mar 2026-)**

| Window | Target | Collected | Scanned | Scan:Collect ratio |
|---|---:|---:|---:|---:|
| 2026-03-01 .. 2026-06-28 | 42 | 42 | 129 | 3.1:1 |
| 2026-06-28 .. 2026-09-05 | 24 | 24 | 1558 | 64.9:1 |

## Date span, per era (post-fix check)

| Era | n | Min published | Max published | Distinct months |
|---|---:|---|---|---:|
| pre-2024 | 67 | 1999-01-01 | 2023-01-02 | 25 |
| backlog era (2024-Feb 2026) | 67 | 2024-01-02 | 2025-12-15 | 8 |
| triage era (Mar 2026-) | 66 | 2026-03-01 | 2026-07-03 | 3 |

## Rule-tag breakdown (before/after comparison)

A CVE can match more than one tag; counts are of collected (included) records only and do not need to sum to the totals above.

| Rule tag | pre-2024 | backlog era | triage era | Overall |
|---|---:|---:|---:|---:|
| `h_any` | 62 | 65 | 66 | 193 |
| `h_vulnerable_true` | 43 | 0 | 0 | 43 |
| `o_firmware` | 21 | 55 | 30 | 106 |
| `include_b_vendor_pattern` | 0 | 0 | 0 | 0 |

## `vulnStatus` distribution, per era (counts only -- not yet interpreted)

Recorded to check whether `configurations` presence on triage-era records reflects NVD analyst enrichment (`vulnStatus` = `Analyzed` / `Modified`) or CNA-supplied `cpeApplicability` data present regardless of NVD's analysis queue (`Awaiting Analysis` / `Undergoing Analysis` / `Received` / `Deferred`). **These are raw counts only; no interpretation is drawn here, and the "Selection-effect limitation" note above is deliberately NOT revised based on this table until it has been reviewed.**

| vulnStatus | pre-2024 | backlog era | triage era | Overall |
|---|---:|---:|---:|---:|
| Analyzed | 1 | 54 | 48 | 103 |
| Modified | 66 | 13 | 17 | 96 |
| Undergoing Analysis | 0 | 0 | 1 | 1 |

## Target vs. achieved, per era

| Era | Target | Collected | CVEs scanned to find them |
|---|---:|---:|---:|
| pre-2024 | 67 | 67 | 2161 |
| backlog era (2024-Feb 2026) | 67 | 67 | 1070 |
| triage era (Mar 2026-) | 66 | 66 | 1687 |
| **Total** | **200** | **200** | |

## Field population -- overall

*`CVSS: CNA-supplied present` and `CVSS: NVD-added present` are intentionally omitted from this aggregate -- both are era-confounded (see "CVSS field population" below) and a single overall percentage for them is not meaningful.*

| Field | % of collected records |
|---|---:|
| cpeMatch/configurations present | 100.0% |
| versionEndExcluding/Including present | 34.0% |
| versionStartExcluding/Including present | 11.0% |
| CPE part:h present | 96.5% |
| references non-empty | 100.0% |
| Patch/Vendor Advisory reference tag present | 56.5% |

## CVSS field population (era-confounded -- per-era only)

No overall aggregate is reported for these two fields: CNA-supplied CVSS is structurally near-zero for pre-2016 records because CNAs did not begin routinely supplying CVSS scores until later in the CVE program's history, and NVD-added CVSS is near-100% for old records because of retroactive scoring. Neither pattern is a finding about embedded/IoT vendors or device types -- both are artifacts of when a record was published, so they are only meaningful read per era.

| Era | CVSS: CNA-supplied present | CVSS: NVD-added present |
|---|---:|---:|
| pre-2024 | 7.5% | 100.0% |
| backlog era (2024-Feb 2026) | 100.0% | 47.8% |
| triage era (Mar 2026-) | 100.0% | 40.9% |

## Field population -- by era

*CVSS fields are omitted here -- see "CVSS field population" above, which already reports these two fields per era.*


### pre-2024 (n=67)

| Field | % |
|---|---:|
| cpeMatch/configurations present | 100.0% |
| versionEndExcluding/Including present | 28.4% |
| versionStartExcluding/Including present | 4.5% |
| CPE part:h present | 92.5% |
| references non-empty | 100.0% |
| Patch/Vendor Advisory reference tag present | 53.7% |

### backlog era (2024-Feb 2026) (n=67)

| Field | % |
|---|---:|
| cpeMatch/configurations present | 100.0% |
| versionEndExcluding/Including present | 31.3% |
| versionStartExcluding/Including present | 6.0% |
| CPE part:h present | 97.0% |
| references non-empty | 100.0% |
| Patch/Vendor Advisory reference tag present | 43.3% |

### triage era (Mar 2026-) (n=66)

| Field | % |
|---|---:|
| cpeMatch/configurations present | 100.0% |
| versionEndExcluding/Including present | 42.4% |
| versionStartExcluding/Including present | 22.7% |
| CPE part:h present | 100.0% |
| references non-empty | 100.0% |
| Patch/Vendor Advisory reference tag present | 72.7% |
