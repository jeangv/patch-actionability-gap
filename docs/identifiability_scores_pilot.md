# Identifiability + Fix-Availability Scores -- 200-Record Pilot Slice (NVD path)

Dimensions 1 (identifiability) and 2 (fix availability) of `docs/scoring_rubric_v0.1.md`, scored against the same `data/pilot_20260905_v2/` slice reported in `docs/pilot_report_v2.md`. Dimension 3 (fix obtainability) is not scored here -- it requires the Week 6 retrievability checker.

## Identifiability -- score distribution

| Era | n | Score 0 | Score 1 | Score 2 | Mean |
|---|---:|---:|---:|---:|---:|
| pre-2024 | 67 | 15 | 6 | 46 | 1.46 |
| backlog era | 67 | 1 | 15 | 51 | 1.75 |
| triage era | 66 | 4 | 11 | 51 | 1.71 |
| **Overall** | **200** | **20** | **32** | **148** | **1.64** |

## Fix availability -- score distribution

| Era | n | Score 0 | Score 1 | Score 2 | Mean |
|---|---:|---:|---:|---:|---:|
| pre-2024 | 67 | 31 | 22 | 14 | 0.75 |
| backlog era | 67 | 37 | 29 | 1 | 0.46 |
| triage era | 66 | 18 | 47 | 1 | 0.74 |
| **Overall** | **200** | **86** | **98** | **16** | **0.65** |

## Worked examples, one per identifiability score (first match found)

- **Score 0:** CVE-1999-0453: every matching CPE has an unbounded version (`*`/`-`) and no range bounds
- **Score 1:** CVE-2012-0695: half-bounded version range on cpe:2.3:o:google:chrome_os:*:*:*:*:*:*:*:*
- **Score 2:** CVE-2000-0005: exact version string in CPE criteria: cpe:2.3:o:hp:hp-ux:7.00:*:*:*:*:*:*:*
