# Response-Class Mapping -- Provisional Pilot Run

**Provisional, not the response-routing evaluation.** Dimension 3 (fix obtainability) is not implemented until Week 6, and end-of-life detection is not implemented at all yet (PR1 already names this as the hardest input). Every record here is scored with `fix_obtainability_score=None, eol=None`, so results collapse to two classes: `FIX_OBTAINABLE` (provisional -- fix availability scored 2, obtainability not yet verified) and `NO_FIX_EOL_UNKNOWN`. This run exists to show `response_class.classify_response()` runs end to end against real records, not to report a response-routing finding.

| Era | n | FIX_OBTAINABLE (provisional) | NO_FIX_EOL_UNKNOWN |
|---|---:|---:|---:|
| pre-2024 | 67 | 14 | 53 |
| backlog era | 67 | 1 | 66 |
| triage era | 66 | 1 | 65 |
| **Overall** | **200** | **16** | **184** |

**184 of 200 records (92.0%) would route to a non-patch response under this provisional mapping** -- read as an upper bound before Dimension 3 and EOL detection exist, since some of the 16 provisional FIX_OBTAINABLE records will likely fail obtainability once Dimension 3 is scored, which would move them into a non-patch class too. The real response-routing evaluation (PR1 Evaluation #6) is scheduled Week 9.
