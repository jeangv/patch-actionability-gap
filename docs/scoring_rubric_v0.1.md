# Patch Actionability Scoring Rubric v0.1 (Design Lock)

**This is the design lock document.** Per the Week 4 milestone, the metric defined
here does not change after Progress Report 2 (September 20, 2026). Anything
found wrong after this point is a documented limitation on the frozen metric,
not a revision to it.

Every CVE record receives three independent 0/1/2 scores -- **identifiability**,
**fix availability**, **fix obtainability** -- plus a composite (sum, 0-6) used
only for the sensitivity analysis (Week 9); the three dimensions are always
reported separately first, per PR1's evaluation plan.

A record is scored twice when both sources are available for it: once against
its NVD API record (CPE-based fields) and once against its CVE List V5 record
(CNA-supplied fields). The two scores are never averaged or combined into one
number -- see `docs/cna_vs_nvd_scoring_split.md` for why, and D10.

---

## Dimension 1: Identifiability

*Can a defender determine whether their specific device and firmware version
are affected?*

### NVD-path anchors (CPE-based)

| Score | Anchor | Rule |
|---|---|---|
| **0** | No structured affectedness data, or an unbounded version wildcard | `configurations` absent, OR every matching `cpeMatch` entry has no `versionStartIncluding/Excluding` and no `versionEndIncluding/Excluding` (i.e. the CPE names a product but not a version range -- version field is `*` or `-`) |
| **1** | Half-bounded version range | At least one matching `cpeMatch` entry has a `versionEnd*` (or `versionStart*`) bound but not both -- a defender can rule some versions out but not draw a precise affected boundary on both sides |
| **2** | Fully-bounded version range, or an exact single version | At least one matching `cpeMatch` entry has both a start and an end bound, OR the CPE's version component itself is a specific version string (not `*`/`-`) |

**Worked examples** (drawn from the existing 200-record pilot slice,
`data/pilot_20260905_v2/`; chosen to illustrate the field pattern, not
because every vendor shown is in the final curated corpus):

- **Score 0 -- CVE-1999-0453** (Cisco router, pre-2024 stratum). Matching CPE:
  `cpe:2.3:h:cisco:router:*:*:*:*:*:*:*:*`. Every version-related field is `*`.
  The record says "a Cisco router" and nothing else -- no defender can tell
  whether their specific model/IOS version is affected from this record alone.
- **Score 1 -- CVE-2012-0695** (Chrome OS on the Acer AC700, Samsung Series
  5, and Cr-48 Chromebooks). The only versioned CPE is
  `cpe:2.3:o:google:chrome_os:*:*:*:*:*:*:*:*` with
  `versionEndIncluding: 17.0.963.26`; the three hardware CPEs are wildcards.
  A defender knows anything at or below 17.0.963.26 is affected, but there is
  no lower bound.

  *Corrected 2026-09-27.* v0.1 used CVE-2009-5037 here. The positive-control
  run showed that record also lists dozens of exact ASA versions, which the
  rubric's own score-2 rule ("an exact, non-wildcard version string") scores
  as 2, and the scorer agreed with the rubric. The example was wrong, not the
  rule, so only the example changed.
- **Score 2 -- CVE-2026-13050** (WatchGuard Fireware, triage era). Matching CPE:
  `cpe:2.3:o:watchguard:fireware:*:*:*:*:*:*:*:*` with `versionStartIncluding:
  12.0`, `versionEndExcluding: 12.12.1` (and three more bounded ranges for
  other release trains). A defender on 12.5 can determine affectedness
  directly from the record.

### CVE List V5-path anchors (CNA `affected[].versions[]`-based)

CVE List V5's CNA container almost never carries a CPE (see
`src/corpus_filter_v5.py` docstring); instead each `affected[]` entry carries
a bare `product`/`vendor` string and a `versions[]` array of
`{version, status}` (and sometimes `versionType`, `lessThan`/`lessThanOrEqual`
range objects). The construct is the same -- can a defender pin down whether
their version is in the affected set -- but the anchors are read off a
different field shape:

| Score | Anchor | Rule |
|---|---|---|
| **0** | No usable version data | `versions[]` empty or absent, OR every entry's `version` is a placeholder (`"0"`, `"unspecified"`, `"n/a"`, `"*"`) with no `lessThan`/`lessThanOrEqual` range |
| **1** | A single affected version pinned, but no stated range or fixed boundary | At least one entry has a concrete `version` string with `status: "affected"`, but no `versions[].lessThan`/`lessThanOrEqual` accompanies it -- a defender on that exact build can confirm affectedness, but a defender on a nearby build cannot |
| **2** | A bounded range or an explicit affected/unaffected version pair | At least one `affected[]` entry supplies both a `status:"affected"` version (or range start) and a `lessThan`/`lessThanOrEqual` upper bound, OR both an `affected` and the corresponding `unaffected` (fixed) version are present for the same product |

Worked example (Tenda A15, `CVE-2024-0531`, inspected directly from
`cves/2024/0xxx/CVE-2024-0531.json` during the V5 pivot build): `affected[0]`
lists `version: "15.13.07.13", status: "affected"` with no `lessThan` --
**score 1**: a defender running exactly that build can confirm affectedness,
but the record gives no signal for any other build.

---

## Dimension 2: Fix availability

*Does the record establish that a fix exists and identify it?*

| Score | Anchor | Rule |
|---|---|---|
| **0** | No fix signal | No reference tagged `Patch` or `Vendor Advisory` (NVD path) / no reference with `tags` containing `patch` (V5 path), AND the English description contains no fix-language pattern (`fixed in`, `patched in`, `upgrade to`, `update to version`) |
| **1** | Fix implied but not pinned to a version | A `Vendor Advisory` reference exists, or the description uses fix language, but no specific fixed version/build is named anywhere in the record (e.g. "contact vendor for a fix" or "upgrade to the latest firmware") |
| **2** | Fix explicitly identified | A `Patch` reference exists, OR the description/CPE data names a specific fixed version (the NVD-path `versionEnd*Excluding` boundary itself is read as "fixed as of this version" when paired with a `Patch`/`Vendor Advisory` reference, per D4/D5) |

Worked example -- score 2: **CVE-2002-1595** (Cisco, pre-2024 stratum) carries
a reference tagged `Patch` pointing to
`http://www.cisco.com/warp/public/707/SN-multiple-pub.shtml`, a named
advisory identifying the fix. Worked example -- score 0: **CVE-1999-0453**
carries only an X-Force cross-reference with no `Patch`/`Vendor Advisory` tag
and no fix language in the description.

---

## Dimension 3: Fix obtainability

*Is the referenced advisory or firmware still retrievable today?*

Scored per the HTTP outcome taxonomy in `docs/http_outcome_taxonomy.md` and
decisions D4/D5:

| Score | Anchor | Rule |
|---|---|---|
| **0** | Advisory unreachable | The advisory/patch reference URL resolves to a hard 404, soft 404, DNS failure, or TLS failure, AND no archived copy (Wayback/Memento) is found either (D4) |
| **1** | Advisory reachable, fix artifact is not | Advisory URL is live (200, or archived with the archive noted per D4), but: (a) it is gated behind a login/support-contract wall, or (b) it names a firmware file that itself 404s or is not offered for download, or (c) the advisory is only reachable via archive (never live) |
| **2** | Advisory and fix artifact both reachable | Advisory URL is live AND, where the advisory names a specific firmware/patch file, that file's URL is also live (reachability only -- the crawler never downloads firmware binaries, per PR1's retrievability ground rules) |

This dimension is not scored against the pilot slice yet -- it requires the
retrievability checker (Week 6, `src/http_retrievability.py`, not yet built).
Dimensions 1 and 2 are implemented now (`src/identifiability_scorer.py`);
Dimension 3's rubric is frozen here so it does not change later, but its
*implementation* is still on schedule for Week 6 per the original timeline.

---

## Composite score

Sum of the three dimensions, range 0-6, reported only in the Week 9
sensitivity analysis (alternative weightings) and never as the headline
number -- PR1 and PR2 both report the three dimensions separately, per
D2's guardrail and the existing evaluation plan.
