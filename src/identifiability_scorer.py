"""Week 3 task (W3.4): identifiability and fix-availability scorers,
implementing Dimensions 1 and 2 of docs/scoring_rubric_v0.1.md.

Two independent scorers, one per source schema (see the rubric doc for why
they read different fields):

  - score_identifiability_nvd(cve) / score_fix_availability_nvd(cve): NVD
    API record, CPE-based (`configurations` / `cpeMatch`).
  - score_identifiability_v5(record) / score_fix_availability_v5(record):
    CVE List V5 record, CNA-`affected[].versions[]`-based.

Dimension 3 (fix obtainability) is not implemented here -- it needs the
Week 6 retrievability checker; see the rubric doc.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

FIX_LANGUAGE_RE = re.compile(
    r"\b(fixed in|patched in|upgrade to|update to version|resolved in|"
    r"has been fixed|has been patched)\b",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# NVD path (CPE-based)
# ---------------------------------------------------------------------------

def _cpe_match_entries(cve: dict):
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for m in node.get("cpeMatch", []):
                yield m


def _cpe_version_from_criteria(criteria: str) -> str | None:
    parts = criteria.split(":")
    # cpe:2.3:part:vendor:product:version:update:...
    if len(parts) > 5:
        return parts[5]
    return None


def score_identifiability_nvd(cve: dict) -> tuple[int, str]:
    matches = list(_cpe_match_entries(cve))
    if not matches:
        return 0, "no configurations/cpeMatch entries"

    best_score = 0
    best_reason = "every matching CPE has an unbounded version (`*`/`-`) and no range bounds"

    for m in matches:
        start = m.get("versionStartIncluding") or m.get("versionStartExcluding")
        end = m.get("versionEndIncluding") or m.get("versionEndExcluding")
        version = _cpe_version_from_criteria(m.get("criteria", ""))
        has_explicit_version = version not in (None, "*", "-")

        if start and end:
            return 2, f"fully-bounded version range on {m.get('criteria')}"
        if has_explicit_version and not (start or end):
            # exact version string in the CPE itself counts as score 2 per rubric
            return 2, f"exact version string in CPE criteria: {m.get('criteria')}"
        if start or end:
            if best_score < 1:
                best_score, best_reason = 1, f"half-bounded version range on {m.get('criteria')}"

    return best_score, best_reason


def score_fix_availability_nvd(cve: dict) -> tuple[int, str]:
    has_patch_tag = False
    has_advisory_tag = False
    for ref in cve.get("references", []):
        tags = ref.get("tags", []) or []
        if "Patch" in tags:
            has_patch_tag = True
        if "Vendor Advisory" in tags:
            has_advisory_tag = True

    desc = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break
    has_fix_language = bool(FIX_LANGUAGE_RE.search(desc))

    if has_patch_tag:
        return 2, "reference tagged Patch"
    if has_advisory_tag or has_fix_language:
        return 1, "Vendor Advisory reference or fix language present, no Patch-tagged reference"
    return 0, "no Patch/Vendor Advisory reference and no fix language in description"


# ---------------------------------------------------------------------------
# CVE List V5 path (CNA affected[].versions[]-based)
# ---------------------------------------------------------------------------

PLACEHOLDER_VERSIONS = {"0", "unspecified", "n/a", "*", "-", ""}


def score_identifiability_v5(record: dict) -> tuple[int, str]:
    cna = record.get("containers", {}).get("cna", {})
    affected = cna.get("affected", [])
    if not affected:
        return 0, "no affected[] entries in CNA container"

    best_score = 0
    best_reason = "every affected[] entry has only placeholder/unspecified version data"
    has_any_concrete_version = False

    for a in affected:
        versions = a.get("versions", [])
        statuses = {v.get("status") for v in versions}
        affected_versions = [v for v in versions if v.get("status") == "affected"]
        unaffected_versions = [v for v in versions if v.get("status") == "unaffected"]

        for v in affected_versions:
            version_str = (v.get("version") or "").strip().lower()
            has_range = bool(v.get("lessThan") or v.get("lessThanOrEqual"))
            if version_str not in PLACEHOLDER_VERSIONS:
                has_any_concrete_version = True
                if has_range:
                    return 2, f"bounded range: version {v.get('version')} .. lessThan {v.get('lessThan') or v.get('lessThanOrEqual')}"
                if unaffected_versions:
                    return 2, f"explicit affected/unaffected version pair for {a.get('product')}"

        if has_any_concrete_version and best_score < 1:
            best_score, best_reason = 1, "concrete affected version(s) with no range bound and no paired fixed version"

    return best_score, best_reason


def score_fix_availability_v5(record: dict) -> tuple[int, str]:
    """v2, corrected after peer review (Monika Schrenk, Sep 23 2026): v1's
    score-1 branch fired on `cna.get("references")` truthiness alone --
    nearly every CNA record has at least one reference regardless of
    content, so score 0 was effectively unreachable. v2 requires a
    vendor-advisory-tagged reference (the V5 schema's analog of the NVD
    path's "Vendor Advisory" reference tag) or explicit fix language,
    exactly mirroring score_fix_availability_nvd's Patch/Vendor-Advisory
    duality -- the mere presence of *some* reference (an issue tracker, a
    third-party writeup, an exploit PoC, etc.) no longer counts."""
    cna = record.get("containers", {}).get("cna", {})
    has_patch_ref = False
    has_advisory_ref = False
    for ref in cna.get("references", []):
        tags = [t.lower() for t in (ref.get("tags") or [])]
        if "patch" in tags:
            has_patch_ref = True
        if "vendor-advisory" in tags:
            has_advisory_ref = True

    desc = ""
    for d in cna.get("descriptions", []):
        if d.get("lang", "").startswith("en"):
            desc = d.get("value", "")
            break
    has_fix_language = bool(FIX_LANGUAGE_RE.search(desc))

    # A stated unaffected/fixed version anywhere counts as an explicit fix identification.
    has_unaffected_version = any(
        v.get("status") == "unaffected"
        for a in cna.get("affected", [])
        for v in a.get("versions", [])
    )

    if has_patch_ref or has_unaffected_version:
        return 2, "reference tagged patch, or an explicit unaffected/fixed version is stated"
    if has_advisory_ref or has_fix_language:
        return 1, "reference tagged vendor-advisory or fix language present, but no patch tag or fixed version stated"
    return 0, "no patch/vendor-advisory reference and no fix language in description"
