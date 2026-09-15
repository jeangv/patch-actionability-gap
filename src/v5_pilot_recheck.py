"""Week 3 task (W3.5), pre-2024 record-level check: fetch the exact 67
pre-2024 CVE IDs from the existing NVD pilot slice
(data/pilot_20260905_v2/pre-2024.json) directly from CVE List V5 by ID (via
raw.githubusercontent.com -- no local sparse checkout needed for just 67
files), and compare field presence against the NVD-path pilot.

This is deliberately scoped to record-level schema comparison, not a
population-level V5 discovery pass -- see v5_corpus_pass.py's module
docstring for why pre-2024 is out of scope for the population-level pass
(it predates the April 2026 policy the V5 pivot targets). This script
answers a narrower, still-useful question: for the exact CVEs NVD's pilot
already found, does CVE List V5 carry comparable identifiability data, this
far back in the corpus?

Output: docs/v5_pilot_recheck_pre2024.md
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import requests

from identifiability_scorer import score_identifiability_nvd, score_identifiability_v5

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = REPO_ROOT / "data" / "pilot_20260905_v2"
OUT_PATH = REPO_ROOT / "docs" / "v5_pilot_recheck_pre2024.md"

RAW_BASE = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"
USER_AGENT = "patch-actionability-gap-research/0.1 (GT OMSCS CS-6727 practicum measurement study)"


def bucket_for(cve_id: str) -> str:
    # CVE-YYYY-NNNNN -> Nxxx bucket, e.g. CVE-2011-1234 -> 1xxx
    num = cve_id.split("-")[2]
    if len(num) <= 4:
        return "0xxx" if len(num) < 4 else f"{num[0]}xxx"
    return f"{num[:-3]}xxx"


def fetch_v5(cve_id: str, year: str) -> dict | None:
    url = f"{RAW_BASE}/{year}/{bucket_for(cve_id)}/{cve_id}.json"
    for attempt in range(3):
        try:
            resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=30)
        except requests.RequestException:
            time.sleep(1 + attempt)
            continue
        if resp.status_code == 200:
            return resp.json()
        if resp.status_code == 404:
            return None
        time.sleep(1 + attempt)
    return None


def main() -> None:
    records = json.loads((DATA_DIR / "pre-2024.json").read_text(encoding="utf-8"))
    lines = ["# CVE List V5 Pre-2024 Pilot Recheck (record-level, 67 CVEs)\n"]
    lines.append(
        "Fetches, by exact CVE ID, the CVE List V5 record for every pre-2024 "
        "CVE in the existing NVD pilot slice (`data/pilot_20260905_v2/"
        "pre-2024.json`), via `raw.githubusercontent.com` (67 individual "
        "fetches -- no local sparse checkout for this scope). Compares "
        "Dimension-1 (identifiability) scores computed from each source for "
        "the same CVE.\n"
    )

    found = 0
    not_found = 0
    both_score2 = 0
    nvd_higher = 0
    v5_higher = 0
    equal = 0
    rows = []

    for r in records:
        cve_id = r["id"]
        year = cve_id.split("-")[1]
        v5_record = fetch_v5(cve_id, year)
        nvd_score, _ = score_identifiability_nvd(r)
        if v5_record is None:
            not_found += 1
            rows.append((cve_id, nvd_score, "not found in V5"))
            continue
        found += 1
        v5_score, _ = score_identifiability_v5(v5_record)
        if nvd_score == 2 and v5_score == 2:
            both_score2 += 1
        if nvd_score > v5_score:
            nvd_higher += 1
        elif v5_score > nvd_score:
            v5_higher += 1
        else:
            equal += 1
        rows.append((cve_id, nvd_score, str(v5_score)))
        time.sleep(0.05)

    lines.append(f"**{found} of {len(records)} pre-2024 pilot CVE IDs found in CVE List V5** "
                 f"({not_found} not found -- CVE List V5 back-population gaps, if any, show up here).\n")
    lines.append(
        f"Of the {found} found: NVD-side score higher in {nvd_higher}, V5-side "
        f"score higher in {v5_higher}, equal in {equal} (both score 2 in "
        f"{both_score2} of those).\n"
    )

    lines.append("| CVE ID | NVD identifiability score | V5 identifiability score |")
    lines.append("|---|---:|---|")
    for cve_id, nvd_s, v5_s in rows:
        lines.append(f"| {cve_id} | {nvd_s} | {v5_s} |")

    OUT_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {OUT_PATH}")
    print(f"found={found} not_found={not_found} nvd_higher={nvd_higher} v5_higher={v5_higher} equal={equal}")


if __name__ == "__main__":
    main()
