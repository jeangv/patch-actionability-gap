"""Corpus freeze, NVD side (W4.2, run Week 6). Scans every CVE in the NVD API
from 1999-01-01 to now, applies corpus_filter.classify(), and writes one
JSON line per included record to data/freeze/nvd_included.jsonl.

Each line keeps what later stages need so they don't have to query NVD
again: publication date, vulnStatus, CPE vendors that triggered inclusion,
rule tags, the Dimension 1 and 2 scores, and every reference URL with its
tags (the Week 7 retrievability crawl reads these).

freeze_manifest.py combines this with freeze_v5_pass.py's output.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

from corpus_filter import classify
from identifiability_scorer import score_fix_availability_nvd, score_identifiability_nvd
from nvd_client import NvdClient, date_windows

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = REPO_ROOT / "data" / "freeze"
OUT_PATH = OUT_DIR / "nvd_included.jsonl"
META_PATH = OUT_DIR / "nvd_pass_meta.json"

START = datetime(1999, 1, 1)


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    client = NvdClient()
    run_started = datetime.now(timezone.utc)
    t0 = time.monotonic()
    scanned = included = ambiguous = 0

    with OUT_PATH.open("w", encoding="utf-8") as out:
        for w in date_windows(START, datetime.now()):
            w_scanned = w_included = 0
            for cve in client.iter_cves(w.as_params()):
                scanned += 1
                w_scanned += 1
                d = classify(cve)
                if d.ambiguous:
                    ambiguous += 1
                if not d.included:
                    continue
                included += 1
                w_included += 1
                vendors = sorted({r.split(": ", 1)[1].split(":", 1)[0] for r in d.include_reasons})
                id_score, _ = score_identifiability_nvd(cve)
                fa_score, _ = score_fix_availability_nvd(cve)
                out.write(json.dumps({
                    "id": d.cve_id,
                    "published": cve.get("published"),
                    "vulnStatus": cve.get("vulnStatus"),
                    "vendors": vendors,
                    "rule_tags": sorted(d.rule_tags),
                    "identifiability": id_score,
                    "fix_availability": fa_score,
                    "references": [
                        {"url": r.get("url"), "tags": r.get("tags") or []}
                        for r in cve.get("references", [])
                    ],
                }) + "\n")
            print(
                f"  {w.start.date()}..{w.end.date()}: scanned {w_scanned:,}, included {w_included:,}"
                f" | total {scanned:,}/{included:,} | {time.monotonic() - t0:,.0f}s",
                flush=True,
            )

    META_PATH.write_text(json.dumps({
        "run_started_utc": run_started.isoformat(timespec="seconds"),
        "elapsed_seconds": round(time.monotonic() - t0),
        "scanned": scanned,
        "included": included,
        "ambiguous": ambiguous,
    }, indent=2), encoding="utf-8")
    print(f"Done: {scanned:,} scanned, {included:,} included, {ambiguous:,} ambiguous")


if __name__ == "__main__":
    main()
