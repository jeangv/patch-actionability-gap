"""Corpus freeze, CVE List V5 side (W4.2, run Week 6). Classifies every
record in the local V5 sparse checkout (cves/1999 through cves/2026) with
corpus_filter_v5.classify() and writes one JSON line per included record to
data/freeze/v5_included.jsonl, in the same shape as freeze_nvd_pass.py.

The checkout lives outside the OneDrive-synced project folder because it is
several GB of small files. Set V5_REPO_DIR in .env to its path.
"""
from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

from dotenv import load_dotenv

from corpus_filter_v5 import classify
from identifiability_scorer import score_fix_availability_v5, score_identifiability_v5

load_dotenv()

REPO_ROOT = Path(__file__).resolve().parent.parent
V5_REPO = Path(os.environ.get("V5_REPO_DIR", REPO_ROOT / "data" / "v5_repo"))
OUT_DIR = REPO_ROOT / "data" / "freeze"
OUT_PATH = OUT_DIR / "v5_included.jsonl"
META_PATH = OUT_DIR / "v5_pass_meta.json"


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    commit = subprocess.run(
        ["git", "-C", str(V5_REPO), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    t0 = time.monotonic()
    scanned = included = ambiguous = 0

    with OUT_PATH.open("w", encoding="utf-8") as out:
        for year_dir in sorted((V5_REPO / "cves").iterdir()):
            if not year_dir.is_dir():
                continue
            y_scanned = y_included = 0
            for path in year_dir.glob("*/*.json"):
                try:
                    rec = json.loads(path.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue
                scanned += 1
                y_scanned += 1
                d = classify(rec)
                if d.ambiguous:
                    ambiguous += 1
                if not d.included:
                    continue
                included += 1
                y_included += 1
                cna = rec.get("containers", {}).get("cna", {})
                id_score, _ = score_identifiability_v5(rec)
                fa_score, _ = score_fix_availability_v5(rec)
                out.write(json.dumps({
                    "id": d.cve_id,
                    "published": rec.get("cveMetadata", {}).get("datePublished"),
                    "vendors": sorted({(a.get("vendor") or "").strip() for a in cna.get("affected", []) if a.get("vendor")}),
                    "reasons": sorted({r.split(":", 1)[0] for r in d.include_reasons}),
                    "identifiability": id_score,
                    "fix_availability": fa_score,
                    "references": [
                        {"url": r.get("url"), "tags": r.get("tags") or []}
                        for r in cna.get("references", [])
                    ],
                }) + "\n")
            print(f"  {year_dir.name}: scanned {y_scanned:,}, included {y_included:,} | {time.monotonic() - t0:,.0f}s", flush=True)

    META_PATH.write_text(json.dumps({
        "v5_commit": commit,
        "elapsed_seconds": round(time.monotonic() - t0),
        "scanned": scanned,
        "included": included,
        "ambiguous": ambiguous,
    }, indent=2), encoding="utf-8")
    print(f"Done: {scanned:,} scanned, {included:,} included, V5 commit {commit}")


if __name__ == "__main__":
    main()
