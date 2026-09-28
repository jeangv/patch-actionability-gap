"""Combine the NVD and V5 freeze passes into the frozen corpus (W4.2, D9).

Reads data/freeze/nvd_included.jsonl and data/freeze/v5_included.jsonl and
writes:

  data/corpus_manifest.json   sorted union of CVE IDs, SHA-256 over the
                              newline-joined list, V5 commit, per-path and
                              per-era counts (committed to git)
  docs/corpus_freeze_results.md
  docs/source_vendor_rankings.md
                              vendor rankings computed separately per
                              source, flagging vendors that rank high on
                              one path only (JP Valentine, Mizanur Rahman)
  docs/v5_nvd_characterization_sample.md
                              random V5-only and NVD-only records for the
                              hand-check (Monika Schrenk, Travis Carlisle)

Vendor names are normalized (lowercase, letters and digits only) so NVD's
CPE "d-link" and a CNA's "D-Link" count as one vendor. Rankings count
CVEs, not affected-product entries.
"""
from __future__ import annotations

import hashlib
import json
import os
import random
import re
from collections import Counter
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()
REPO_ROOT = Path(__file__).resolve().parent.parent
FREEZE = REPO_ROOT / "data" / "freeze"
DOCS = REPO_ROOT / "docs"
V5_REPO = Path(os.environ.get("V5_REPO_DIR", REPO_ROOT / "data" / "v5_repo"))
MIN_N = 10  # D6
SAMPLE_N = 30


def load(path: Path) -> dict:
    out = {}
    with path.open(encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            out[r["id"]] = r
    return out


def era(published: str | None) -> str:
    d = (published or "")[:10]
    if d < "2024-01-01":
        return "pre-2024"
    if d < "2026-03-01":
        return "backlog"
    return "triage"


def norm(v: str) -> str:
    return re.sub(r"[^a-z0-9]", "", v.lower())


def v5_description(cve_id: str) -> str:
    y, n = cve_id.split("-")[1], cve_id.split("-")[2]
    b = f"{n[:-3]}xxx" if len(n) > 3 else "0xxx"
    p = V5_REPO / "cves" / y / b / f"{cve_id}.json"
    if not p.exists():
        return "(no V5 record)"
    rec = json.loads(p.read_text(encoding="utf-8"))
    for d in rec.get("containers", {}).get("cna", {}).get("descriptions", []):
        if d.get("lang", "").startswith("en"):
            return " ".join(d.get("value", "").split())
    return "(no English description)"


def ranking(records: dict, ids: set) -> Counter:
    c = Counter()
    for cid in ids:
        for v in {norm(x) for x in records[cid]["vendors"] if x}:
            c[v] += 1
    return c


def main() -> None:
    nvd = load(FREEZE / "nvd_included.jsonl")
    v5 = load(FREEZE / "v5_included.jsonl")
    v5_meta = json.loads((FREEZE / "v5_pass_meta.json").read_text())
    nvd_meta = json.loads((FREEZE / "nvd_pass_meta.json").read_text())

    nvd_ids, v5_ids = set(nvd), set(v5)
    union = sorted(nvd_ids | v5_ids, key=lambda s: (int(s.split("-")[1]), int(s.split("-")[2])))
    digest = hashlib.sha256("\n".join(union).encode()).hexdigest()
    both, v5_only, nvd_only = nvd_ids & v5_ids, v5_ids - nvd_ids, nvd_ids - v5_ids

    def pub(cid):
        return (nvd.get(cid) or v5.get(cid))["published"]

    era_counts = Counter(era(pub(c)) for c in union)
    era_split = {e: Counter() for e in ("pre-2024", "backlog", "triage")}
    for c in union:
        era_split[era(pub(c))]["both" if c in both else "v5_only" if c in v5_only else "nvd_only"] += 1
    pre2011 = sum(1 for c in union if (pub(c) or "")[:4] < "2011")

    manifest = {
        "frozen_utc": nvd_meta["run_started_utc"],
        "v5_commit": v5_meta["v5_commit"],
        "rule": "corpus_filter.classify (NVD) OR corpus_filter_v5.classify v3 (V5)",
        "counts": {"union": len(union), "nvd_path": len(nvd_ids), "v5_path": len(v5_ids),
                   "both": len(both), "v5_only": len(v5_only), "nvd_only": len(nvd_only),
                   "pre_2011": pre2011, **{f"era_{k}": v for k, v in era_counts.items()}},
        "scanned": {"nvd": nvd_meta["scanned"], "v5": v5_meta["scanned"]},
        "sha256_sorted_ids": digest,
        "ids": union,
    }
    (REPO_ROOT / "data" / "corpus_manifest.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")

    pct = lambda a, b: f"{100 * a / b:.1f}%" if b else "n/a"
    L = ["# Corpus Freeze Results\n",
         f"Frozen corpus: **{len(union):,} CVEs**. NVD path {len(nvd_ids):,} of {nvd_meta['scanned']:,} scanned; "
         f"V5 path {len(v5_ids):,} of {v5_meta['scanned']:,} scanned. CVE List V5 commit `{v5_meta['v5_commit']}`. "
         f"SHA-256 of the sorted ID list: `{digest}`.\n",
         "| Path | Records | Share of union |", "|---|---:|---:|",
         f"| Both | {len(both):,} | {pct(len(both), len(union))} |",
         f"| NVD only | {len(nvd_only):,} | {pct(len(nvd_only), len(union))} |",
         f"| V5 only | {len(v5_only):,} | {pct(len(v5_only), len(union))} |",
         "\n## By era\n", "| Era | Union | Both | NVD only | V5 only | V5-only share |", "|---|---:|---:|---:|---:|---:|"]
    for e, c in era_split.items():
        tot = sum(c.values())
        L.append(f"| {e} | {tot:,} | {c['both']:,} | {c['nvd_only']:,} | {c['v5_only']:,} | {pct(c['v5_only'], tot)} |")
    L.append(f"\nPublished before 2011 (D1 covariate stratum): {pre2011:,}.")
    (DOCS / "corpus_freeze_results.md").write_text("\n".join(L) + "\n", encoding="utf-8")

    rn, rv = ranking(nvd, nvd_ids), ranking(v5, v5_ids)
    top_n = [v for v, n in rn.most_common() if n >= MIN_N]
    top_v = [v for v, n in rv.most_common() if n >= MIN_N]
    pos_n = {v: i + 1 for i, v in enumerate(top_n)}
    pos_v = {v: i + 1 for i, v in enumerate(top_v)}
    R = ["# Vendor Rankings by Source\n",
         f"CVE counts per vendor, computed separately for the NVD path and the V5 path. Vendors need at least "
         f"{MIN_N} CVEs on a path to be ranked there (D6). A vendor is flagged when it is in one path's top 20 "
         f"but outside the other path's top 50, or unranked there.\n",
         "| Vendor | NVD CVEs | NVD rank | V5 CVEs | V5 rank | Flag |", "|---|---:|---:|---:|---:|---|"]
    flagged = 0
    for v in sorted(set(top_n[:20]) | set(top_v[:20]), key=lambda x: min(pos_n.get(x, 999), pos_v.get(x, 999))):
        a, b = pos_n.get(v), pos_v.get(v)
        flag = ""
        if (a and a <= 20 and (not b or b > 50)) or (b and b <= 20 and (not a or a > 50)):
            flag = "one path only"
            flagged += 1
        R.append(f"| {v} | {rn[v]:,} | {a or '-'} | {rv[v]:,} | {b or '-'} | {flag} |")
    R.append(f"\n{flagged} vendor(s) flagged.")
    (DOCS / "source_vendor_rankings.md").write_text("\n".join(R) + "\n", encoding="utf-8")

    random.seed(20260927)
    S = ["# V5-only and NVD-only Sample for Hand-Check\n",
         f"{SAMPLE_N} random records from each side (seed 20260927). Descriptions come from the CVE List V5 record "
         "for both, so the two sides are read the same way.\n"]
    for label, pool, src in (("V5 only", v5_only, v5), ("NVD only", nvd_only, nvd)):
        S += [f"\n## {label}\n", "| # | CVE | Era | Vendor(s) | Description |", "|---:|---|---|---|---|"]
        for i, cid in enumerate(random.sample(sorted(pool), min(SAMPLE_N, len(pool))), 1):
            S.append(f"| {i} | {cid} | {era(src[cid]['published'])} | {', '.join(src[cid]['vendors'][:3])} | "
                     f"{v5_description(cid)[:220].replace('|', '/')} |")
    (DOCS / "v5_nvd_characterization_sample.md").write_text("\n".join(S) + "\n", encoding="utf-8")

    print(f"union {len(union):,} | nvd {len(nvd_ids):,} | v5 {len(v5_ids):,} | both {len(both):,} | "
          f"v5_only {len(v5_only):,} | nvd_only {len(nvd_only):,} | flagged vendors {flagged} | sha256 {digest[:16]}")


if __name__ == "__main__":
    main()
