"""The single results script (locked at PR4). Every number in PR4 onward comes
from here.

    python src/results.py

Reads the frozen corpus (data/freeze, data/corpus_manifest.json), the crawl
passes (data/crawl/pass1.jsonl and pass2.jsonl if present), and the local
CVE List V5 checkout. Writes data/results/results.json.

Metric names (locked at PR4):
  identifiability_score   Dimension 1, 0/1/2, per source (never pooled across
                          sources: the rubric anchors differ, see PR4)
  fix_availability_score  Dimension 2, 0/1/2, per source
  url_live                reference URL classed live_200
  url_dead                hard_404, soft_404, redirect_to_root, dns_failure,
                          tls_failure; with two passes, only if it failed in both
  url_blocked             waf_challenge or auth_or_paywall_gated (kept apart
                          from dead, never counted as decay)
  retrievability_rate     url_live / (url_live + url_dead), blocked and
                          unclassifiable URLs excluded
  retrievable_fix_rate    share of CVEs whose record names a fix
                          (fix_availability_score >= 1) and has at least one
                          live patch or vendor-advisory reference: the headline.
                          Only patch/vendor-advisory links are crawled and that
                          tag already scores D2 >= 1, so in practice this equals
                          "has a live patch or vendor-advisory link" (Monika, PR5)

Added at PR5 (new fields, no locked metric changed):
  fix_link_rate           share of CVEs with any patch or vendor-advisory link
  live_given_link_rate    of those, the share with at least one live link
  own_cna_share           per vendor: share of records whose V5 assigner is
                          the vendor itself (assignerShortName)
"""
from __future__ import annotations

import json
import os
import random
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dotenv import load_dotenv  # noqa: E402

from identifiability_scorer import score_fix_availability_v5, score_identifiability_v5  # noqa: E402

load_dotenv()
REPO = Path(__file__).resolve().parent.parent
FREEZE, CRAWL, OUT = REPO / "data" / "freeze", REPO / "data" / "crawl", REPO / "data" / "results"
V5 = Path(os.environ.get("V5_REPO_DIR", REPO / "data" / "v5_repo"))
DEAD = {"hard_404", "soft_404", "redirect_to_root", "dns_failure", "tls_failure"}
BLOCKED = {"waf_challenge", "auth_or_paywall_gated"}
LIVE = {"live_200"}
FIX_TAGS = re.compile(r"patch|vendor.?advisory", re.I)
CONTROL_N, SEED = 1000, 20261012
# Week 8 description screen (deliberately short; see PR4).
SCREEN = re.compile(
    r"smartphone|android (?:device|phone)|\bhandset|mobile phone|\bios\b app|\btablet\b|"
    r"\bplc\b|scada|\bhmi\b|\bcnc\b|programmable logic|industrial control|"
    r"medical|patient|infusion|hospital|healthcare|vehicle|automotive|infotainment", re.I)
ALIASES = {"tendacn": "tenda", "draytekcorporation": "draytek"}


def era(d: str | None) -> str:
    d = (d or "")[:10]
    return "pre-2024" if d < "2024-01-01" else "backlog" if d < "2026-03-01" else "triage"


def norm(v: str) -> str:
    k = re.sub(r"[^a-z0-9]", "", v.lower())
    return ALIASES.get(k, k)


def load(fn: str) -> dict:
    with (FREEZE / fn).open(encoding="utf-8") as f:
        return {r["id"]: r for r in map(json.loads, f)}


def v5_record(cve_id: str) -> dict | None:
    _, y, n = cve_id.split("-")
    p = V5 / "cves" / y / (f"{n[:-3]}xxx" if len(n) > 3 else "0xxx") / f"{cve_id}.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def v5_desc(rec: dict | None) -> str:
    for d in (rec or {}).get("containers", {}).get("cna", {}).get("descriptions", []):
        if d.get("lang", "").startswith("en"):
            return d.get("value", "")
    return ""


def dist(values) -> dict:
    c, n = Counter(values), len(values)
    return {"n": n, **{str(k): c.get(k, 0) for k in (0, 1, 2)},
            "mean": round(sum(values) / n, 3) if n else None,
            "share_2": round(c.get(2, 0) / n, 3) if n else None}


def load_pass(n: int) -> dict[str, str]:
    p = CRAWL / f"pass{n}.jsonl"
    if not p.exists():
        return {}
    with p.open(encoding="utf-8") as f:
        return {r["url"]: r["outcome"] for r in map(json.loads, f)}


def url_state(url: str, p1: dict, p2: dict) -> str:
    a = p1.get(url)
    if a is None:
        return "unchecked"
    if a in LIVE or (p2 and p2.get(url) in LIVE):
        return "live"
    if a in BLOCKED:
        return "blocked"
    if a in DEAD or a in {"timeout", "connection_error", "server_error"}:
        if not p2:
            return "dead" if a in DEAD else "transient"
        b = p2.get(url)
        if b is None:
            return "dead" if a in DEAD else "transient"
        if b in DEAD or b in {"timeout", "connection_error", "server_error"}:
            return "dead" if (a in DEAD or b in DEAD) else "transient"
        return "blocked" if b in BLOCKED else "transient"
    return "other"


def main() -> None:
    man = json.loads((REPO / "data" / "corpus_manifest.json").read_text())
    ids = set(man["ids"])
    nvd = {k: v for k, v in load("nvd_included.jsonl").items() if k in ids}
    v5 = {k: v for k, v in load("v5_included.jsonl").items() if k in ids}
    p1, p2 = load_pass(1), load_pass(2)
    R: dict = {"passes": [n for n, p in ((1, p1), (2, p2)) if p]}

    # Per-record view: publication date, path, refs, V5 (CNA-side) scores for every CVE.
    recs = {}
    for cid in ids:
        a, b = nvd.get(cid), v5.get(cid)
        path = "both" if a and b else "nvd_only" if a else "v5_only"
        refs = {}
        for r in (a or {}).get("references", []) + (b or {}).get("references", []):
            if FIX_TAGS.search(" ".join(r.get("tags") or [])):  # only patch / vendor-advisory links are crawled
                refs.setdefault(r["url"].strip(), set()).update(r.get("tags") or [])
        raw = v5_record(cid)
        cna_d1 = score_identifiability_v5(raw)[0] if raw else None
        cna_d2 = score_fix_availability_v5(raw)[0] if raw else None
        recs[cid] = {"published": (a or b)["published"], "path": path, "refs": refs,
                     "nvd_d1": a["identifiability"] if a else None, "nvd_d2": a["fix_availability"] if a else None,
                     "cna_d1": cna_d1, "cna_d2": cna_d2,
                     "assigner": norm(((raw or {}).get("cveMetadata") or {}).get("assignerShortName") or ""),
                     "vendors": {norm(v) for v in (a or b)["vendors"] if v},
                     "screened_out": bool(SCREEN.search(v5_desc(raw)))}

    # RQ1 / Dimension 2: per source (NVD-scored on NVD records, CNA-scored on V5 records) x era.
    R["rq1_d2"] = {}
    for e in ("pre-2024", "backlog", "triage", "all"):
        sel = [r for r in recs.values() if e == "all" or era(r["published"]) == e]
        R["rq1_d2"][e] = {
            "nvd_identifiability": dist([r["nvd_d1"] for r in sel if r["nvd_d1"] is not None]),
            "nvd_fix_availability": dist([r["nvd_d2"] for r in sel if r["nvd_d2"] is not None]),
            "cna_identifiability": dist([r["cna_d1"] for r in sel if r["cna_d1"] is not None]),
            "cna_fix_availability": dist([r["cna_d2"] for r in sel if r["cna_d2"] is not None]),
        }

    # RQ2: URL outcomes, retrievability, decay by disclosure age, stability between passes.
    states = {u: url_state(u, p1, p2) for r in recs.values() for u in r["refs"]}
    R["rq2_outcomes_pass1"] = dict(Counter(p1.values()).most_common())
    R["rq2_url_states"] = dict(Counter(states.values()).most_common())
    live, dead = sum(s == "live" for s in states.values()), sum(s == "dead" for s in states.values())
    R["retrievability_rate"] = round(live / (live + dead), 3) if live + dead else None
    by_year = defaultdict(lambda: [0, 0])
    for r in recs.values():
        y = int(r["published"][:4])
        bucket = "1999-2010" if y < 2011 else "2011-2015" if y < 2016 else "2016-2019" if y < 2020 else "2020-2023" if y < 2024 else str(y)
        for u in r["refs"]:
            s = states[u]
            if s in ("live", "dead"):
                by_year[bucket][0 if s == "live" else 1] += 1
    R["rq2_decay_by_publication_year"] = {k: {"live": v[0], "dead": v[1], "retrievability_rate": round(v[0] / sum(v), 3)}
                                          for k, v in sorted(by_year.items(), key=lambda kv: int(kv[0][:4]))}
    if p1 and p2:
        both = [u for u in p1 if u in p2]
        flips = sum((p1[u] in LIVE) != (p2[u] in LIVE) for u in both)
        R["pass_stability"] = {"urls_in_both": len(both), "live_status_flips": flips,
                               "flip_rate": round(flips / len(both), 4) if both else None}

    # Headline: retrievable_fix_rate, plus per-CVE "any live reference".
    def cve_flags(r: dict) -> tuple[bool, bool]:
        named = (r["nvd_d2"] or 0) >= 1 or (r["cna_d2"] or 0) >= 1
        live_fix = any(states[u] == "live" and FIX_TAGS.search(" ".join(t)) for u, t in r["refs"].items())
        any_live = any(states[u] == "live" for u in r["refs"])
        return named and live_fix, any_live

    def headline(sel: list[dict]) -> dict:
        f = [cve_flags(r) for r in sel]
        linked = sum(bool(r["refs"]) for r in sel)
        return {"n": len(sel), "retrievable_fix_rate": round(sum(a for a, _ in f) / len(f), 3) if f else None,
                "any_live_reference_rate": round(sum(b for _, b in f) / len(f), 3) if f else None,
                "fix_link_rate": round(linked / len(sel), 3) if sel else None,
                "live_given_link_rate": round(sum(b for _, b in f) / linked, 3) if linked else None}

    allr = list(recs.values())
    R["headline"] = {"all": headline(allr), "screened": headline([r for r in allr if not r["screened_out"]])}
    R["headline_by_path_era"] = {f"{p}|{e}": headline([r for r in allr if r["path"] == p and era(r["published"]) == e])
                                 for p in ("both", "nvd_only", "v5_only") for e in ("pre-2024", "backlog", "triage")}
    R["headline_by_path"] = {p: headline([r for r in allr if r["path"] == p]) for p in ("both", "nvd_only", "v5_only")}
    R["screen"] = {"screened_out": sum(r["screened_out"] for r in allr), "kept": sum(not r["screened_out"] for r in allr)}

    # RQ3: vendors with at least 10 CVEs (D6).
    by_v = defaultdict(list)
    for r in allr:
        for v in r["vendors"]:
            by_v[v].append(r)
    vend = []
    for v, rs in by_v.items():
        if len(rs) >= 10:
            h = headline(rs)
            d1 = [r["nvd_d1"] for r in rs if r["nvd_d1"] is not None]
            vend.append({"vendor": v, "n": len(rs), **{k: h[k] for k in ("retrievable_fix_rate", "any_live_reference_rate")},
                         "fix_link_rate": h["fix_link_rate"],
                         "own_cna_share": round(sum(bool(r["assigner"]) and (v in r["assigner"] or r["assigner"] in v)
                                                    for r in rs) / len(rs), 3),
                         "nvd_identifiability_mean": round(sum(d1) / len(d1), 2) if d1 else None})
    vend.sort(key=lambda x: -x["n"])
    R["rq3_vendors"] = vend

    # RQ4: CNA-side scores, corpus vs a random sample of non-corpus CVEs matched on era share.
    random.seed(SEED)
    want = Counter(era(r["published"]) for r in allr)
    quota = {e: round(CONTROL_N * want[e] / len(allr)) for e in want}
    pool = [p for p in (V5 / "cves").glob("*/*/CVE-*.json") if p.stem not in ids]
    random.shuffle(pool)
    ctrl = defaultdict(list)
    for p in pool:
        if all(len(ctrl[e]) >= quota[e] for e in quota):
            break
        rec = json.loads(p.read_text(encoding="utf-8"))
        if rec.get("cveMetadata", {}).get("state") != "PUBLISHED":
            continue
        e = era(rec["cveMetadata"].get("datePublished"))
        if len(ctrl[e]) < quota.get(e, 0):
            ctrl[e].append((score_identifiability_v5(rec)[0], score_fix_availability_v5(rec)[0]))
    c_all = [x for v in ctrl.values() for x in v]
    R["rq4_cna_side"] = {
        "corpus": {"identifiability": dist([r["cna_d1"] for r in allr if r["cna_d1"] is not None]),
                   "fix_availability": dist([r["cna_d2"] for r in allr if r["cna_d2"] is not None])},
        "control": {"identifiability": dist([a for a, _ in c_all]), "fix_availability": dist([b for _, b in c_all]),
                    "quota": quota, "seed": SEED},
    }

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "results.json").write_text(json.dumps(R, indent=1), encoding="utf-8")
    print(json.dumps({k: R[k] for k in ("passes", "retrievability_rate", "headline", "screen", "rq2_url_states")}, indent=1))


if __name__ == "__main__":
    main()
