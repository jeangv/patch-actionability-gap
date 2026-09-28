"""Positive-control ground-truth set (Evaluation 1, built Week 6).

Hand-picked records and URLs whose correct answer is fixed before the
pipeline is run against them. Three groups:

  membership  CVEs that corpus_filter_v5 must include or exclude. The
              excluded ones are real false positives found during the
              Week 5 bug fix.
  scoring     CVEs with a known Dimension 1 or 2 score, taken from the
              worked examples in docs/scoring_rubric_v0.1.md, plus three
              synthetic V5 records that pin down the 0/1/2 boundaries of
              score_fix_availability_v5.
  http        URLs with a known retrieval outcome class for the Week 7
              retrievability checker. Most use endpoints built for testing
              (badssl.com, httpbin.org, the reserved .invalid TLD, a
              non-routable address) so the answer can't drift. Real vendor
              URLs are labeled with what they returned when probed.

Membership and scoring controls are run now. HTTP controls get an observed
status recorded here and are scored once the checker exists.

Writes data/positive_controls.json and docs/positive_control_set.md.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import requests
from dotenv import load_dotenv

from corpus_filter_v5 import classify as classify_v5
from identifiability_scorer import (
    score_fix_availability_nvd,
    score_fix_availability_v5,
    score_identifiability_nvd,
    score_identifiability_v5,
)

load_dotenv()
REPO_ROOT = Path(__file__).resolve().parent.parent
V5_REPO = Path(os.environ.get("V5_REPO_DIR", REPO_ROOT / "data" / "v5_repo"))
PILOT_DIR = REPO_ROOT / "data" / "pilot_20260905_v2"
OUT_JSON = REPO_ROOT / "data" / "positive_controls.json"
OUT_MD = REPO_ROOT / "docs" / "positive_control_set.md"
UA = "patch-actionability-gap-research/0.1 (GT OMSCS CS-6727 practicum measurement study)"

MEMBERSHIP = [
    ("CVE-2024-0531", True, "Tenda A15 router, stack overflow in web management UI"),
    ("CVE-2025-27480", False, "Microsoft Remote Desktop Gateway Service, Windows server software"),
    ("CVE-2024-38015", False, "Microsoft RD Gateway denial of service"),
    ("CVE-2025-21403", False, "Microsoft On-Premises Data Gateway"),
    ("CVE-2024-22316", False, "IBM Sterling File Gateway, enterprise software"),
    ("CVE-2024-45655", False, "IBM Application Gateway"),
    ("CVE-2024-22457", False, "Dell Secure Connect Gateway, enterprise software"),
    ("CVE-2024-44100", False, "Google Pixel modem component, mobile handset"),
    ("CVE-2024-27795", False, "Apple macOS camera extension"),
]

NVD_SCORING = [
    ("CVE-1999-0453", "identifiability", 0, "rubric worked example: wildcard-only CPE"),
    ("CVE-2012-0695", "identifiability", 1, "rubric worked example: upper bound only (replaced CVE-2009-5037, which also lists exact versions)"),
    ("CVE-2009-5037", "identifiability", 2, "range plus dozens of exact versions; exact version scores 2 per rubric"),
    ("CVE-2026-13050", "identifiability", 2, "rubric worked example: fully bounded ranges"),
    ("CVE-2002-1595", "fix_availability", 2, "rubric worked example: Patch-tagged reference"),
    ("CVE-1999-0453", "fix_availability", 0, "rubric worked example: no Patch/Vendor Advisory tag, no fix language"),
]

V5_SCORING = [("CVE-2024-0531", "identifiability", 1, "rubric worked example: one affected version, no range")]

SYNTHETIC_V5_FIX = [
    ("synthetic-fa0", {"references": [{"url": "x", "tags": ["exploit"]}], "descriptions": [{"lang": "en", "value": "No fix information."}], "affected": []}, 0, "exploit reference only; must score 0 (the C2 bug scored this 1)"),
    ("synthetic-fa1", {"references": [{"url": "x", "tags": ["vendor-advisory"]}], "descriptions": [{"lang": "en", "value": "See advisory."}], "affected": []}, 1, "vendor-advisory reference, no fixed version"),
    ("synthetic-fa2", {"references": [{"url": "x", "tags": ["patch"]}], "descriptions": [{"lang": "en", "value": "Patched."}], "affected": []}, 2, "patch-tagged reference"),
]

HTTP = [
    ("https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "live_200", "stable government page"),
    ("https://nvd.nist.gov/developers/vulnerabilities", "live_200", "stable government page"),
    ("https://github.com/CVEProject/cvelistV5", "live_200", "stable repository page"),
    ("https://www.usenix.org/conference/usenixsecurity14/technical-sessions/presentation/costin", "live_200", "stable conference page"),
    ("https://httpbin.org/status/200", "live_200", "test endpoint"),
    ("https://httpbin.org/status/404", "hard_404", "test endpoint"),
    ("https://httpbin.org/status/410", "hard_404", "test endpoint"),
    ("https://www.netgear.com/support/pa-gap-nonexistent-7731/", "hard_404", "real vendor, missing page returns 404"),
    ("https://www.tp-link.com/us/support/pa-gap-nonexistent-7731/", "hard_404", "real vendor, missing page returns 404"),
    ("https://old.tenda.com.cn/error?path=/pa-gap-nonexistent-7731", "hard_404", "real vendor, reached via two 302s, ends at 404"),
    ("https://www.hikvision.com/en/pa-gap-nonexistent-7731/", "soft_404", "real vendor, missing page returns 200"),
    ("https://httpbin.org/redirect-to?url=https%3A%2F%2Fhttpbin.org%2F", "redirect_to_root", "test endpoint, redirects to site root"),
    ("https://httpbin.org/status/401", "auth_or_paywall_gated", "test endpoint"),
    ("https://httpbin.org/basic-auth/user/pass", "auth_or_paywall_gated", "test endpoint, basic-auth challenge"),
    ("https://httpbin.org/status/429", "waf_challenge", "test endpoint, rate-limit status"),
    ("https://httpbin.org/status/403", "waf_challenge", "test endpoint; a bare 403 with no login page, classed as blocked"),
    ("https://pa-gap-control.invalid/advisory", "dns_failure", "RFC 2606 reserved TLD, never resolves"),
    ("https://expired.badssl.com/", "tls_failure", "test endpoint, expired certificate"),
    ("https://self-signed.badssl.com/", "tls_failure", "test endpoint, self-signed certificate"),
    ("https://wrong.host.badssl.com/", "tls_failure", "test endpoint, hostname mismatch"),
    ("http://10.255.255.1/", "timeout", "non-routable address, connection never completes"),
]


def load_pilot_nvd() -> dict:
    out = {}
    for name in ("pre-2024.json", "backlog.json", "triage.json"):
        for rec in json.loads((PILOT_DIR / name).read_text(encoding="utf-8")):
            out[rec["id"]] = rec
    return out


def load_v5(cve_id: str) -> dict | None:
    year, num = cve_id.split("-")[1], cve_id.split("-")[2]
    bucket = f"{num[:-3]}xxx" if len(num) > 3 else "0xxx"
    path = V5_REPO / "cves" / year / bucket / f"{cve_id}.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def probe(url: str) -> str:
    try:
        r = requests.get(url, headers={"User-Agent": UA}, timeout=10, allow_redirects=True)
        hops = "->".join(str(h.status_code) for h in r.history)
        return f"{r.status_code}" + (f" via {hops}" if hops else "") + f", {len(r.content)} bytes"
    except requests.exceptions.SSLError:
        return "TLS error"
    except requests.exceptions.ConnectTimeout:
        return "connect timeout"
    except requests.exceptions.ConnectionError as e:
        return "DNS failure" if "resolve" in str(e).lower() or "getaddrinfo" in str(e).lower() else "connection error"
    except requests.exceptions.Timeout:
        return "read timeout"


def main() -> None:
    nvd = load_pilot_nvd()
    rows = []

    for cve_id, expected, note in MEMBERSHIP:
        rec = load_v5(cve_id)
        actual = classify_v5(rec).included if rec else None
        rows.append({"group": "membership", "id": cve_id, "expected": expected, "actual": actual,
                     "pass": actual == expected, "note": note})

    for cve_id, dim, expected, note in NVD_SCORING:
        rec = nvd.get(cve_id)
        fn = score_identifiability_nvd if dim == "identifiability" else score_fix_availability_nvd
        actual = fn(rec)[0] if rec else None
        rows.append({"group": "scoring_nvd", "id": cve_id, "dimension": dim, "expected": expected,
                     "actual": actual, "pass": actual == expected, "note": note})

    for cve_id, dim, expected, note in V5_SCORING:
        rec = load_v5(cve_id)
        actual = score_identifiability_v5(rec)[0] if rec else None
        rows.append({"group": "scoring_v5", "id": cve_id, "dimension": dim, "expected": expected,
                     "actual": actual, "pass": actual == expected, "note": note})

    for cid, cna, expected, note in SYNTHETIC_V5_FIX:
        actual = score_fix_availability_v5({"containers": {"cna": cna}})[0]
        rows.append({"group": "scoring_v5", "id": cid, "dimension": "fix_availability", "expected": expected,
                     "actual": actual, "pass": actual == expected, "note": note})

    probed_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    for url, expected, note in HTTP:
        rows.append({"group": "http", "id": url, "expected": expected, "observed": probe(url),
                     "pass": None, "note": note})

    OUT_JSON.write_text(json.dumps({"built_utc": probed_at, "controls": rows}, indent=2), encoding="utf-8")

    scored = [r for r in rows if r["pass"] is not None]
    passed = sum(r["pass"] for r in scored)
    lines = [
        "# Positive-Control Set (Evaluation 1)\n",
        f"Built {probed_at}. {len(rows)} controls: {len(scored)} run against the current code now, "
        f"{len(rows) - len(scored)} HTTP controls waiting on the Week 7 retrievability checker.\n",
        f"**Current code: {passed} of {len(scored)} membership and scoring controls pass.**\n",
        "## Membership and scoring controls\n",
        "| Group | ID | Dimension | Expected | Actual | Pass | Note |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in scored:
        lines.append(f"| {r['group']} | {r['id']} | {r.get('dimension', '')} | {r['expected']} | {r['actual']} | "
                     f"{'yes' if r['pass'] else 'NO'} | {r['note']} |")
    lines += ["\n## HTTP outcome controls\n",
              "Observed values are what each URL returned when this set was built. The checker passes a control "
              "when it assigns the expected class.\n",
              "| URL | Expected class | Observed at build | Note |", "|---|---|---|---|"]
    for r in rows:
        if r["group"] == "http":
            lines.append(f"| {r['id']} | {r['expected']} | {r['observed']} | {r['note']} |")
    OUT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"{passed}/{len(scored)} membership+scoring controls pass; {len(rows)} controls total")
    for r in scored:
        if not r["pass"]:
            print("FAIL:", r)


if __name__ == "__main__":
    main()
