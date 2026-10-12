"""Retrievability checker (Week 7): fetch every reference URL in the frozen
corpus and classify it per docs/http_outcome_taxonomy.md.

    python src/http_retrievability.py --controls        # run the 21 HTTP positive controls
    python src/http_retrievability.py --pass 1          # crawl the corpus, write data/crawl/pass1.jsonl

Conduct (PR1 ground rules): declared user-agent, robots.txt respected, one
request per host at a time with a fixed delay, no logins, no WAF evasion.
Bodies are never downloaded in full: at most the first 1 MB is read (for
the soft-404 and challenge-page checks) and only its SHA-256 is kept, and
binary content types are not read at all, so no firmware is fetched.

Simplifications, stated in PR4: archiving keeps response metadata and a
hash of the first 64 KB rather than full bodies; robots-disallowed URLs get
their own class (robots_disallowed) and are left out of denominators.
Re-running with the same --pass resumes where a crash left off.

Scope (PR4): only references tagged as a patch or vendor advisory are
crawled (6,582 URLs). Those are the links a defender needs, and the headline
metric uses only them. Crawling every reference (39,646 URLs) also hit
exploit databases (exploit-db, cxsecurity, VulDB, Packet Storm) that the
host's endpoint protection blocks, which would have shown up as false TLS
and connection failures.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from urllib import robotparser
from urllib.parse import urlparse

import requests
import urllib3

REPO = Path(__file__).resolve().parent.parent
FREEZE = REPO / "data" / "freeze"
OUT_DIR = REPO / "data" / "crawl"
UA = "patch-actionability-gap-research/0.1 (GT OMSCS CS-6727 practicum measurement study; github.com/jeangv/patch-actionability-gap)"
TIMEOUT = (10, 20)          # connect, read seconds
PER_HOST_DELAY = 1.5        # seconds between requests to one host
BODY_CAP = 1024 * 1024    # 1 MB of text; 64 KB cut off server-rendered pages (Netgear, GitHub) before their content
WORKERS = 8                 # hosts in parallel; 64 overwhelmed the host's endpoint protection / router and broke TLS handshakes

NOT_FOUND_PHRASES = re.compile(
    r"page not found|content no longer available|this page has moved|article not found|"
    r"the page you requested|404 not found|page (?:cannot|could not) be found|no longer exists", re.I)
CHALLENGE = re.compile(
    r"cf-chl|challenge-platform|just a moment\.\.\.|attention required! \| cloudflare|"
    r"access denied.{0,200}reference #|incapsula incident|ddos-guard|px-captcha|proof.of.work", re.I | re.S)
SCRIPT = re.compile(r"<script", re.I)
LOGIN = re.compile(r"(?:^|[/_.-])(?:login|log-in|signin|sign-in|sso|auth|oauth)(?:[/_.?=-]|$)", re.I)
FIX_TAGS = re.compile(r"patch|vendor.?advisory", re.I)
BINARY = re.compile(r"octet-stream|zip|x-tar|gzip|x-msdownload|x-binary|firmware", re.I)
TAG = re.compile(r"<script.*?</script>|<style.*?</style>|<[^>]+>", re.I | re.S)
GENERIC_PATHS = {"", "/", "/support", "/support/", "/downloads", "/downloads/", "/download", "/download/"}

urllib3.disable_warnings()
_robots: dict[str, robotparser.RobotFileParser | None] = {}
_robots_lock = threading.Lock()


_base_locks: dict[str, threading.Lock] = defaultdict(threading.Lock)


def robots_allows(url: str) -> bool:
    p = urlparse(url)
    base = f"{p.scheme}://{p.netloc}"
    with _robots_lock:  # only guards the lock table; fetches run in parallel across sites
        lock = _base_locks[base]
    with lock:
        if base not in _robots:
            rp = robotparser.RobotFileParser()
            try:
                r = requests.get(base + "/robots.txt", headers={"User-Agent": UA}, timeout=TIMEOUT)
                rp.parse(r.text.splitlines() if r.status_code == 200 else [])
            except requests.RequestException:
                rp.parse([])
            _robots[base] = rp
    return _robots[base].can_fetch(UA, url)


def classify(url: str, cves: set[str]) -> dict:
    """Fetch one URL and return its archived metadata plus outcome class."""
    rec = {"url": url, "cves": sorted(cves), "ts": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    if not url.lower().startswith(("http://", "https://")):
        return {**rec, "outcome": "unsupported_scheme"}
    if not robots_allows(url):
        return {**rec, "outcome": "robots_disallowed"}
    try:
        r = requests.get(url, headers={"User-Agent": UA}, timeout=TIMEOUT, allow_redirects=True, stream=True)
    except requests.exceptions.SSLError as e:
        return {**rec, "outcome": "tls_failure", "error": str(e)[:200]}
    except requests.exceptions.Timeout as e:
        return {**rec, "outcome": "timeout", "error": str(e)[:200]}
    except requests.exceptions.ConnectionError as e:
        msg = str(e).lower()
        dns = any(s in msg for s in ("getaddrinfo", "name or service not known", "nodename nor servname", "failed to resolve"))
        return {**rec, "outcome": "dns_failure" if dns else "connection_error", "error": str(e)[:200]}
    except requests.RequestException as e:
        return {**rec, "outcome": "connection_error", "error": str(e)[:200]}

    ctype = r.headers.get("Content-Type", "")
    body = b""
    if not BINARY.search(ctype):
        try:
            for chunk in r.iter_content(8192):
                body += chunk
                if len(body) >= BODY_CAP:
                    break
        except requests.RequestException:
            pass
    r.close()
    html = body.decode("utf-8", "replace")
    text = TAG.sub(" ", html)
    final = r.url
    visible = len(" ".join(text.split()))
    rec.update({
        "status": r.status_code, "final_url": final, "history": [h.status_code for h in r.history],
        "content_type": ctype[:100], "server": r.headers.get("Server", "")[:60],
        "bytes_read": len(body), "body_sha256": hashlib.sha256(body).hexdigest(),
        "visible_text_len": visible, "script_tags": len(SCRIPT.findall(html)),
    })
    s, head = r.status_code, text[:2000]
    if s == 429 or "/_pow" in final or CHALLENGE.search(html[:20000]) and s in (200, 403, 503):
        out = "waf_challenge"
    elif s == 401 or (s == 403 and (LOGIN.search(final) or re.search(r"log ?in|sign ?in", head, re.I))):
        out = "auth_or_paywall_gated"
    elif s == 403:
        out = "waf_challenge"
    elif s in (404, 410):
        out = "hard_404"
    elif 200 <= s < 300:
        orig, fin = urlparse(url), urlparse(final)
        if LOGIN.search(fin.path) and not LOGIN.search(orig.path):
            out = "auth_or_paywall_gated"
        elif r.history and fin.path.rstrip("/") in ("",) and orig.path.rstrip("/") not in ("",):
            out = "redirect_to_root"
        elif NOT_FOUND_PHRASES.search(head):
            out = "soft_404"
        elif visible < 512 and rec["script_tags"] and len(body) > 5000:
            out = "js_rendered"  # page built by JavaScript; can't judge without a browser, left out of rates
        elif cves and len(text.strip()) < 512 and not any(c.lower() in text.lower() for c in cves) and BINARY.search(ctype) is None:
            out = "soft_404"
        elif fin.path in GENERIC_PATHS and orig.path not in GENERIC_PATHS:
            out = "redirect_to_root"
        else:
            out = "live_200"
    elif 500 <= s < 600:
        out = "server_error"
    else:
        out = f"other_{s}"
    return {**rec, "outcome": out}


def corpus_urls() -> dict[str, set[str]]:
    ids = set(json.loads((REPO / "data" / "corpus_manifest.json").read_text())["ids"])
    urls: dict[str, set[str]] = defaultdict(set)
    for fn in ("nvd_included.jsonl", "v5_included.jsonl"):
        with (FREEZE / fn).open(encoding="utf-8") as f:
            for line in f:
                r = json.loads(line)
                if r["id"] in ids:
                    for ref in r.get("references", []):
                        u = (ref.get("url") if isinstance(ref, dict) else ref) or ""
                        if u.strip() and FIX_TAGS.search(" ".join(ref.get("tags") or [])):
                            urls[u.strip()].add(r["id"])
    return urls


def crawl(pass_no: int) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out = OUT_DIR / f"pass{pass_no}.jsonl"
    done = set()
    if out.exists():
        with out.open(encoding="utf-8") as f:
            done = {json.loads(l)["url"] for l in f if l.strip()}
    urls = corpus_urls()
    todo = {u: c for u, c in urls.items() if u not in done}
    by_host: dict[str, list[str]] = defaultdict(list)
    for u in todo:
        by_host[urlparse(u).netloc.lower()].append(u)
    print(f"pass {pass_no}: {len(urls):,} URLs, {len(done):,} already done, {len(todo):,} to go across {len(by_host):,} hosts", flush=True)
    lock, counter, t0 = threading.Lock(), [0], time.time()

    def host_worker(host: str) -> None:
        with out.open("a", encoding="utf-8") as fh:
            for i, u in enumerate(by_host[host]):
                if i:
                    time.sleep(PER_HOST_DELAY)
                rec = classify(u, todo[u])
                with lock:
                    fh.write(json.dumps(rec) + "\n")
                    fh.flush()
                    counter[0] += 1
                    if counter[0] % 1000 == 0:
                        print(f"  {counter[0]:,}/{len(todo):,} | {time.time() - t0:,.0f}s", flush=True)

    hosts = sorted(by_host, key=lambda h: -len(by_host[h]))  # big hosts first so they finish in time
    with ThreadPoolExecutor(WORKERS) as ex:
        list(ex.map(host_worker, hosts))
    meta = {"pass": pass_no, "finished_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "urls": len(urls), "elapsed_seconds": round(time.time() - t0)}
    (OUT_DIR / f"pass{pass_no}_meta.json").write_text(json.dumps(meta, indent=1))
    print(f"Done: pass {pass_no}, {len(urls):,} URLs, {time.time() - t0:,.0f}s", flush=True)


def run_controls() -> None:
    path = REPO / "data" / "positive_controls.json"
    pc = json.loads(path.read_text(encoding="utf-8"))
    ok = 0
    http = [c for c in pc["controls"] if c["group"] == "http"]
    for c in http:
        got = classify(c["id"], set())["outcome"]
        c["actual"], c["pass"] = got, got == c["expected"]
        ok += c["pass"]
        print(f"{'pass' if c['pass'] else 'FAIL'}  {c['expected']:<22} {got:<22} {c['id']}")
    path.write_text(json.dumps(pc, indent=1), encoding="utf-8")
    print(f"{ok}/{len(http)} HTTP controls pass")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--controls", action="store_true")
    ap.add_argument("--pass", dest="pass_no", type=int)
    a = ap.parse_args()
    if a.controls:
        run_controls()
    elif a.pass_no:
        crawl(a.pass_no)
    else:
        ap.error("give --controls or --pass N")


