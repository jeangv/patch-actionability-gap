"""Shared client for the NVD CVE API 2.0.

Handles API-key loading (from .env), conservative rate limiting with
exponential backoff, and generator-based pagination so callers never hold
the full result set in memory at once.
"""
from __future__ import annotations

import os
import random
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterator, Optional

import requests
from dotenv import load_dotenv

load_dotenv()

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
USER_AGENT = (
    "patch-actionability-gap-research/0.1 "
    "(GT OMSCS CS-6727 practicum measurement study; non-commercial research)"
)
MAX_RESULTS_PER_PAGE = 2000
MAX_DATE_WINDOW_DAYS = 120  # NVD API hard limit on pubStartDate/pubEndDate span
NVD_DATE_FMT = "%Y-%m-%dT%H:%M:%S.000"


def _api_key() -> Optional[str]:
    return os.environ.get("NVD_API_KEY")


def _headers() -> dict:
    headers = {"User-Agent": USER_AGENT}
    key = _api_key()
    if key:
        headers["apiKey"] = key
    return headers


def _min_interval_seconds() -> float:
    # NVD allows 50 req/30s with a key, 5 req/30s without. Stay well under both.
    return 0.7 if _api_key() else 6.5


class NvdClient:
    def __init__(self) -> None:
        self._last_request_at = 0.0

    def _throttle(self) -> None:
        elapsed = time.monotonic() - self._last_request_at
        wait = _min_interval_seconds() - elapsed
        if wait > 0:
            time.sleep(wait)

    def get_page(self, params: dict) -> dict:
        last_exc: Optional[Exception] = None
        for attempt in range(6):
            self._throttle()
            self._last_request_at = time.monotonic()
            try:
                resp = requests.get(
                    BASE_URL, headers=_headers(), params=params, timeout=60
                )
            except requests.RequestException as exc:
                last_exc = exc
                time.sleep(min(60, (2**attempt) + random.uniform(0, 1)))
                continue
            if resp.status_code == 200:
                return resp.json()
            if resp.status_code in (403, 404, 429, 500, 503, 520):
                last_exc = RuntimeError(
                    f"NVD API {resp.status_code}: {resp.text[:300]}"
                )
                time.sleep(min(60, (2**attempt) + random.uniform(0, 1)))
                continue
            resp.raise_for_status()
        raise RuntimeError(
            f"NVD API request failed after retries: params={params}"
        ) from last_exc

    def iter_cves(self, extra_params: Optional[dict] = None) -> Iterator[dict]:
        """Yield every CVE item (the inner ``cve`` object) for the given filters."""
        params = dict(extra_params or {})
        params["resultsPerPage"] = MAX_RESULTS_PER_PAGE
        start_index = 0
        while True:
            params["startIndex"] = start_index
            page = self.get_page(params)
            vulns = page.get("vulnerabilities", [])
            for v in vulns:
                yield v.get("cve", {})
            total = page.get("totalResults", 0)
            start_index += len(vulns)
            if not vulns or start_index >= total:
                break


@dataclass(frozen=True)
class DateWindow:
    start: datetime
    end: datetime

    def as_params(self) -> dict:
        return {
            "pubStartDate": self.start.strftime(NVD_DATE_FMT),
            "pubEndDate": self.end.strftime(NVD_DATE_FMT),
        }


def date_windows(
    start: datetime, end: datetime, max_days: int = MAX_DATE_WINDOW_DAYS
) -> Iterator[DateWindow]:
    """Split [start, end] into consecutive, non-overlapping windows of at most
    ``max_days`` days each, respecting the NVD API's date-range cap."""
    cur = start
    while cur < end:
        window_end = min(cur + timedelta(days=max_days - 1), end)
        yield DateWindow(cur, window_end)
        cur = window_end + timedelta(seconds=1)
