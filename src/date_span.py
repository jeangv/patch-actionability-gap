"""Date-span diagnostics for a set of collected CVE records.

Reports the min/max `published` date and distinct-month coverage, so a
stratified sample can be checked for unwanted temporal clustering before its
field-population percentages are reported. Importable (used by pilot_pull.py
to embed this in its report) or runnable directly against a data directory:

    python date_span.py ../data/pilot_20260905_v1
"""
from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path


def parse_published(cve: dict) -> datetime:
    return datetime.strptime(cve["published"][:19], "%Y-%m-%dT%H:%M:%S")


def date_span_stats(records: list[dict]) -> dict:
    if not records:
        return {"count": 0, "min_published": None, "max_published": None, "distinct_months": 0}
    dates = [parse_published(r) for r in records]
    months = {(d.year, d.month) for d in dates}
    return {
        "count": len(records),
        "min_published": min(dates),
        "max_published": max(dates),
        "distinct_months": len(months),
    }


def main() -> None:
    data_dir = Path(sys.argv[1])
    for path in sorted(data_dir.glob("*.json")):
        if path.name == "ambiguous.json":
            continue
        records = json.loads(path.read_text(encoding="utf-8"))
        stats = date_span_stats(records)
        if stats["count"]:
            print(
                f"{path.name}: n={stats['count']} | "
                f"min={stats['min_published'].date()} max={stats['max_published'].date()} | "
                f"distinct_months={stats['distinct_months']}"
            )
        else:
            print(f"{path.name}: n=0")


if __name__ == "__main__":
    main()
