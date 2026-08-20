#!/usr/bin/env python3
"""Evaluate the permanent evidence-first Rich Facts golden set."""
from __future__ import annotations

import json
from pathlib import Path

from cyberwatch.collectors.frenchbreaches_rich import extract_frenchbreaches_rich_facts
from cyberwatch.rich_facts_consolidation import consolidate_sources

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "data" / "golden" / "rich_facts_golden.json"


def _fail(case_id: str, message: str) -> None:
    raise AssertionError(f"{case_id}: {message}")


def main() -> None:
    data = json.loads(GOLDEN.read_text(encoding="utf-8"))
    passed = 0
    for case in data.get("cases", []):
        case_id = case["id"]
        expect = case.get("expect", {})
        if case.get("claims"):
            payload = consolidate_sources([{"claims": case["claims"]}])
            if "primary" in expect:
                got = payload["primary"]["affected_count"]["value"]
                if got != expect["primary"]:
                    _fail(case_id, f"primary={got}")
            if "divergences" in expect and len(payload["divergences"]) != expect["divergences"]:
                _fail(case_id, f"divergences={len(payload['divergences'])}")
            passed += 1
            continue

        rich = extract_frenchbreaches_rich_facts(case.get("text", "")) or {
            "affected_counts": [], "data_volumes": [], "data_types": [],
            "timeline": [], "vulnerabilities": [], "claims": []
        }
        claims = rich.get("claims") or []
        if "count" in expect and not any(c.get("value") == expect["count"] for c in rich.get("affected_counts", [])):
            _fail(case_id, "count missing")
        if "data_type" in expect and not any(c.get("value") == expect["data_type"] for c in rich.get("data_types", [])):
            _fail(case_id, "data type missing")
        if "status" in expect:
            matching = [c for c in claims if c.get("status") == expect["status"]]
            if not matching and not any(c.get("status") == expect["status"] for key in ("timeline", "data_types", "affected_counts", "data_volumes") for c in rich.get(key, [])):
                _fail(case_id, f"status {expect['status']} missing")
        if expect.get("no_confirmed") and any(c.get("status") == "confirmed" for c in claims):
            _fail(case_id, "negation promoted to confirmed")
        if "volumes" in expect:
            got = sorted(float(c.get("value")) for c in rich.get("data_volumes", []))
            if got != sorted(expect["volumes"]):
                _fail(case_id, f"volumes={got}")
        if "dates" in expect:
            got = [c.get("date") for c in rich.get("timeline", [])]
            for date in expect["dates"]:
                if date not in got:
                    _fail(case_id, f"date {date} missing")
        if "cve" in expect and not any(c.get("value") == expect["cve"] for c in rich.get("vulnerabilities", [])):
            _fail(case_id, "CVE missing")
        passed += 1

    print(json.dumps({"golden_cases": len(data.get("cases", [])), "passed": passed}, indent=2))


if __name__ == "__main__":
    main()
