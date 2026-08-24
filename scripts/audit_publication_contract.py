#!/usr/bin/env python3
"""Vérifie les contrats des JSON publiés sans les modifier."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from cyberwatch import publication_audit, store


def _load(path: Path, fallback):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return fallback


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--incidents", type=Path, default=store.SITE_DATA_DIR / "incidents.json")
    parser.add_argument("--facts", type=Path, default=store.SITE_DATA_DIR / "facts.json")
    parser.add_argument("--report", type=Path, default=store.DATA_DIR / "source_facts_backfill_report.json")
    args = parser.parse_args()
    result = publication_audit.audit_payload(
        _load(args.incidents, []),
        _load(args.facts, {}),
        _load(args.report, None),
    )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
