#!/usr/bin/env python3
"""Produce the publication-quality report from already collected facts.

This is intentionally read-only with respect to collection and LLM caches.
It turns persisted SourceFacts statuses into the per-incident audit contract
used by a reset or release gate.
"""
from __future__ import annotations

import argparse
from pathlib import Path

from cyberwatch import store
from scripts.backfill_source_fact_summaries import reports_from_existing_source_facts


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output", type=Path,
        default=store.DATA_DIR / "source_facts_backfill_report.json",
    )
    args = parser.parse_args()
    reports = reports_from_existing_source_facts(
        store.load_items(), store.load_source_facts()
    )
    store.write_json(args.output, {
        "schema_version": 3,
        "metrics": {
            "mode": "persisted_source_facts_audit",
            "incidents_reported": len(reports),
        },
        "incidents": reports,
    })
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
