#!/usr/bin/env python3
"""Vérifie la parité exacte du cache qualification sur le snapshot publié."""
from __future__ import annotations

import copy
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cyberwatch import qualification_cache, store
from cyberwatch.qualification import qualify


def _sorted_rows(rows):
    return sorted(
        (dict(row) for row in rows),
        key=lambda row: tuple((key, str(value)) for key, value in sorted(row.items())),
    )


def main() -> int:
    items = store.load_items()
    if not items:
        print("QUALIFICATION_CACHE_PARITY skipped=no_items")
        return 0

    previous = os.environ.get("CYBERWATCH_QUALIFICATION_CACHE")
    os.environ["CYBERWATCH_QUALIFICATION_CACHE"] = "0"
    try:
        canonical = qualify(copy.deepcopy(items))
    finally:
        if previous is None:
            os.environ.pop("CYBERWATCH_QUALIFICATION_CACHE", None)
        else:
            os.environ["CYBERWATCH_QUALIFICATION_CACHE"] = previous

    payload = qualification_cache.load_pending_cache()
    if not payload:
        print("QUALIFICATION_CACHE_PARITY failure=pending_cache_missing")
        return 1
    cached = qualification_cache.payload_parts(payload)

    failures = []
    if cached["items_hash"] != canonical.items_hash:
        failures.append("items_hash")
    if cached["incidents_hash"] != canonical.incidents_hash:
        failures.append("incidents_hash")
    if [item.to_row() for item in cached["items"]] != [item.to_row() for item in canonical.items]:
        failures.append("items")
    if [incident.to_row() for incident in cached["incidents"]] != [incident.to_row() for incident in canonical.incidents]:
        failures.append("incidents")
    if _sorted_rows(cached["provenance"]) != _sorted_rows(canonical.provenance):
        failures.append("provenance")
    if [decision.to_row() for decision in cached["decisions"]] != [decision.to_row() for decision in canonical.decisions]:
        failures.append("decisions")
    if _sorted_rows(cached["incident_id_registry"]) != _sorted_rows(canonical.incident_id_registry):
        failures.append("incident_id_registry")

    print(
        "QUALIFICATION_CACHE_PARITY "
        f"items={len(canonical.items)} incidents={len(canonical.incidents)} "
        f"failures={len(failures)}"
    )
    for failure in failures:
        print(f"- {failure}")
    qualification_cache.clear_pending_cache()
    qualification_cache.usage_observation_path().unlink(missing_ok=True)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
