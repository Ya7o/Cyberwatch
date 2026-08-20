#!/usr/bin/env python3
"""Vérifie la parité du fast-path incrémental sur le snapshot publié."""
from __future__ import annotations

import copy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cyberwatch import store
from cyberwatch.incremental_qualification import parity_failures, qualify_delta
from cyberwatch.qualification import qualify


def main() -> int:
    items = store.load_items()
    incidents = store.load_incidents()
    provenance = store.load_qualification_provenance()
    registry = store.load_incident_id_registry()
    if not items:
        print("INCREMENTAL_QUALIFICATION_PARITY skipped=no_items")
        return 0

    canonical = qualify(copy.deepcopy(items))
    delta = qualify_delta(
        copy.deepcopy(items),
        previous_items=copy.deepcopy(items),
        previous_incidents=copy.deepcopy(incidents),
        previous_provenance=copy.deepcopy(provenance),
        previous_incident_id_registry=copy.deepcopy(registry),
        work_item_ids=[],
    )
    failures = parity_failures(delta.report, canonical)
    print(
        "INCREMENTAL_QUALIFICATION_PARITY "
        f"reused={int(delta.reused_snapshot)} "
        f"items={len(items)} incidents={len(incidents)} "
        f"failures={len(failures)}"
    )
    for failure in failures:
        print(f"- {failure}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
