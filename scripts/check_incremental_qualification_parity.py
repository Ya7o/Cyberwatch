#!/usr/bin/env python3
"""Vérifie la parité du runtime incrémental sur le snapshot publié.

Le gate utilise le même dirty-set que la production. Si une dépendance, une
policy ou un item a changé, le résultat attendu est un fallback canonique ; le
fast-path n'est testé que lorsque l'état publié est réellement réutilisable.
"""
from __future__ import annotations

import copy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cyberwatch import incremental_runtime, store
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

    dirty = incremental_runtime._dirty_set(copy.deepcopy(items))
    canonical = qualify(copy.deepcopy(items))
    delta = qualify_delta(
        copy.deepcopy(items),
        previous_items=copy.deepcopy(items),
        previous_incidents=copy.deepcopy(incidents),
        previous_provenance=copy.deepcopy(provenance),
        previous_incident_id_registry=copy.deepcopy(registry),
        work_item_ids=dirty.work_item_ids,
    )
    failures = parity_failures(delta.report, canonical)
    expected_mode = "delta" if not dirty.work_item_ids else "full"
    if delta.reused_snapshot != (expected_mode == "delta"):
        failures.append(
            f"runtime_mode: expected={expected_mode} "
            f"reused={int(delta.reused_snapshot)} reason={delta.fallback_reason}"
        )
    print(
        "INCREMENTAL_QUALIFICATION_PARITY "
        f"mode={expected_mode} reused={int(delta.reused_snapshot)} "
        f"new={len(dirty.new)} dirty={len(dirty.dirty)} "
        f"unchanged={len(dirty.unchanged)} "
        f"items={len(items)} incidents={len(incidents)} "
        f"failures={len(failures)}"
    )
    for failure in failures:
        print(f"- {failure}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
