"""Activation runtime prudente de la qualification incrémentale.

Le runtime est opt-in. Il n'autorise actuellement que le fast-path dont la
parité est démontrée : snapshot métier strictement inchangé. Tout NEW/DIRTY ou
toute absence de preuve retombe sur ``qualify()`` canonique.
"""
from __future__ import annotations

import os
import time

from . import identity, store
from .incremental_qualification import qualify_delta

_INSTALLED = False
_LAST_MODE = "full"
_LAST_REASON = "disabled"
_LAST_DURATION = 0.0


def enabled() -> bool:
    value = os.getenv("CYBERWATCH_INCREMENTAL_QUALIFICATION", "0").strip().lower()
    return value in {"1", "true", "yes", "on"}


def last_stats() -> dict[str, object]:
    return {
        "qualification_mode": _LAST_MODE,
        "qualification_reason": _LAST_REASON,
        "qualification_runtime_s": _LAST_DURATION,
    }


def _same_business_snapshot(items, previous_items) -> bool:
    return len(items) == len(previous_items) and identity.items_hash(items) == identity.items_hash(previous_items)


def install() -> None:
    global _INSTALLED
    if _INSTALLED:
        return
    from . import runner

    canonical = runner.qualify

    def runtime_qualify(items):
        global _LAST_MODE, _LAST_REASON, _LAST_DURATION
        started = time.monotonic()
        try:
            if not enabled():
                _LAST_MODE, _LAST_REASON = "full", "disabled"
                return canonical(items)

            previous_items = store.load_items()
            # La preuve de sûreté actuelle est volontairement plus stricte que
            # l'observer post-qualification : aucun changement métier du snapshot.
            if not _same_business_snapshot(items, previous_items):
                _LAST_MODE, _LAST_REASON = "full", "snapshot_changed"
                return canonical(items)

            result = qualify_delta(
                items,
                previous_items=previous_items,
                previous_incidents=store.load_incidents(),
                previous_provenance=store.load_qualification_provenance(),
                previous_incident_id_registry=store.load_incident_id_registry(),
                work_item_ids=(),
            )
            _LAST_MODE = "delta" if result.reused_snapshot else "full"
            _LAST_REASON = result.fallback_reason
            return result.report
        finally:
            _LAST_DURATION = round(time.monotonic() - started, 3)

    runner.qualify = runtime_qualify
    runner._incremental_runtime_installed = True
    _INSTALLED = True
