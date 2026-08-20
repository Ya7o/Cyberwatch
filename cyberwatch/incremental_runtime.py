"""Runtime incrémental sûr de qualification.

Le fast-path n'est utilisé que lorsque le dirty-set pré-qualification prouve
qu'aucune entrée métier ni dépendance de qualification n'a changé. Dès qu'un
item est NEW/DIRTY, ou qu'aucun état précédent fiable n'existe, le pipeline
canonique complet reste la référence. Les incidents sont toujours reconstruits
avec la déduplication courante.
"""
from __future__ import annotations

from collections import defaultdict
import os
import time

from . import config, incremental, store
from .incremental_qualification import qualify_delta

_INSTALLED = False
_LAST_MODE = "full"
_LAST_REASON = "disabled"
_LAST_DURATION = 0.0
_LAST_NEW = 0
_LAST_DIRTY = 0
_LAST_UNCHANGED = 0

PREQUAL_STATE_CSV = store.DATA_DIR / "prequalification_state.csv"


def enabled() -> bool:
    value = os.getenv("CYBERWATCH_INCREMENTAL_QUALIFICATION", "0").strip().lower()
    return value in {"1", "true", "yes", "on"}


def last_stats() -> dict[str, object]:
    total = _LAST_NEW + _LAST_DIRTY + _LAST_UNCHANGED
    return {
        "qualification_mode": _LAST_MODE,
        "qualification_reason": _LAST_REASON,
        "qualification_runtime_s": _LAST_DURATION,
        "prequal_new": _LAST_NEW,
        "prequal_dirty": _LAST_DIRTY,
        "prequal_unchanged": _LAST_UNCHANGED,
        "prequal_reuse_rate": (_LAST_UNCHANGED / total) if total else 0.0,
    }


def _dirty_set(items):
    facts_by_item = defaultdict(list)
    for row in store.load_source_facts():
        item_id = str(row.get("Item_ID") or "").strip()
        if item_id:
            facts_by_item[item_id].append(row)
    dependency = incremental.qualification_dependency_digest(
        store.ROOT,
        reference_rows=store.read_csv(store.ENRICHMENT_REFERENCE_CSV),
        org_cache_rows=store.load_org_enrichment_cache(),
    )
    previous = incremental.fingerprints_from_state(
        store.read_csv(PREQUAL_STATE_CSV), column="Prequalification_Fingerprint"
    )
    return incremental.classify_prequalification_items(
        items,
        previous,
        facts_by_item=facts_by_item,
        policy_version=config.METHOD_ID,
        dependency_digest_value=dependency,
    )


def install() -> None:
    global _INSTALLED
    if _INSTALLED:
        return
    from . import runner

    canonical = runner.qualify

    def runtime_qualify(items):
        global _LAST_MODE, _LAST_REASON, _LAST_DURATION
        global _LAST_NEW, _LAST_DIRTY, _LAST_UNCHANGED
        started = time.monotonic()
        try:
            if not enabled():
                _LAST_MODE, _LAST_REASON = "full", "disabled"
                _LAST_NEW = _LAST_DIRTY = _LAST_UNCHANGED = 0
                return canonical(items)

            dirty = _dirty_set(items)
            _LAST_NEW = len(dirty.new)
            _LAST_DIRTY = len(dirty.dirty)
            _LAST_UNCHANGED = len(dirty.unchanged)
            if dirty.work_item_ids:
                _LAST_MODE = "full"
                _LAST_REASON = "new_or_dirty_items"
                return canonical(items)

            previous_items = store.load_items()
            if len(previous_items) != len(items):
                _LAST_MODE, _LAST_REASON = "full", "snapshot_count_changed"
                return canonical(items)

            result = qualify_delta(
                items,
                previous_items=previous_items,
                previous_incidents=store.load_incidents(),
                previous_provenance=store.load_qualification_provenance(),
                previous_incident_id_registry=store.load_incident_id_registry(),
                work_item_ids=dirty.work_item_ids,
            )
            _LAST_MODE = "delta" if result.reused_snapshot else "full"
            _LAST_REASON = result.fallback_reason
            return result.report
        finally:
            _LAST_DURATION = round(time.monotonic() - started, 3)

    runner.qualify = runtime_qualify
    runner._incremental_runtime_installed = True
    _INSTALLED = True
