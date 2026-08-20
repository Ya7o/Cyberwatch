"""Optimisations incrémentales et télémétrie de performance.

Les fast-paths de ce module restent auxiliaires : ils évitent du travail externe
coûteux quand une preuve de fraîcheur forte existe, mais ne modifient jamais la
qualification canonique ni les hashes ITEMS/INCIDENTS.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Callable

_INSTALLED = False
_CACHE_BY_ITEM: dict[str, dict] | None = None
_FULL_FACT_CACHE_HITS = 0
_FRENCH_DETAIL_CACHE_HITS = 0
_FRENCH_DETAIL_NETWORK_FETCHES = 0
_FRENCH_DETAIL_STALE_FALLBACKS = 0
_LAST_QUALIFY_DURATION = 0.0

PERFORMANCE_FORMAT = "cyberwatch-performance-v1"
FRENCH_DETAIL_CACHE_FORMAT = "frenchbreaches-detail-cache-v1"


def _enabled() -> bool:
    value = os.getenv("CYBERWATCH_INCREMENTAL_SOURCE_FACTS", "1").strip().lower()
    return value not in {"0", "false", "no", "off"}


def _load_cache() -> dict[str, dict]:
    global _CACHE_BY_ITEM
    if _CACHE_BY_ITEM is not None:
        return _CACHE_BY_ITEM
    from . import store
    _CACHE_BY_ITEM = {
        str(row.get("Item_ID") or "").strip(): row
        for row in store.load_source_facts()
        if str(row.get("Item_ID") or "").strip()
    }
    return _CACHE_BY_ITEM


def _metadata(row: dict) -> dict:
    raw = str(row.get("Source_Metadata_JSON") or "").strip()
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _reusable_fact(item, entry, spec) -> dict | None:
    if not _enabled():
        return None
    from . import source_facts, source_facts_ai
    if spec.source_id not in source_facts_ai.TARGET_SOURCES:
        return None
    cached = _load_cache().get(item.Item_ID)
    if not cached:
        return None
    if str(cached.get("Source_ID") or "") != item.Source_ID:
        return None
    if str(cached.get("Extraction_Version") or "") != source_facts.SOURCE_FACTS_VERSION:
        return None
    previous_hash = str(_metadata(cached).get("_source_facts_content_hash") or "")
    current_hash = source_facts_ai.content_hash(entry)
    if not previous_hash or previous_hash != current_hash:
        return None
    return dict(cached)


def _apply_cached_sector_side_effect(item, fact: dict) -> None:
    try:
        from . import config, sector
        from .sector_completion import _strong_activity_sector
    except ImportError:
        return
    if item.Sector != config.SECTOR_UNKNOWN:
        return
    raw_sector = str(fact.get("Source_Sector_Raw") or "").strip()
    if raw_sector:
        candidate = sector.classify_source_sector(raw_sector)
        if candidate in config.SECTORS and candidate != config.SECTOR_UNKNOWN:
            item.Sector = candidate
            return
    activity = str(fact.get("Activity_Description") or "").strip()
    candidate = _strong_activity_sector(activity)
    if candidate in config.SECTORS and candidate != config.SECTOR_UNKNOWN:
        item.Sector = candidate


def _patch_source_facts() -> None:
    from . import source_facts
    if getattr(source_facts, "_incremental_performance_installed", False):
        return
    original_extract: Callable = source_facts.extract_source_fact

    def extract_source_fact(item, entry, spec):
        global _FULL_FACT_CACHE_HITS
        cached = _reusable_fact(item, entry, spec)
        if cached is not None:
            _FULL_FACT_CACHE_HITS += 1
            _apply_cached_sector_side_effect(item, cached)
            return cached
        return original_extract(item, entry, spec)

    source_facts.extract_source_fact = extract_source_fact
    source_facts._incremental_performance_installed = True


def _french_cache_path() -> Path:
    value = os.getenv("FRENCHBREACHES_DETAIL_CACHE_PATH", "").strip()
    if value:
        return Path(value)
    from . import store
    return store.DATA_DIR / "frenchbreaches_detail_cache.json"


def _performance_path() -> Path:
    value = os.getenv("CYBERWATCH_PERFORMANCE_LOG_PATH", "").strip()
    if value:
        return Path(value)
    from . import store
    return store.DATA_DIR / "performance_runs.json"


def _load_json(path: Path, default):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return default
    return value


def _write_json(path: Path, payload) -> None:
    from . import store
    store.write_json(path, payload)


def _entry_fingerprint(entry) -> str:
    raw = "\n".join(str(value or "").strip() for value in (
        entry.url, entry.published, entry.title, entry.summary,
    ))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _cache_age_days(value: str) -> float:
    try:
        stamp = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=dt.timezone.utc)
        return max(0.0, (dt.datetime.now(dt.timezone.utc) - stamp).total_seconds() / 86400)
    except (TypeError, ValueError):
        return 1e9


def _patch_frenchbreaches_hydration() -> None:
    from .collectors import feed
    if getattr(feed, "_incremental_detail_cache_installed", False):
        return

    def hydrate(client, entries, budget):
        global _FRENCH_DETAIL_CACHE_HITS, _FRENCH_DETAIL_NETWORK_FETCHES
        global _FRENCH_DETAIL_STALE_FALLBACKS
        try:
            ttl_days = max(0.0, float(os.getenv("FRENCHBREACHES_DETAIL_CACHE_TTL_DAYS", "7")))
        except ValueError:
            ttl_days = 7.0
        path = _french_cache_path()
        payload = _load_json(path, {})
        cache = payload.get("entries", {}) if isinstance(payload, dict) else {}
        if not isinstance(cache, dict):
            cache = {}
        attempted = 0
        hydrated = 0
        changed = False
        now = dt.datetime.now(dt.timezone.utc).isoformat()

        for entry in entries:
            if not entry.url:
                continue
            attempted += 1
            fingerprint = _entry_fingerprint(entry)
            cached = cache.get(entry.url)
            cached_content = str(cached.get("content") or "") if isinstance(cached, dict) else ""
            valid = (
                isinstance(cached, dict)
                and cached.get("fingerprint") == fingerprint
                and cached_content.strip()
                and _cache_age_days(str(cached.get("fetched_at") or "")) <= ttl_days
            )
            if valid:
                entry.content = cached_content[:40000]
                hydrated += 1
                _FRENCH_DETAIL_CACHE_HITS += 1
                continue
            if budget.exhausted:
                if cached_content.strip():
                    entry.content = cached_content[:40000]
                    hydrated += 1
                    _FRENCH_DETAIL_STALE_FALLBACKS += 1
                break
            _FRENCH_DETAIL_NETWORK_FETCHES += 1
            response = client.fetch(entry.url, budget)
            if response.ok:
                text = feed.stable_frenchbreaches_detail_text(response.text)
                if text:
                    entry.content = text[:40000]
                    cache[entry.url] = {
                        "fingerprint": fingerprint,
                        "fetched_at": now,
                        "content": entry.content,
                    }
                    hydrated += 1
                    changed = True
                    continue
            if cached_content.strip():
                entry.content = cached_content[:40000]
                hydrated += 1
                _FRENCH_DETAIL_STALE_FALLBACKS += 1

        if changed:
            _write_json(path, {"_format": FRENCH_DETAIL_CACHE_FORMAT, "entries": cache})
        return attempted, hydrated

    feed._hydrate_frenchbreaches_details = hydrate
    feed._incremental_detail_cache_installed = True


def _patch_qualification_timer() -> None:
    from . import qualification, runner
    if getattr(runner, "_incremental_perf_qualify_timer_installed", False):
        return
    original = runner.qualify

    def qualify(items):
        global _LAST_QUALIFY_DURATION
        started = time.monotonic()
        try:
            return original(items)
        finally:
            _LAST_QUALIFY_DURATION = round(time.monotonic() - started, 3)

    runner.qualify = qualify
    qualification.qualify = qualify
    runner._incremental_perf_qualify_timer_installed = True
    qualification._incremental_perf_timer_installed = True


def _item_signature(item) -> tuple:
    row = item.to_row()
    return tuple((key, row.get(key, "")) for key in sorted(row) if key != "Collected_As_Of")


def _load_performance_history() -> list[dict]:
    payload = _load_json(_performance_path(), {})
    if not isinstance(payload, dict) or payload.get("_format") != PERFORMANCE_FORMAT:
        return []
    rows = payload.get("runs")
    return rows if isinstance(rows, list) else []


def _save_performance_row(row: dict) -> None:
    rows = [old for old in _load_performance_history() if old.get("run_id") != row.get("run_id")]
    rows.append(row)
    _write_json(_performance_path(), {"_format": PERFORMANCE_FORMAT, "runs": rows[-200:]})


def _patch_runner_telemetry() -> None:
    from . import runner, store
    if getattr(runner, "_incremental_perf_telemetry_installed", False):
        return
    original = runner.execute

    def execute(context, offline=False, persist=True):
        before_items = store.load_items()
        before = {item.Item_ID: _item_signature(item) for item in before_items}
        counters_before = stats()
        report = original(context, offline=offline, persist=persist)
        counters_after = stats()
        current = {item.Item_ID: _item_signature(item) for item in report.items}
        existing_ids = set(before) & set(current)
        modified = sum(before[item_id] != current[item_id] for item_id in existing_ids)
        unchanged = len(existing_ids) - modified
        row = {
            "run_id": context.run_id,
            "as_of": context.as_of,
            "mode": context.mode,
            "duration_s": report.duration,
            "qualify_duration_s": _LAST_QUALIFY_DURATION,
            "items_before": len(before_items),
            "items_after": len(report.items),
            "items_new": report.new_items,
            "snapshot_items_modified": modified,
            "snapshot_items_unchanged": unchanged,
            "sourcefacts_reused": counters_after["full_fact_cache_hits"] - counters_before["full_fact_cache_hits"],
            "sourcefacts_llm_calls": sum(getattr(o, "source_facts_llm_calls", 0) for o in report.outcomes),
            "sourcefacts_llm_duration_s": round(sum(getattr(o, "source_facts_llm_duration_seconds", 0.0) for o in report.outcomes), 3),
            "french_detail_cache_hits": counters_after["french_detail_cache_hits"] - counters_before["french_detail_cache_hits"],
            "french_detail_network_fetches": counters_after["french_detail_network_fetches"] - counters_before["french_detail_network_fetches"],
            "french_detail_stale_fallbacks": counters_after["french_detail_stale_fallbacks"] - counters_before["french_detail_stale_fallbacks"],
            "requests": report.requests,
            "overall": report.overall,
        }
        report.performance = row
        if persist:
            try:
                _save_performance_row(row)
            except OSError:
                pass
        return report

    runner.execute = execute
    runner._incremental_perf_telemetry_installed = True


def _patch_site_status() -> None:
    from . import site
    if getattr(site, "_incremental_perf_status_installed", False):
        return
    original = site.status_payload

    def status_payload():
        payload = original()
        history = _load_performance_history()
        payload["performance"] = {
            "latest": history[-1] if history else {},
            "history": history[-30:],
        }
        return payload

    site.status_payload = status_payload
    site._incremental_perf_status_installed = True


def stats() -> dict[str, int]:
    return {
        "full_fact_cache_hits": _FULL_FACT_CACHE_HITS,
        "french_detail_cache_hits": _FRENCH_DETAIL_CACHE_HITS,
        "french_detail_network_fetches": _FRENCH_DETAIL_NETWORK_FETCHES,
        "french_detail_stale_fallbacks": _FRENCH_DETAIL_STALE_FALLBACKS,
    }


def reset_for_tests() -> None:
    global _CACHE_BY_ITEM, _FULL_FACT_CACHE_HITS
    global _FRENCH_DETAIL_CACHE_HITS, _FRENCH_DETAIL_NETWORK_FETCHES
    global _FRENCH_DETAIL_STALE_FALLBACKS, _LAST_QUALIFY_DURATION
    _CACHE_BY_ITEM = None
    _FULL_FACT_CACHE_HITS = 0
    _FRENCH_DETAIL_CACHE_HITS = 0
    _FRENCH_DETAIL_NETWORK_FETCHES = 0
    _FRENCH_DETAIL_STALE_FALLBACKS = 0
    _LAST_QUALIFY_DURATION = 0.0


def install() -> None:
    global _INSTALLED
    if _INSTALLED:
        return
    _patch_source_facts()
    _patch_frenchbreaches_hydration()
    _patch_qualification_timer()
    _patch_runner_telemetry()
    _patch_site_status()
    _INSTALLED = True
