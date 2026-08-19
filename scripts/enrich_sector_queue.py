#!/usr/bin/env python3
"""Enrichit la file Sector avec exécution incrémentale et purge ciblée.

Modes :
- ``golden-only`` : cible les organisations du Golden (ou une liste explicite) ;
- ``sector-only`` : ne retente que les organisations absentes du cache ou expirées ;
- ``full`` : rescane toute la file.

En ``golden-only``, les classifications Sector qui contredisent le Golden sont
invalidées de façon ciblée avant le rejeu. La purge ne touche ni l'identité
légale ni les autres organisations : le secteur courant est remis à ``Inconnu``
et la validation Sector du cache est vidée, afin que l'organisation soit
réévaluée depuis les preuves au lieu de recycler sa propre ancienne décision.
"""
from __future__ import annotations

import datetime as dt
import os
import re
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cyberwatch import (
    company_subject_evidence,
    config,
    official_site_discovery,
    org_enrichment,
    sector_registry,
    store,
)
from cyberwatch.model import ORG_ENRICHMENT_CACHE_COLUMNS

_URL_RE = re.compile(r"https?://[^\s|,;]+", re.I)
_VALID_MODES = {"golden-only", "sector-only", "full"}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() not in {"0", "false", "no", "off", ""}


def _empty_cache_row() -> dict[str, str]:
    return {column: "" for column in ORG_ENRICHMENT_CACHE_COLUMNS}


def _parse_iso(value: str) -> dt.datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def _retry_delay(row: dict | None) -> dt.timedelta:
    status = str((row or {}).get("Match_Status") or "").strip()
    if status == org_enrichment.ERROR:
        return dt.timedelta(hours=max(1, _env_int("SECTOR_RETRY_ERROR_HOURS", 6)))
    if status == org_enrichment.NOT_FOUND:
        return dt.timedelta(days=max(1, _env_int("SECTOR_RETRY_NOT_FOUND_DAYS", 7)))
    if status == org_enrichment.AMBIGUOUS:
        return dt.timedelta(days=max(1, _env_int("SECTOR_RETRY_AMBIGUOUS_DAYS", 30)))
    if status == org_enrichment.MATCHED:
        return dt.timedelta(days=max(1, _env_int("SECTOR_RETRY_MATCHED_DAYS", 30)))
    return dt.timedelta(0)


def _cache_fresh(row: dict | None, now_utc: dt.datetime) -> bool:
    if not row:
        return False
    fetched_at = _parse_iso(row.get("Fetched_At", ""))
    if fetched_at is None:
        return False
    return now_utc - fetched_at < _retry_delay(row)


def _target_keys_from_env() -> set[str]:
    raw = os.getenv("SECTOR_ENRICHMENT_TARGET_KEYS", "")
    return {part.strip() for part in re.split(r"[,|\n]", raw) if part.strip()}


def _golden_rows() -> list[dict]:
    return store.read_csv(ROOT / "data" / "golden" / "qualification_golden.csv")


def _golden_keys() -> set[str]:
    return {
        (row.get("Organisation_Key") or "").strip()
        for row in _golden_rows()
        if (row.get("Organisation_Key") or "").strip()
    }


def _golden_expected_sector_by_key() -> dict[str, str]:
    result: dict[str, str] = {}
    for row in _golden_rows():
        key = (row.get("Organisation_Key") or "").strip()
        expected = (row.get("Secteur_REF") or "").strip()
        if key and expected in config.SECTORS:
            result[key] = expected
    return result


def _purge_golden_mismatches(
    items,
    cache: dict[str, dict],
    mode: str,
) -> tuple[set[str], dict[str, int]]:
    """Invalide uniquement les décisions Sector Golden actuellement fausses.

    Le cache conserve les métadonnées d'identité (SIREN, nom légal, URL) mais
    perd toute conclusion Sector issue de l'ancienne politique. ``Fetched_At``
    est vidé pour forcer le rejeu même si la ligne était récente.
    """
    if mode != "golden-only" or not _env_bool("SECTOR_PURGE_GOLDEN_MISMATCHES", True):
        return set(), {"purged_organisations": 0, "purged_items": 0, "purged_cache_rows": 0}

    expected = _golden_expected_sector_by_key()
    explicit = _target_keys_from_env()
    current: dict[str, set[str]] = defaultdict(set)
    for item in items:
        if item.Organisation_Key:
            current[item.Organisation_Key].add(item.Sector)

    purge_keys = {
        key
        for key, expected_sector in expected.items()
        if (not explicit or key in explicit)
        and key in current
        and any(value != expected_sector for value in current[key])
    }

    purged_items = 0
    for item in items:
        if item.Organisation_Key in purge_keys and item.Sector != config.SECTOR_UNKNOWN:
            item.Sector = config.SECTOR_UNKNOWN
            purged_items += 1

    purged_cache_rows = 0
    for key in purge_keys:
        row = cache.get(key)
        if row is None:
            continue
        row["Validated_Sector"] = ""
        row["Validated_Via"] = ""
        row["Activity_Label"] = ""
        row["Fetched_At"] = ""
        purged_cache_rows += 1

    if purged_items:
        store.save_items(items)

    return purge_keys, {
        "purged_organisations": len(purge_keys),
        "purged_items": purged_items,
        "purged_cache_rows": purged_cache_rows,
    }


def _augment_queue_with_targets(queue: list[dict], items, target_keys: set[str]) -> list[dict]:
    """Ajoute les cibles connues absentes de la queue des ``Inconnu``.

    C'est nécessaire pour corriger une classification connue mais fausse : la
    queue historique ne contenait que les organisations déjà ``Inconnu``.
    """
    if not target_keys:
        return queue
    existing = {(row.get("Organisation_Key") or "").strip() for row in queue}
    grouped = defaultdict(list)
    for item in items:
        if item.Organisation_Key in target_keys:
            grouped[item.Organisation_Key].append(item)
    augmented = list(queue)
    for key in sorted(target_keys - existing):
        rows = grouped.get(key, [])
        if not rows:
            continue
        organisation = next((item.Organisation_Raw for item in rows if item.Organisation_Raw), key)
        sources = sorted({item.Source_ID for item in rows if item.Source_ID})
        urls = sorted({item.URL for item in rows if item.URL})
        augmented.append({
            "Priority": "0",
            "Organisation_Key": key,
            "Organisation": organisation,
            "Unknown_Items": str(len(rows)),
            "Sources": " | ".join(sources),
            "Category": "GOLDEN_REEVALUATION",
            "Candidate_Sectors": "",
            "Raw_Sector_Values": "",
            "Evidence_Type": "",
            "Evidence_URLs": " | ".join(urls),
            "Evidence_Text": "",
            "Registry_Decision": "",
            "Reason": "classification Golden réévaluée après purge ciblée",
        })
    return augmented


def _select_queue_rows(
    queue: list[dict],
    cache: dict[str, dict],
    mode: str,
    now_utc: dt.datetime,
) -> tuple[list[dict], dict[str, int]]:
    explicit = _target_keys_from_env()
    golden = _golden_keys() if mode == "golden-only" and not explicit else set()
    selected: list[dict] = []
    skipped_fresh = 0
    skipped_scope = 0

    for row in queue:
        key = (row.get("Organisation_Key") or "").strip()
        if not key:
            continue
        if explicit and key not in explicit:
            skipped_scope += 1
            continue
        if mode == "golden-only" and not explicit and key not in golden:
            skipped_scope += 1
            continue
        if mode != "full" and _cache_fresh(cache.get(key), now_utc):
            skipped_fresh += 1
            continue
        selected.append(row)

    limit = max(0, _env_int("SECTOR_ENRICHMENT_MAX_ORGS", 60))
    if limit:
        selected = selected[:limit]
    return selected, {
        "queue_total": len(queue),
        "skipped_fresh_cache": skipped_fresh,
        "skipped_scope": skipped_scope,
    }


def _source_fact_website_hints() -> dict[str, tuple[str, ...]]:
    item_to_key = {
        item.Item_ID: item.Organisation_Key
        for item in store.load_items()
        if item.Item_ID and item.Organisation_Key
    }
    values: dict[str, list[str]] = defaultdict(list)
    for row in store.read_csv(store.SOURCE_FACTS_CSV):
        key = item_to_key.get((row.get("Item_ID") or "").strip(), "")
        website = str(row.get("Victim_Website") or "").strip()
        if not key or not website:
            continue
        if not website.startswith(("http://", "https://")) and "." in website:
            website = "https://" + website
        if website.startswith(("http://", "https://")) and website not in values[key]:
            values[key].append(website)
    return {key: tuple(rows) for key, rows in values.items()}


def _hint_urls(queue_row: dict, cache_row: dict | None = None, source_fact_hints: tuple[str, ...] = ()) -> tuple[str, ...]:
    values: list[str] = []
    for hint in source_fact_hints:
        hint = str(hint or "").strip()
        if hint and hint not in values:
            values.append(hint)
    for field in ("Evidence_URLs", "Evidence_Text"):
        for match in _URL_RE.findall(str(queue_row.get(field) or "")):
            if match not in values:
                values.append(match)
    if cache_row:
        cached = str(cache_row.get("Evidence_URL") or "").strip()
        if cached and cached not in values:
            values.append(cached)
    return tuple(values)


def _strict_official(organisation: str, hint_urls: tuple[str, ...]):
    started = time.monotonic()
    try:
        candidates = official_site_discovery.discover_official_sites(organisation, hint_urls)
        evidence = company_subject_evidence.resolve_official_site_subject_attributed(organisation, candidates)
        return evidence, len(candidates), time.monotonic() - started
    except Exception:
        return None, 0, time.monotonic() - started


def main() -> int:
    started_total = time.monotonic()
    mode = os.getenv("SECTOR_ENRICHMENT_MODE", "sector-only").strip() or "sector-only"
    if mode not in _VALID_MODES:
        print(f"SECTOR ENRICHMENT: mode invalide {mode!r}", file=sys.stderr)
        return 2

    workers = max(1, min(8, _env_int("SECTOR_ENRICHMENT_WORKERS", 6)))
    source_fact_hints = _source_fact_website_hints()
    state = org_enrichment.start_state()
    if not state.enabled:
        state.enabled = True
    state.official_site_max_calls = 0

    items = store.load_items()
    purge_keys, purge_stats = _purge_golden_mismatches(items, state.cache, mode)

    queue_path = store.ITEMS_CSV.parent / sector_registry.QUEUE_CSV.name
    queue = store.read_csv(queue_path)
    explicit = _target_keys_from_env()
    targets_to_add = explicit or purge_keys
    if mode == "golden-only" and not targets_to_add:
        targets_to_add = _golden_keys()
    queue = _augment_queue_with_targets(queue, items, targets_to_add)
    if not queue:
        print("SECTOR ENRICHMENT: queue vide")
        return 0

    now_dt = dt.datetime.now(dt.timezone.utc)
    now = now_dt.astimezone(dt.timezone(dt.timedelta(hours=4))).isoformat()
    selected, selection_stats = _select_queue_rows(queue, state.cache, mode, now_dt)
    state.max_calls = max(state.max_calls, len(selected))

    stats: dict[str, int | float | str] = {
        "mode": mode,
        **purge_stats,
        **selection_stats,
        "selected": len(selected),
        "registry_attempted": 0,
        "registry_matched": 0,
        "strict_official_attempted": 0,
        "strict_official_targets_with_candidates": 0,
        "strict_official_candidate_urls": 0,
        "strict_official_matched": 0,
        "strict_official_skipped_validated_cache": 0,
        "hinted_targets": 0,
        "source_fact_hinted_targets": 0,
        "cache_existing": 0,
        "official_workers": workers,
        "registry_duration_s": 0.0,
        "official_duration_s": 0.0,
        "official_task_p95_s": 0.0,
        "total_duration_s": 0.0,
    }
    targets: list[tuple[str, str, tuple[str, ...]]] = []

    registry_started = time.monotonic()
    for queue_row in selected:
        key = (queue_row.get("Organisation_Key") or "").strip()
        organisation = (queue_row.get("Organisation") or "").strip()
        if not key or not organisation:
            continue

        existing = state.cache.get(key)
        if existing:
            stats["cache_existing"] = int(stats["cache_existing"]) + 1
        sf_hints = source_fact_hints.get(key, ())
        if sf_hints:
            stats["source_fact_hinted_targets"] = int(stats["source_fact_hinted_targets"]) + 1
        hints = _hint_urls(queue_row, existing, sf_hints)
        if hints:
            stats["hinted_targets"] = int(stats["hinted_targets"]) + 1

        record = None
        if not existing or existing.get("Match_Status") not in {org_enrichment.MATCHED, org_enrichment.AMBIGUOUS}:
            stats["registry_attempted"] = int(stats["registry_attempted"]) + 1
            record = org_enrichment.resolve(key, organisation, now, state)
        elif existing.get("Match_Status") == org_enrichment.MATCHED:
            stats["registry_matched"] = int(stats["registry_matched"]) + 1
        if record is not None and record.Match_Status == org_enrichment.MATCHED:
            stats["registry_matched"] = int(stats["registry_matched"]) + 1

        current = state.cache.get(key) or existing or {}
        if current.get("Validated_Sector") and current.get("Validated_Via"):
            stats["strict_official_skipped_validated_cache"] = int(stats["strict_official_skipped_validated_cache"]) + 1
            continue
        targets.append((key, organisation, hints))

    stats["registry_duration_s"] = round(time.monotonic() - registry_started, 3)

    evidence_by_key = {}
    task_durations: list[float] = []
    stats["strict_official_attempted"] = len(targets)
    official_started = time.monotonic()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_strict_official, organisation, hints): (key, organisation)
            for key, organisation, hints in targets
        }
        for future in as_completed(futures):
            key, organisation = futures[future]
            evidence, candidate_count, duration = future.result()
            task_durations.append(duration)
            stats["strict_official_candidate_urls"] = int(stats["strict_official_candidate_urls"]) + candidate_count
            if candidate_count:
                stats["strict_official_targets_with_candidates"] = int(stats["strict_official_targets_with_candidates"]) + 1
            if evidence is not None:
                evidence_by_key[key] = (organisation, evidence)
    stats["official_duration_s"] = round(time.monotonic() - official_started, 3)
    if task_durations:
        ordered = sorted(task_durations)
        idx = min(len(ordered) - 1, max(0, int(round(0.95 * len(ordered) + 0.499999)) - 1))
        stats["official_task_p95_s"] = round(ordered[idx], 3)

    for key, (organisation, evidence) in sorted(evidence_by_key.items()):
        stats["strict_official_matched"] = int(stats["strict_official_matched"]) + 1
        current = dict(state.cache.get(key) or _empty_cache_row())
        current.update({
            "Organisation_Key": key,
            "Query_Name": organisation,
            "Matched_Name": current.get("Matched_Name") or organisation,
            "Activity_Label": evidence.evidence_text,
            "Evidence_Source": evidence.evidence_source,
            "Evidence_URL": evidence.evidence_url,
            "Match_Status": org_enrichment.MATCHED,
            "Fetched_At": now,
            "Validated_Sector": evidence.sector,
            "Validated_Via": "official_subject_activity",
            "Cache_Version": org_enrichment.ORG_ENRICHMENT_CACHE_VERSION,
        })
        state.cache[key] = current

    rows = [
        {column: row.get(column, "") for column in ORG_ENRICHMENT_CACHE_COLUMNS}
        for _key, row in sorted(state.cache.items())
    ]
    store.save_org_enrichment_cache(rows)

    stats["total_duration_s"] = round(time.monotonic() - started_total, 3)
    print("SECTOR ENRICHMENT")
    for key, value in stats.items():
        print(f"{key}={value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
