"""Compatibilité des fast-paths Performance avec les contrats historiques.

Le cache persistant FrenchBreaches est volontairement opt-in : sans variable
d'environnement explicite, le collecteur conserve exactement sa sémantique
historique. Lorsqu'il est activé, seules les entrées dont la fraîcheur est
prouvée sont réutilisées ; un échec réseau ne réinjecte jamais du contenu périmé.
"""
from __future__ import annotations

import datetime as dt
import os

_INSTALLED = False


def _cache_enabled() -> bool:
    value = os.getenv("CYBERWATCH_FRENCHBREACHES_DETAIL_CACHE", "0").strip().lower()
    return value in {"1", "true", "yes", "on"}


def install() -> None:
    global _INSTALLED
    if _INSTALLED:
        return

    from . import incremental_performance as perf
    from .collectors import feed

    def hydrate_without_cache(client, entries, budget):
        attempted = 0
        hydrated = 0
        for entry in entries:
            if budget.exhausted or not entry.url:
                break
            attempted += 1
            response = client.fetch(entry.url, budget)
            if not response.ok:
                continue
            text = feed.stable_frenchbreaches_detail_text(response.text)
            if not text:
                continue
            entry.content = text[:40000]
            hydrated += 1
        return attempted, hydrated

    def hydrate(client, entries, budget):
        if not _cache_enabled():
            return hydrate_without_cache(client, entries, budget)

        try:
            ttl_days = max(0.0, float(os.getenv("FRENCHBREACHES_DETAIL_CACHE_TTL_DAYS", "7")))
        except ValueError:
            ttl_days = 7.0

        path = perf._french_cache_path()
        payload = perf._load_json(path, {})
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
            fingerprint = perf._entry_fingerprint(entry)
            cached = cache.get(entry.url)
            cached_content = str(cached.get("content") or "") if isinstance(cached, dict) else ""
            valid = (
                isinstance(cached, dict)
                and cached.get("fingerprint") == fingerprint
                and cached_content.strip()
                and perf._cache_age_days(str(cached.get("fetched_at") or "")) <= ttl_days
            )
            if valid:
                entry.content = cached_content[:40000]
                hydrated += 1
                perf._FRENCH_DETAIL_CACHE_HITS += 1
                continue

            if budget.exhausted:
                break

            perf._FRENCH_DETAIL_NETWORK_FETCHES += 1
            response = client.fetch(entry.url, budget)
            if not response.ok:
                continue

            text = feed.stable_frenchbreaches_detail_text(response.text)
            if not text:
                continue

            entry.content = text[:40000]
            cache[entry.url] = {
                "fingerprint": fingerprint,
                "fetched_at": now,
                "content": entry.content,
            }
            hydrated += 1
            changed = True

        if changed:
            perf._write_json(path, {"_format": perf.FRENCH_DETAIL_CACHE_FORMAT, "entries": cache})
        return attempted, hydrated

    feed._hydrate_frenchbreaches_details = hydrate
    _INSTALLED = True
