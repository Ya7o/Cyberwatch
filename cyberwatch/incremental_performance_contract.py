"""Compatibilité des fast-paths Performance avec les contrats historiques.

Le cache FrenchBreaches accélère uniquement les lectures dont la fraîcheur est
prouvée. En cas d'échec réseau ou de budget épuisé, il ne réinjecte jamais un
contenu périmé : le comportement historique (content vide) est conservé.
"""
from __future__ import annotations

import datetime as dt
import os

_INSTALLED = False


def install() -> None:
    global _INSTALLED
    if _INSTALLED:
        return

    from . import incremental_performance as perf
    from .collectors import feed

    def hydrate(client, entries, budget):
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
