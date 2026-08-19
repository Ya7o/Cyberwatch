#!/usr/bin/env python3
"""Résout les homonymes d'organisations via domaine officiel -> SIREN -> registre.

Le worker est volontairement ciblé : uniquement les organisations encore en
Secteur Inconnu et uniquement lorsque le cache organisation n'a pas déjà un
match exploitable. Il ne publie aucun secteur directement ; il enrichit le cache
canonique, puis `backfill-unknowns` applique la politique Sector habituelle.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone

from cyberwatch import config, legal_identity, org_enrichment, store


def _max_orgs() -> int:
    try:
        return max(0, int(os.getenv("LEGAL_IDENTITY_MAX_ORGS", "40")))
    except ValueError:
        return 40


def main() -> int:
    items = store.load_items()
    cache_rows = store.load_org_enrichment_cache()
    cache = {
        row.get("Organisation_Key", ""): dict(row)
        for row in cache_rows
        if row.get("Organisation_Key", "")
    }

    organisations: dict[str, str] = {}
    for item in items:
        if item.Sector != config.SECTOR_UNKNOWN:
            continue
        key = item.Organisation_Key
        name = item.Organisation_Raw
        if key and name and key not in organisations:
            organisations[key] = name

    candidates: list[tuple[str, str]] = []
    for key, name in organisations.items():
        existing = cache.get(key)
        if existing and existing.get("Match_Status") == org_enrichment.MATCHED:
            continue
        candidates.append((key, name))

    limit = _max_orgs()
    attempted = matched = 0
    fetched_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    for key, name in candidates[:limit]:
        attempted += 1
        row = legal_identity.resolve(key, name, fetched_at)
        if row is None:
            continue
        cache[key] = row
        matched += 1
        print(
            f"LEGAL_IDENTITY MATCH {name} -> SIREN={row['Company_ID']} "
            f"NAF={row['Activity_Code']} activity={row['Activity_Label']}"
        )

    store.save_org_enrichment_cache(
        sorted(cache.values(), key=lambda row: row.get("Organisation_Key", ""))
    )
    print(
        f"LEGAL_IDENTITY candidates={len(candidates)} attempted={attempted} "
        f"matched={matched} limit={limit}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
