#!/usr/bin/env python3
"""Résout les homonymes d'organisations via domaine officiel -> SIREN -> registre.

Le worker cible uniquement les organisations encore en Secteur Inconnu et dont
le cache organisation n'a pas déjà un match exploitable. Les résolutions sont
indépendantes et peuvent donc être parallélisées avec un pool borné. Le worker
ne publie aucun secteur directement ; il enrichit le cache canonique, puis
`backfill-unknowns` applique la politique Sector habituelle.

Convention d'exploitation : LEGAL_IDENTITY_MAX_ORGS=0 signifie « toute la file ».
"""
from __future__ import annotations

import os
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

# Quand ce fichier est exécuté directement (`python scripts/...`), Python place
# `scripts/` et non la racine du dépôt en tête de sys.path. Le package local
# `cyberwatch` doit donc être rendu explicitement importable, comme pour les
# autres workers exécutés directement par GitHub Actions.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cyberwatch import config, legal_identity, org_enrichment, store
from cyberwatch.normalize import searchable


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _max_orgs() -> int:
    return max(0, _env_int("LEGAL_IDENTITY_MAX_ORGS", 40))


def _workers() -> int:
    return max(1, min(8, _env_int("LEGAL_IDENTITY_WORKERS", 6)))


def _select_candidates(candidates: list[tuple[str, str]], limit: int) -> list[tuple[str, str]]:
    """0 = toute la file ; une valeur positive borne le lot."""
    return candidates if limit == 0 else candidates[:limit]


def _resolve_one(key: str, name: str, fetched_at: str):
    try:
        return legal_identity.resolve(key, name, fetched_at)
    except Exception:
        return None


def _name_tokens(value: str) -> set[str]:
    ignored = {
        "sa", "sas", "sarl", "eurl", "sasu", "groupe", "group", "france",
        "societe", "company", "holding", "association", "et", "de", "du", "des",
        "la", "le", "les",
    }
    return {
        token
        for token in searchable(value or "").split()
        if len(token) >= 3 and token not in ignored
    }


def _filter_suspicious_duplicate_sirens(results: dict[str, dict]) -> tuple[dict[str, dict], int]:
    """Écarte les collisions SIREN faibles entre organisations sans lien nominal.

    Un SIREN peut légitimement porter plusieurs marques. On ne rejette donc jamais
    une résolution forte fondée sur SIRET/adresse. Pour les résolutions faibles,
    une collision n'est conservée que si le nom de requête partage au moins un
    token significatif avec la raison sociale du registre.
    """
    by_siren: dict[str, list[tuple[str, dict]]] = defaultdict(list)
    for key, row in results.items():
        siren = str(row.get("Company_ID") or "").strip()
        if siren:
            by_siren[siren].append((key, row))

    rejected: set[str] = set()
    for siren, rows in by_siren.items():
        if len(rows) < 2:
            continue
        for key, row in rows:
            via = str(row.get("Validated_Via") or "")
            if via in {"legal_identity_siret", "legal_identity_address"}:
                continue
            query_tokens = _name_tokens(str(row.get("Query_Name") or ""))
            matched_tokens = _name_tokens(str(row.get("Matched_Name") or ""))
            if not query_tokens.intersection(matched_tokens):
                rejected.add(key)
                print(
                    f"LEGAL_IDENTITY REJECT duplicate_siren={siren} "
                    f"query={row.get('Query_Name', '')} matched={row.get('Matched_Name', '')}"
                )

    return ({key: row for key, row in results.items() if key not in rejected}, len(rejected))


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
    workers = _workers()
    selected = _select_candidates(candidates, limit)
    fetched_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    results: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_resolve_one, key, name, fetched_at): (key, name)
            for key, name in selected
        }
        for future in as_completed(futures):
            key, name = futures[future]
            row = future.result()
            if row is None:
                continue
            results[key] = row
            print(
                f"LEGAL_IDENTITY MATCH {name} -> SIREN={row['Company_ID']} "
                f"NAF={row['Activity_Code']} activity={row['Activity_Label']}"
            )

    results, rejected_duplicates = _filter_suspicious_duplicate_sirens(results)
    cache.update(results)
    store.save_org_enrichment_cache(
        sorted(cache.values(), key=lambda row: row.get("Organisation_Key", ""))
    )
    print(
        f"LEGAL_IDENTITY candidates={len(candidates)} attempted={len(selected)} "
        f"matched={len(results)} rejected_duplicate_sirens={rejected_duplicates} "
        f"limit={limit} workers={workers}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
