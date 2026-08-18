#!/usr/bin/env python3
"""Backfill ciblé des synthèses SourceFacts manquantes.

Le script ne touche ni ITEMS, ni INCIDENTS, ni le registre d'identité. Il
réhydrate uniquement les articles déjà présents dans ITEMS pour
CYBERATTAQUE_ORG/FRENCHBREACHES, recalcule leurs SourceFacts, puis fusionne
les résultats avec la règle non destructive de source_facts.merge_source_facts.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from urllib.parse import unquote, urlencode, urlparse

from cyberwatch import site, source_facts, source_facts_ai, sources, store
from cyberwatch.collectors.base import RawEntry, SourceSpec
from cyberwatch.collectors.feed import stable_frenchbreaches_detail_text
from cyberwatch.collectors.wordpress import entry_from_post, origin_of
from cyberwatch.http import HttpClient
from cyberwatch.model import Item

TARGET_SOURCES = {"CYBERATTAQUE_ORG", "FRENCHBREACHES"}
DEFAULT_MAX_ITEMS = 100
_WP_FIELDS = "id,date,link,title,excerpt,content,categories"


def source_specs() -> dict[str, SourceSpec]:
    return {
        spec.source_id: spec
        for spec in sources.ALL_SOURCES
        if spec.source_id in TARGET_SOURCES
    }


def select_candidates(
    items: list[Item],
    source_facts_rows: list[dict],
    *,
    item_ids: set[str] | None = None,
    max_items: int = DEFAULT_MAX_ITEMS,
) -> tuple[list[Item], dict]:
    """Sélectionne uniquement les items cibles dont la synthèse source manque."""
    facts_by_id = {
        str(row.get("Item_ID") or ""): row
        for row in source_facts_rows
        if row.get("Item_ID")
    }
    requested = {value.strip() for value in (item_ids or set()) if value.strip()}
    candidates: list[Item] = []
    missing_fact = 0

    for item in items:
        if item.Source_ID not in TARGET_SOURCES:
            continue
        if requested and item.Item_ID not in requested:
            continue
        fact = facts_by_id.get(item.Item_ID)
        if fact is not None and str(fact.get("Summary") or "").strip():
            continue
        if fact is None:
            missing_fact += 1
        candidates.append(item)

    # Les plus récents d'abord : le backfill reste borné et utile immédiatement.
    candidates.sort(
        key=lambda item: (item.Published_Date or "", item.Item_ID),
        reverse=True,
    )
    selected = candidates[:max(0, max_items)]
    metrics = {
        "candidates_total": len(candidates),
        "candidates_by_source": dict(sorted(Counter(
            item.Source_ID for item in candidates
        ).items())),
        "candidates_without_source_fact": missing_fact,
        "selected": len(selected),
        "selected_by_source": dict(sorted(Counter(
            item.Source_ID for item in selected
        ).items())),
    }
    if requested:
        present = {item.Item_ID for item in candidates}
        metrics["requested_item_ids"] = sorted(requested)
        metrics["requested_not_eligible"] = sorted(requested - present)
    return selected, metrics


def _cyberattaque_post_urls(item: Item, spec: SourceSpec) -> list[str]:
    endpoint = f"{origin_of(spec.start_url)}/wp-json/wp/v2"
    urls: list[str] = []
    native_id = str(item.Source_Item_ID or "").strip()
    if native_id.isdigit():
        urls.append(f"{endpoint}/posts/{native_id}?{urlencode({'_fields': _WP_FIELDS})}")

    slug = unquote(urlparse(item.URL or "").path.rstrip("/").split("/")[-1]).strip()
    if slug:
        urls.append(
            f"{endpoint}/posts?{urlencode({'slug': slug, '_fields': _WP_FIELDS})}"
        )
    return list(dict.fromkeys(urls))


def hydrate_cyberattaque_entry(
    client: HttpClient, item: Item, spec: SourceSpec
) -> RawEntry | None:
    budget = client.source_budget()
    for url in _cyberattaque_post_urls(item, spec):
        response = client.fetch(url, budget)
        if not response.ok:
            continue
        payload = response.json()
        post = payload if isinstance(payload, dict) else (
            payload[0] if isinstance(payload, list) and payload else None
        )
        if not isinstance(post, dict):
            continue
        entry = entry_from_post(post, spec)
        if entry is None:
            continue
        entry.organisation = item.Organisation_Raw
        # ITEMS reste l'autorité d'identité ; l'hydratation n'en modifie aucune clé.
        entry.url = item.URL or entry.url
        entry.source_item_id = item.Source_Item_ID or entry.source_item_id
        return entry
    return None


def hydrate_frenchbreaches_entry(
    client: HttpClient, item: Item, _spec: SourceSpec
) -> RawEntry | None:
    if not item.URL:
        return None
    response = client.fetch(item.URL, client.source_budget())
    if not response.ok:
        return None
    content = stable_frenchbreaches_detail_text(response.text)
    if not content:
        return None
    return RawEntry(
        title=item.Title,
        url=item.URL,
        source_item_id=item.Source_Item_ID,
        published=item.Published_Date,
        content=content[:40000],
        organisation=item.Organisation_Raw,
    )


def hydrate_entry(
    client: HttpClient, item: Item, spec: SourceSpec
) -> RawEntry | None:
    if item.Source_ID == "CYBERATTAQUE_ORG":
        return hydrate_cyberattaque_entry(client, item, spec)
    if item.Source_ID == "FRENCHBREACHES":
        return hydrate_frenchbreaches_entry(client, item, spec)
    return None


def run_backfill(
    *,
    max_items: int = DEFAULT_MAX_ITEMS,
    item_ids: set[str] | None = None,
    dry_run: bool = False,
    client: HttpClient | None = None,
) -> dict:
    items = store.load_items()
    existing = store.load_source_facts()
    selected, metrics = select_candidates(
        items, existing, item_ids=item_ids, max_items=max_items
    )
    metrics.update({
        "dry_run": dry_run,
        "hydrated": 0,
        "hydration_failed": 0,
        "source_facts_extracted": 0,
        "source_facts_recovered": 0,
        "summary_recovered": 0,
        "still_without_summary": len(selected),
    })
    if dry_run or not selected:
        return metrics

    specs = source_specs()
    http = client or HttpClient()
    existing_by_id = {
        str(row.get("Item_ID") or ""): row
        for row in existing
        if row.get("Item_ID")
    }
    incoming: list[dict] = []
    recovered_summary_ids: list[str] = []

    for item in selected:
        spec = specs.get(item.Source_ID)
        if spec is None:
            metrics["hydration_failed"] += 1
            continue
        entry = hydrate_entry(http, item, spec)
        if entry is None:
            metrics["hydration_failed"] += 1
            continue
        metrics["hydrated"] += 1

        fact = source_facts.extract_source_fact(item, entry, spec)
        if fact is None:
            continue
        incoming.append(fact)
        metrics["source_facts_extracted"] += 1
        if item.Item_ID not in existing_by_id:
            metrics["source_facts_recovered"] += 1
        if str(fact.get("Summary") or "").strip():
            metrics["summary_recovered"] += 1
            recovered_summary_ids.append(item.Item_ID)

    if incoming:
        store.save_source_facts(source_facts.merge_source_facts(existing, incoming))

    # L'enrichissement sémantique possède son propre cache ; le flush explicite
    # garantit que le backfill persiste les miss/abstentions même sans nouveau fait.
    ai_stats = source_facts_ai.runtime_stats()
    source_facts_ai._flush_runtime()
    site.build()

    metrics["still_without_summary"] = len(selected) - metrics["summary_recovered"]
    metrics["recovered_summary_item_ids"] = recovered_summary_ids
    metrics["http_requests"] = http.run_budget.requests_made
    metrics["ai_stats"] = ai_stats
    return metrics


def _parse_item_ids(raw: str) -> set[str]:
    return {value.strip() for value in (raw or "").split(",") if value.strip()}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Backfill ciblé des synthèses SourceFacts manquantes."
    )
    parser.add_argument(
        "--max-items", type=int, default=DEFAULT_MAX_ITEMS,
        help=f"Nombre maximal d'items à traiter (défaut: {DEFAULT_MAX_ITEMS}).",
    )
    parser.add_argument(
        "--item-ids", default="",
        help="Liste optionnelle d'Item_ID séparés par des virgules.",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Compte les candidats sans réseau ni écriture.",
    )
    args = parser.parse_args()
    if args.max_items < 0:
        parser.error("--max-items doit être positif ou nul")

    metrics = run_backfill(
        max_items=args.max_items,
        item_ids=_parse_item_ids(args.item_ids),
        dry_run=args.dry_run,
    )
    print(json.dumps(metrics, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
