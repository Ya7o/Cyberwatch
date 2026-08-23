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
from cyberwatch.dedup import build_incidents, group_components
from cyberwatch.headline import is_publishable_headline
from cyberwatch.http import HttpClient
from cyberwatch.model import Item

TARGET_SOURCES = {"CYBERATTAQUE_ORG", "FRENCHBREACHES"}
DEFAULT_MAX_ITEMS = 100
RETRYABLE_SEMANTIC_FIELDS = {"summary", "initial_access", "attack_flow", "impact"}
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
    include_existing: bool = False,
) -> tuple[list[Item], dict]:
    """Sélectionne les items SourceFacts, les plus récents d'abord."""
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
        if not (requested or include_existing) and fact is not None and str(fact.get("Summary") or "").strip():
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
        "include_existing": include_existing,
    }
    if requested:
        present = {item.Item_ID for item in candidates}
        metrics["requested_item_ids"] = sorted(requested)
        metrics["requested_not_eligible"] = sorted(requested - present)
    return selected, metrics


def select_latest_incident_candidates(
    items: list[Item], *, max_items: int = DEFAULT_MAX_ITEMS
) -> tuple[list[Item], dict]:
    """Choisit au plus une source éditoriale par incident récent distinct.

    La déduplication reste l'autorité : le LLM n'est jamais appelé deux fois
    pour les sources d'un même incident tant qu'un autre incident est éligible.
    """
    choices: list[tuple[str, str, Item, str]] = []
    for component in group_components(items):
        eligible = [item for item in component if item.Source_ID in TARGET_SOURCES]
        if not eligible:
            continue
        # Une page WordPress complète est généralement la source la plus
        # directement hydratable ; à égalité, on privilégie le titre riche.
        eligible.sort(key=lambda item: (
            0 if item.Source_ID == "CYBERATTAQUE_ORG" else 1,
            -len(item.Title or ""),
            item.Item_ID,
        ))
        chosen = eligible[0]
        incident = build_incidents(component)[0]
        date = max((item.Published_Date or "" for item in component), default="")
        choices.append((date, incident.Incident_ID, chosen, chosen.Source_ID))
    choices.sort(key=lambda row: (row[0], row[1]), reverse=True)
    selected_rows = choices[:max(0, max_items)]
    selected = [row[2] for row in selected_rows]
    return selected, {
        "selection_scope": "latest_distinct_incidents",
        "eligible_incidents": len(choices),
        "selected": len(selected),
        "selected_incident_ids": [row[1] for row in selected_rows],
        "selected_by_source": dict(sorted(Counter(row[3] for row in selected_rows).items())),
        "one_source_per_incident": True,
    }


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


def reopen_abstained_semantic_fields(item: Item, entry: RawEntry) -> dict[str, dict]:
    """Rouvre une seule fois les abstentions sémantiques du backfill historique.

    Le comportement normal de ``source_facts_ai.enrich`` reste inchangé. On ne
    touche qu'à l'entrée de cache correspondant exactement à l'Item_ID, au hash
    du contenu hydraté et au modèle courant. Le champ est repositionné comme un
    premier miss : une réponse vide le remet immédiatement en ``abstained`` ;
    une réponse valide le fait passer en ``accepted``.
    """
    if item.Source_ID not in TARGET_SOURCES:
        return {}

    wanted = source_facts_ai.fields_needed_for_ai(item, entry) & RETRYABLE_SEMANTIC_FIELDS
    if not wanted:
        return {}

    runtime = source_facts_ai._runtime()
    expected_hash = source_facts_ai.content_hash(entry)
    reopened: dict[str, dict] = {}
    for cache_entry in runtime.cache.values():
        if not isinstance(cache_entry, dict):
            continue
        if str(cache_entry.get("item_id") or "") != item.Item_ID:
            continue
        if str(cache_entry.get("source_id") or "") != item.Source_ID:
            continue
        if str(cache_entry.get("content_hash") or "") != expected_hash:
            continue
        if str(cache_entry.get("model") or "") != runtime.model:
            continue
        fields = cache_entry.get("fields")
        if not isinstance(fields, dict):
            continue

        for field in wanted:
            cached = fields.get(field)
            if not isinstance(cached, dict):
                continue
            if cached.get("version") != source_facts_ai.FIELD_VERSIONS[field]:
                continue
            status = str(cached.get("status") or "").strip().lower()
            try:
                misses = max(0, int(cached.get("misses") or 0))
            except (TypeError, ValueError):
                misses = 0
            terminal = status == "abstained" or (
                status == "miss" and misses >= source_facts_ai.MAX_FIELD_MISSES
            )
            if not terminal:
                continue
            reopened[field] = dict(cached)
            fields[field] = {
                "version": source_facts_ai.FIELD_VERSIONS[field],
                "status": "miss",
                "misses": max(1, source_facts_ai.MAX_FIELD_MISSES - 1),
                "value": None,
            }
        break
    return reopened


def restore_reopened_semantic_fields(
    item: Item, entry: RawEntry, previous: dict[str, dict]
) -> None:
    """Restaure l'abstention si la tentative forcée n'a pas réellement abouti."""
    if not previous:
        return


def invalidate_summary_cache(item: Item, entry: RawEntry) -> bool:
    """Force une seule nouvelle headline, sans toucher aux autres faits."""
    runtime = source_facts_ai._runtime()
    expected_hash = source_facts_ai.content_hash(entry)
    for cache_entry in runtime.cache.values():
        if not isinstance(cache_entry, dict):
            continue
        if (cache_entry.get("item_id"), cache_entry.get("source_id"), cache_entry.get("content_hash"), cache_entry.get("model")) != (item.Item_ID, item.Source_ID, expected_hash, runtime.model):
            continue
        fields = cache_entry.get("fields")
        if isinstance(fields, dict):
            fields.pop("summary", None)
            return True
    return False
    runtime = source_facts_ai._runtime()
    expected_hash = source_facts_ai.content_hash(entry)
    for cache_entry in runtime.cache.values():
        if not isinstance(cache_entry, dict):
            continue
        if str(cache_entry.get("item_id") or "") != item.Item_ID:
            continue
        if str(cache_entry.get("source_id") or "") != item.Source_ID:
            continue
        if str(cache_entry.get("content_hash") or "") != expected_hash:
            continue
        if str(cache_entry.get("model") or "") != runtime.model:
            continue
        fields = cache_entry.get("fields")
        if isinstance(fields, dict):
            for field, cached in previous.items():
                fields[field] = dict(cached)
        return


def run_backfill(
    *,
    max_items: int = DEFAULT_MAX_ITEMS,
    item_ids: set[str] | None = None,
    dry_run: bool = False,
    retry_abstained: bool = False,
    retry_legacy_nulls: bool = False,
    include_existing: bool = False,
    latest_incidents: bool = False,
    refresh_summary: bool = False,
    client: HttpClient | None = None,
) -> dict:
    items = store.load_items()
    existing = store.load_source_facts()
    if latest_incidents:
        if item_ids:
            raise ValueError("--latest-incidents ne peut pas être combiné avec --item-ids")
        selected, metrics = select_latest_incident_candidates(items, max_items=max_items)
    else:
        selected, metrics = select_candidates(
            items, existing, item_ids=item_ids, max_items=max_items,
            include_existing=include_existing,
        )
    metrics.update({
        "dry_run": dry_run,
        "retry_abstained": retry_abstained,
        "retry_legacy_nulls": retry_legacy_nulls,
        "hydrated": 0,
        "hydration_failed": 0,
        "source_facts_extracted": 0,
        "source_facts_recovered": 0,
        "headlines_accepted": 0,
        "headlines_rejected_quality": 0,
        "headlines_abstained": 0,
        "technical_failures": 0,
        "incidents_covered": len(selected),
        "incidents_published_without_headline": len(selected),
        "abstained_retry_items": 0,
        "abstained_retry_fields": 0,
        "abstained_retry_restored": 0,
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
    accepted_headline_ids: list[str] = []
    retried_item_ids: list[str] = []

    for item in selected:
        spec = specs.get(item.Source_ID)
        if spec is None:
            metrics["hydration_failed"] += 1
            metrics["technical_failures"] += 1
            continue
        entry = hydrate_entry(http, item, spec)
        if entry is None:
            metrics["hydration_failed"] += 1
            metrics["technical_failures"] += 1
            continue
        metrics["hydrated"] += 1

        runtime = source_facts_ai._runtime()
        if refresh_summary:
            invalidate_summary_cache(item, entry)
        calls_before = runtime.calls
        failures_before = runtime.calls_failed
        reopened = (
            reopen_abstained_semantic_fields(item, entry)
            if retry_abstained else {}
        )
        if reopened:
            metrics["abstained_retry_items"] += 1
            metrics["abstained_retry_fields"] += len(reopened)
            retried_item_ids.append(item.Item_ID)

        previous_retry_legacy_nulls = runtime.retry_legacy_nulls
        runtime.retry_legacy_nulls = bool(retry_legacy_nulls)
        try:
            fact = source_facts.extract_source_fact(item, entry, spec)
        finally:
            runtime.retry_legacy_nulls = previous_retry_legacy_nulls

        # Une panne technique ou un budget bloqué ne doit pas dégrader une
        # abstention déjà confirmée. Seule une vraie réponse sémantique peut
        # remplacer cet état historique.
        if reopened and (
            runtime.calls == calls_before or runtime.calls_failed > failures_before
        ):
            restore_reopened_semantic_fields(item, entry, reopened)
            metrics["abstained_retry_restored"] += len(reopened)

        if fact is None:
            metrics["technical_failures"] += 1
            continue
        incoming.append(fact)
        metrics["source_facts_extracted"] += 1
        if item.Item_ID not in existing_by_id:
            metrics["source_facts_recovered"] += 1
        if is_publishable_headline(fact.get("Summary")):
            metrics["headlines_accepted"] += 1
            accepted_headline_ids.append(item.Item_ID)
        else:
            status = source_facts._loads_json(str(fact.get("Source_Metadata_JSON") or "")).get("_source_facts_summary_status", "rejected_quality")
            metric = {
                "abstained": "headlines_abstained",
                "technical_failure": "technical_failures",
            }.get(str(status), "headlines_rejected_quality")
            metrics[metric] += 1

    if incoming:
        store.save_source_facts(source_facts.merge_source_facts(existing, incoming))

    # L'enrichissement sémantique possède son propre cache ; le flush explicite
    # garantit que le backfill persiste les miss/abstentions même sans nouveau fait.
    ai_stats = source_facts_ai.runtime_stats()
    source_facts_ai._flush_runtime()
    site.build()

    metrics["incidents_published_without_headline"] = len(selected) - metrics["headlines_accepted"]
    metrics["accepted_headline_item_ids"] = accepted_headline_ids
    metrics["abstained_retry_item_ids"] = retried_item_ids
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
        "--include-existing", action="store_true",
        help="Requalifie aussi les synthèses déjà présentes, pour un rattrapage qualité.",
    )
    parser.add_argument(
        "--latest-incidents", action="store_true",
        help="Sélectionne les incidents distincts les plus récents (une source par incident).",
    )
    parser.add_argument("--refresh-summary", action="store_true", help="Invalide uniquement la headline mise en cache.")
    parser.add_argument(
        "--max-items", type=int, default=DEFAULT_MAX_ITEMS,
        help=f"Nombre maximal d'items à traiter (défaut: {DEFAULT_MAX_ITEMS}).",
    )
    parser.add_argument(
        "--item-ids", default="",
        help="Liste optionnelle d'Item_ID séparés par des virgules.",
    )
    parser.add_argument(
        "--retry-abstained", action="store_true",
        help=(
            "Rouvre une seule fois les abstentions sémantiques terminales des "
            "candidats historiques sélectionnés."
        ),
    )
    parser.add_argument(
        "--retry-legacy-nulls", action="store_true",
        help=(
            "Autorise ce backfill à convertir les anciens value:null sans statut "
            "en miss retentable. CREATE les considère sinon déjà traités."
        ),
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
        retry_abstained=args.retry_abstained,
        retry_legacy_nulls=args.retry_legacy_nulls,
        include_existing=args.include_existing,
        latest_incidents=args.latest_incidents,
        refresh_summary=args.refresh_summary,
    )
    print(json.dumps(metrics, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
