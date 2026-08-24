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
import re
from pathlib import Path
from urllib.parse import unquote, urlencode, urlparse

from cyberwatch import site, source_facts, source_facts_ai, sources, store
from cyberwatch.collectors.base import RawEntry, SourceSpec
from cyberwatch.collectors.feed import stable_frenchbreaches_detail_text
from cyberwatch.collectors.wordpress import entry_from_post, origin_of
from cyberwatch.dedup import build_incidents, group_components
from cyberwatch.headline import is_organisation_name_only, is_publishable_headline
from cyberwatch.http import HttpClient
from cyberwatch.model import Item

TARGET_SOURCES = {"CYBERATTAQUE_ORG", "FRENCHBREACHES"}
DEFAULT_MAX_ITEMS = 100
RETRYABLE_SEMANTIC_FIELDS = {"summary", "initial_access", "attack_flow", "impact"}
_WP_FIELDS = "id,date,link,title,excerpt,content,categories"


def cached_summary_with_current_evidence(item: Item, entry: RawEntry) -> str:
    """Return a prior accepted headline only when its evidence still matches.

    Cache keys deliberately include the full fetched content.  A harmless
    article layout change therefore creates a new key, although a previously
    validated factual headline for the same source item remains usable.  This
    bridge never trusts the cache blindly: the saved evidence must still occur
    in the currently hydrated editorial text.
    """
    context = " ".join((entry.title or "", entry.summary or "", entry.content or ""))
    compact_context = re.sub(r"\W+", "", context, flags=re.UNICODE).casefold()
    if not compact_context:
        return ""
    entries = getattr(source_facts_ai._runtime(), "cache", {}).values()
    for cached in entries:
        if not isinstance(cached, dict):
            continue
        if cached.get("item_id") != item.Item_ID or cached.get("source_id") != item.Source_ID:
            continue
        summary = (cached.get("fields") or {}).get("summary") or {}
        value = summary.get("value") if isinstance(summary, dict) else None
        if not (isinstance(value, dict) and summary.get("status") == "accepted"):
            continue
        headline = str(value.get("value") or "").strip()
        evidence = re.sub(r"\W+", "", str(value.get("evidence") or ""), flags=re.UNICODE).casefold()
        # Les extraits peuvent être tronqués par une ellipse : un préfixe
        # substantiel reste une preuve déterministe de rattachement.
        if len(evidence) >= 24 and evidence[:80] in compact_context and is_publishable_headline(headline):
            return headline
    return ""


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
    runtime = source_facts_ai._runtime()
    expected_hash = source_facts_ai.content_hash(entry)
    for cache_entry in runtime.cache.values():
        if not isinstance(cache_entry, dict):
            continue
        if (str(cache_entry.get("item_id") or ""), str(cache_entry.get("source_id") or ""), str(cache_entry.get("content_hash") or ""), str(cache_entry.get("model") or "")) != (item.Item_ID, item.Source_ID, expected_hash, runtime.model):
            continue
        fields = cache_entry.get("fields")
        if isinstance(fields, dict):
            for field, cached in previous.items():
                fields[field] = dict(cached)
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
    refresh_complete: bool = False,
    replay_summary_cache: bool = False,
    report_path: Path | None = None,
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
        "refresh_complete": refresh_complete,
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
        "semantic_promotion_gaps": 0,
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
    item_reports: list[dict] = []

    for item in selected:
        spec = specs.get(item.Source_ID)
        if spec is None:
            metrics["hydration_failed"] += 1
            metrics["technical_failures"] += 1
            item_reports.append({
                "item_id": item.Item_ID,
                "source_id": item.Source_ID,
                "organisation": item.Organisation_Raw,
                "status": "technical_failure",
                "reason": "source_spec_missing",
            })
            continue
        entry = hydrate_entry(http, item, spec)
        if entry is None:
            metrics["hydration_failed"] += 1
            metrics["technical_failures"] += 1
            item_reports.append({
                "item_id": item.Item_ID,
                "source_id": item.Source_ID,
                "organisation": item.Organisation_Raw,
                "status": "technical_failure",
                "reason": "hydration_failed",
            })
            continue
        metrics["hydrated"] += 1

        runtime = source_facts_ai._runtime()
        semantic = None
        editorial_fields = None
        if refresh_complete:
            invalidate_summary_cache(item, entry)
            source_facts_ai.force_full_refresh(item, entry)
            semantic = source_facts_ai.extract_semantic(item, entry)
            editorial_fields = semantic.fields
        elif refresh_summary:
            invalidate_summary_cache(item, entry)
            source_facts_ai.force_summary_refresh(item, entry)
            # Le backfill doit matérialiser l'appel avant l'extracteur : cela
            # évite qu'un adaptateur source court-circuite silencieusement la
            # couche éditoriale.
            semantic = source_facts_ai.extract_semantic(item, entry)
            editorial_fields = semantic.fields
        elif replay_summary_cache:
            # Réinjecte uniquement une headline déjà accepted dans le cache.
            # Aucun cache n'est invalidé, donc cette réparation ne peut pas
            # consommer le budget LLM.
            semantic = source_facts_ai.extract_semantic(item, entry)
            editorial_fields = semantic.fields
            if not is_publishable_headline(str((editorial_fields or {}).get("summary") or "")):
                editorial_fields = {
                    **(editorial_fields or {}),
                    "summary": cached_summary_with_current_evidence(item, entry),
                }
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
            fact = source_facts.extract_source_fact(item, entry, spec, semantic=semantic)
        finally:
            runtime.retry_legacy_nulls = previous_retry_legacy_nulls

        # ``entry`` est la source de vérité de la passe éditoriale.  Les
        # adaptateurs historiques peuvent reconstruire une Summary technique
        # (volumes, vecteur, etc.) après l'enrichissement ; ne leur permettons
        # pas d'écraser une headline LLM déjà validée et mise en cache.
        # Cette copie est aussi nécessaire lors d'un rejeu depuis cache :
        # aucune nouvelle requête ne doit être requise pour republier une
        # réponse accepted.
        # ``enrich`` retourne ses champs, il ne modifie pas RawEntry.
        cached_summary = str((editorial_fields or {}).get("summary") or "").strip()
        if fact is not None and is_publishable_headline(cached_summary) and not is_organisation_name_only(
            cached_summary, item.Organisation_Raw
        ):
            fact["Summary"] = cached_summary
        # Même garantie pour un titre éditorial source : le backfill doit
        # publier le contrat validé, même si un extracteur historique a
        # reconstruit entre-temps une ancienne synthèse structurée.
        if fact is not None and (
            not is_publishable_headline(fact.get("Summary"))
            or is_organisation_name_only(fact.get("Summary"), item.Organisation_Raw)
        ):
            source_title = " ".join(str(entry.title or "").split()).strip()
            if is_publishable_headline(source_title) and not is_organisation_name_only(
                source_title, item.Organisation_Raw
            ):
                fact["Summary"] = source_title
                evidence = source_facts._loads_json(str(fact.get("Evidence_JSON") or ""))
                evidence = evidence if isinstance(evidence, dict) else {}
                evidence["Summary"] = source_title
                fact["Evidence_JSON"] = source_facts._dumps_json(evidence)

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
            item_reports.append({
                "item_id": item.Item_ID,
                "source_id": item.Source_ID,
                "organisation": item.Organisation_Raw,
                "status": "technical_failure",
                "reason": "source_facts_extraction_failed",
            })
            continue
        incoming.append(fact)
        promotion_gaps = source_facts.semantic_promotion_gaps(fact, semantic)
        metrics["semantic_promotion_gaps"] += len(promotion_gaps)
        metrics["source_facts_extracted"] += 1
        if item.Item_ID not in existing_by_id:
            metrics["source_facts_recovered"] += 1
        headline_accepted = is_publishable_headline(fact.get("Summary")) and not is_organisation_name_only(
            fact.get("Summary"), item.Organisation_Raw
        )
        if headline_accepted:
            metrics["headlines_accepted"] += 1
            accepted_headline_ids.append(item.Item_ID)
        else:
            metadata = source_facts._loads_json(str(fact.get("Source_Metadata_JSON") or ""))
            metadata = metadata if isinstance(metadata, dict) else {}
            status = metadata.get("_source_facts_summary_status", "rejected_quality")
            metric = {
                "abstained": "headlines_abstained",
                "technical_failure": "technical_failures",
            }.get(str(status), "headlines_rejected_quality")
            metrics[metric] += 1
        metadata = source_facts._loads_json(str(fact.get("Source_Metadata_JSON") or ""))
        metadata = metadata if isinstance(metadata, dict) else {}
        item_reports.append({
            "item_id": item.Item_ID,
            "source_id": item.Source_ID,
            "organisation": item.Organisation_Raw,
            "hydrated": True,
            "status": "accepted" if headline_accepted else str(
                metadata.get("_source_facts_summary_status") or "rejected_quality"
            ),
            "reason": metadata.get("_source_facts_summary_reason") or "",
            "headline": str(fact.get("Summary") or ""),
            "promotion_gaps": promotion_gaps,
        })

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
    metrics["incident_reports"] = item_reports
    if report_path is not None:
        incident_reports = _published_incident_reports(items, item_reports)
        metrics["incidents_reported"] = len(incident_reports)
        store.write_json(report_path, {
            "schema_version": 3,
            "metrics": {key: value for key, value in metrics.items() if key != "incident_reports"},
            "incidents": incident_reports,
        })
    return metrics


def _parse_item_ids(raw: str) -> set[str]:
    return {value.strip() for value in (raw or "").split(",") if value.strip()}


def _published_incident_reports(items: list[Item], item_reports: list[dict]) -> list[dict]:
    """Construit le rapport depuis les incidents effectivement publiés."""
    payload_path = store.SITE_DATA_DIR / "incidents.json"
    try:
        published = json.loads(payload_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    item_url = {item.Item_ID: item.URL for item in items if item.Item_ID and item.URL}
    by_url: dict[str, list[dict]] = {}
    for report in item_reports:
        url = item_url.get(str(report.get("item_id") or ""), "")
        if url:
            by_url.setdefault(url, []).append(report)

    reports: list[dict] = []
    for incident in published if isinstance(published, list) else []:
        urls = {str(value) for value in incident.get("urls", []) if value}
        source_reports = [report for url in urls for report in by_url.get(url, [])]
        sources = [str(value) for value in incident.get("sources", []) if value]
        summary = str(incident.get("summary") or "").strip()
        if summary:
            status, reason = "accepted", ""
        elif not set(sources) & TARGET_SOURCES:
            status, reason = "missing_content", "non_editorial_source"
        elif source_reports:
            statuses = {str(report.get("status") or "") for report in source_reports}
            status = next((value for value in ("technical_failure", "abstained", "rejected_quality") if value in statuses), "missing_content")
            reason = next((str(report.get("reason") or "") for report in source_reports if report.get("reason")), "headline_not_published")
        else:
            status, reason = "missing_content", "not_selected"
        reports.append({
            "incident_id": str(incident.get("id") or ""),
            "organisation": str(incident.get("org") or ""),
            "sources": sources,
            "summary_status": status,
            "summary_reason": reason,
            "summary": summary,
            "source_reports": source_reports,
            "promotion_gaps": sorted({
                gap for report in source_reports for gap in report.get("promotion_gaps", [])
            }),
        })
    return reports


def reports_from_existing_source_facts(
    items: list[Item], source_facts_rows: list[dict]
) -> list[dict]:
    """Materialise the public quality report without invoking the LLM.

    A reset and a normal collection both need a report for *every* published
    incident, not only for the subset selected by a corrective backfill.  The
    SourceFacts row is already the durable record of the outcome of a
    semantic extraction, so reading it is sufficient and cannot create a
    second paid call.
    """
    by_id = {
        str(row.get("Item_ID") or ""): row
        for row in source_facts_rows
        if row.get("Item_ID")
    }
    item_reports: list[dict] = []
    for item in items:
        if item.Source_ID not in TARGET_SOURCES:
            continue
        fact = by_id.get(item.Item_ID)
        if fact is None:
            item_reports.append({
                "item_id": item.Item_ID,
                "source_id": item.Source_ID,
                "organisation": item.Organisation_Raw,
                "hydrated": False,
                "status": "missing_content",
                "reason": "source_fact_missing",
                "headline": "",
                "promotion_gaps": [],
            })
            continue
        metadata = source_facts._loads_json(str(fact.get("Source_Metadata_JSON") or ""))
        metadata = metadata if isinstance(metadata, dict) else {}
        headline = str(fact.get("Summary") or "").strip()
        accepted = is_publishable_headline(headline) and not is_organisation_name_only(
            headline, item.Organisation_Raw
        )
        item_reports.append({
            "item_id": item.Item_ID,
            "source_id": item.Source_ID,
            "organisation": item.Organisation_Raw,
            "hydrated": True,
            "status": "accepted" if accepted else str(
                metadata.get("_source_facts_summary_status") or "rejected_quality"
            ),
            "reason": str(
                metadata.get("_source_facts_summary_reason")
                or metadata.get("_source_facts_summary_rejection")
                or ("headline_not_publishable" if headline else "headline_missing")
            ),
            "headline": headline,
            "promotion_gaps": [],
        })
    return _published_incident_reports(items, item_reports)


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
        "--refresh-complete", action="store_true",
        help="Rouvre tous les faits sémantiques d'un article hydraté (backfill explicite seulement).",
    )
    parser.add_argument("--replay-summary-cache", action="store_true", help="Réinjecte les headlines accepted du cache sans appel LLM.")
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
        refresh_complete=args.refresh_complete,
        replay_summary_cache=args.replay_summary_cache,
        report_path=store.DATA_DIR / "source_facts_backfill_report.json",
    )
    print(json.dumps(metrics, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
