"""Enrichissement sémantique conservateur des faits éditoriaux publiés par une source.

La couche reste auxiliaire et ne touche jamais Threat/Sector/Location. Les faits
mécaniques sont extraits déterministement ; le LLM ne sert qu'aux relations
sémantiques. Les résultats sont cachés par champ afin qu'un rebuild réutilise
les extractions valides et ne recalcule que les champs nouveaux ou invalidés.
"""
from __future__ import annotations

import atexit
from collections import Counter
from dataclasses import dataclass
import hashlib
import json
import math
import os
import re
import time
from pathlib import Path

import requests

from . import config, llm_runtime, source_facts_ai_retry
from .collectors.base import RawEntry
from .model import Item
from .normalize import classify_threat, searchable
from .headline import (MAX_HEADLINE_CHARS, is_organisation_name_only,
                       is_publishable_headline, summary_role_is_supported)

from .source_facts_ai_contract import (
    CACHE_FORMAT,
    CONFIDENCE_THRESHOLD,
    DATA_TYPES_UNDISCLOSED_LABEL,
    DEFAULT_MODEL,
    FIELD_VERSIONS,
    INITIAL_ACCESS_VALUES,
    LEGACY_PROMPT_VERSION,
    LEGACY_REUSABLE_FIELDS,
    LEGACY_SCHEMA_VERSION,
    MAX_ATTACK_FLOW_STEPS,
    MAX_EVIDENCE_CHARS,
    MAX_FIELD_MISSES,
    MAX_LABEL_VALUE_CHARS,
    MAX_SUMMARY_CHARS,
    NEW_SEMANTIC_FIELDS,
    OPENAI_URL,
    PREVIOUS_FIELD_VERSIONS,
    PRICING,
    PROMPT_VERSION,
    SCHEMA_VERSION,
    TARGET_SOURCES,
    SemanticExtraction,
    _ACTOR_TRIGGER,
    _ATTACK_ACTION_RE,
    _DATA_RELATION,
    _DATA_TYPES_UNDISCLOSED_RE,
    _DATA_TYPE_PATTERNS,
    _EDITORIAL_FIELDS,
    _GENERIC_EXPLAINER_RE,
    _HYPOTHETICAL_RE,
    _IMPACT_TRIGGER,
    _INITIAL_ACCESS_CAUSAL_RE,
    _INITIAL_ACCESS_EVENT_RE,
    _INITIAL_ACCESS_UNCERTAIN_RE,
    _INITIAL_ACCESS_UNKNOWN_RE,
    _LLM_FIELDS,
    _NEGATED_DATA_RELATION,
    _NEGATED_DATA_VALUE_PREFIX,
    _NEGATED_DATA_VALUE_SENTENCE,
    _RESPONSE_ACTION_RE,
    _SEMANTIC_DATA_TYPES_TRIGGER,
    _SEMANTIC_ENRICHMENT_TRIGGER,
    _STRUCTURED_FIELDS,
    _SYSTEM_PROMPT,
    _THIRD_PARTY_TRIGGER,
)

from .source_facts_ai_runtime import (
    SourceFactsAiError,
    _Runtime,
    _cache_path,
    _env_float,
    _env_int,
    _flush_runtime,
    _percentile,
    _runtime,
    _stats_path,
    reset_runtime_for_tests,
    runtime_stats,
)

from .source_facts_ai_normalize import (
    _NON_EXPOSURE_DATA_CONTEXT_RE,
    _content_hash,
    _evidence_sentence,
    _evidence_window,
    _full_context,
    _grounded,
    _negated_data_type,
    _normalize,
    _normalize_attack_flow,
    _normalize_data_types,
    _normalize_fact,
    _normalize_impact,
    _normalize_initial_access,
    _normalize_record_lists,
    _normalize_summary,
    _truncate_context,
    prepared_context,
    _valid_confidence,
    content_hash,
)
from .source_facts_ai_deterministic import (
    _INITIAL_ACCESS_PATTERNS,
    _deterministic_data_types,
    _deterministic_impact,
    _deterministic_initial_access,
    _deterministic_seed,
)


def field_statuses(item: Item, entry: RawEntry) -> dict[str, str]:
    """État courant des champs du cache pour cette version exacte du contenu.

    Une panne technique n'invente aucun état : si un premier miss existait, il
    reste ``miss``. Seules deux réponses sémantiques vides peuvent donc faire
    apparaître ``abstained`` et autoriser le nettoyage d'un fait devenu obsolète.
    """
    if item.Source_ID not in TARGET_SOURCES:
        return {}
    runtime = _runtime()
    key = _cache_item_key(item, entry, runtime)
    cache_entry = runtime.cache.get(key)
    if not isinstance(cache_entry, dict) or not isinstance(cache_entry.get("fields"), dict):
        return {}
    result: dict[str, str] = {}
    for field, cached in cache_entry["fields"].items():
        if field not in FIELD_VERSIONS or not isinstance(cached, dict):
            continue
        status = str(cached.get("status") or "").strip().lower()
        if status in {"accepted", "miss", "abstained"}:
            result[field] = status
    return result


def _record_cache_read(
    runtime: _Runtime, item: Item, entry: RawEntry, fields: set[str],
    values: dict, satisfied: set[str], context_meta: dict,
) -> None:
    """Journalise une lecture de cache, valeur par valeur.

    L'audit du 10 septembre 2026 comptait 17 valeurs acceptées réutilisées et
    40 abstentions sans qu'aucune trace du run ne dise lesquelles ni sur quel
    article : une collecte sans appel restait donc indocumentée. `effective_model`
    reste vide ici — aucune inférence n'a eu lieu dans ce run.
    """
    read = sorted(fields & satisfied)
    if not read:
        return
    entries = (runtime.cache.get(_cache_item_key(item, entry, runtime)) or {}).get("fields") or {}
    runtime.record_event(
        item_id=item.Item_ID, url=item.URL, status="cache_read",
        content_hash=_content_hash(entry), context=context_meta,
        requested_fields=read, effective_model="",
        cached_model=(runtime.cache.get(_cache_item_key(item, entry, runtime)) or {}).get(
            "effective_model", ""
        ),
        fields={
            field: {
                "status": str((entries.get(field) or {}).get("status") or ""),
                "version": str((entries.get(field) or {}).get("version") or ""),
                "value": values.get(field),
                "rejection_reason": str((entries.get(field) or {}).get("rejection_reason") or ""),
            }
            for field in read
        },
    )


def _cache_item_key(item: Item, entry: RawEntry, runtime: _Runtime) -> str:
    payload = "\x1f".join((item.Item_ID, item.Source_ID, _content_hash(entry), runtime.model))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _legacy_input_hash(item: Item, entry: RawEntry, runtime: _Runtime, fields: set[str]) -> str:
    payload = "\x1f".join((
        item.Item_ID,
        item.Source_ID,
        _content_hash(entry),
        ",".join(sorted(fields)),
        runtime.model,
        LEGACY_PROMPT_VERSION,
        LEGACY_SCHEMA_VERSION,
    ))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


from .source_facts_ai_api import (
    _attack_flow_schema,
    _extract_output_text,
    _fact_schema,
    _initial_access_schema,
    _post_openai,
    _record_schema,
    _schema,
    _usage,
    _usage_cost,
    _user_prompt,
)

def _legacy_fields_needed(item: Item, entry: RawEntry, seed: dict | None = None) -> set[str]:
    from . import source_facts as sf

    text = _full_context(entry)
    organisation = entry.organisation or item.Organisation_Raw
    requested: set[str] = set()
    seed = seed or {}
    actor_patterns = sf._ACTOR_PATTERNS if item.Source_ID == "FRENCHBREACHES" else sf._CO_THREAT_ACTOR_RE
    actor, _ = sf._first_valid_match(actor_patterns, text, sf._valid_actor, organisation)
    if not actor and _ACTOR_TRIGGER.search(text):
        requested.add("threat_actor")
    third_patterns = sf._THIRD_PARTY_PATTERNS if item.Source_ID == "FRENCHBREACHES" else sf._CO_THIRD_PARTY_RE
    third_party, _ = sf._first_valid_match(third_patterns, text, sf._valid_third_party, organisation)
    if not third_party and _THIRD_PARTY_TRIGGER.search(text):
        requested.add("third_party")
    if not seed.get("data_types") and _SEMANTIC_DATA_TYPES_TRIGGER.search(text):
        requested.add("data_types")
    if requested:
        requested.add("summary")
    return requested


def _has_semantic_context(entry: RawEntry) -> bool:
    body = " ".join(part.strip() for part in (entry.summary, entry.content) if (part or "").strip())
    return len(body) >= 80 or bool(_SEMANTIC_ENRICHMENT_TRIGGER.search(body))


def _fields_needed(item: Item, entry: RawEntry, seed: dict | None = None) -> set[str]:
    requested = _legacy_fields_needed(item, entry, seed)
    if _full_context(entry):
        requested.add("summary")
    if not _has_semantic_context(entry):
        return requested
    # One request contains every semantic gap. Cache filtering later removes
    # fields already known without splitting this article into several calls.
    requested.update(NEW_SEMANTIC_FIELDS | {"summary", "initial_access", "attack_flow"})
    if not (seed or {}).get("impact"):
        requested.add("impact")
    return requested


def fields_needed_for_ai(item: Item, entry: RawEntry) -> set[str]:
    if item.Source_ID not in TARGET_SOURCES:
        return set()
    return _fields_needed(item, entry, _deterministic_seed(entry))


def _cache_entry(runtime: _Runtime, key: str, item: Item, entry: RawEntry) -> dict:
    value = runtime.cache.get(key)
    if not isinstance(value, dict):
        value = {
            "item_id": item.Item_ID,
            "source_id": item.Source_ID,
            "content_hash": _content_hash(entry),
            "model": runtime.model,
            "fields": {},
        }
        runtime.cache[key] = value
    if not isinstance(value.get("fields"), dict):
        value["fields"] = {}
    return value


def _revalidate_previous_cached_value(field: str, value, context: str):
    if value is None:
        return None
    if field == "attack_flow":
        cleaned = _normalize_attack_flow(value, context)
        return cleaned or None
    if field == "impact":
        return _normalize_impact(value, context)
    return value


def _cache_value_present(value) -> bool:
    return value not in (None, "", [], {})


#: Statut terminal d'une valeur retirée par une évolution de contrat ou par une
#: revalidation. Elle reste lisible dans le cache et dans la trace, mais aucun
#: chemin ne la republie : seul `accepted` est matérialisé.
CACHE_STATUS_INVALIDATED = "invalidated"


def _invalidate_cached_field(
    runtime: _Runtime, field: str, cached: dict, version: str, reason: str
) -> None:
    """Retire une valeur du cache sans l'effacer de la trace.

    L'audit demandait qu'une valeur invalidée reste consultable — c'est le seul
    moyen de distinguer les étages « réponse brute », « validation » et
    « fait publié » — mais qu'elle ne puisse plus revenir comme acceptée. Elle
    est donc déplacée dans `invalidated_value` et son statut devient terminal.
    """
    runtime.fields_invalidated += 1
    if not _cache_value_present(cached.get("invalidated_value")):
        cached["invalidated_value"] = cached.get("value")
    cached.update({
        "status": CACHE_STATUS_INVALIDATED,
        "value": None,
        "invalidated_from_version": cached.get("version"),
        "invalidated_reason": reason,
        "version": version,
    })


def _cache_miss_count(cached: dict) -> int:
    try:
        return max(0, int(cached.get("misses") or 0))
    except (TypeError, ValueError):
        return 0


def _read_field_cache(
    runtime: _Runtime, key: str, fields: set[str], context: str = "", organisation: str = ""
) -> tuple[dict, set[str]]:
    entry = runtime.cache.get(key)
    if not isinstance(entry, dict) or not isinstance(entry.get("fields"), dict):
        return {}, set()
    from .source_facts_ai_activity import revalidate_activity_cache
    revalidate_activity_cache(entry, context, organisation, FIELD_VERSIONS)
    result: dict = {}
    satisfied: set[str] = set()
    for field in fields:
        cached = entry["fields"].get(field)
        if not isinstance(cached, dict):
            continue
        current_version = FIELD_VERSIONS[field]
        if cached.get("version") != current_version:
            previous = PREVIOUS_FIELD_VERSIONS.get(field)
            if previous and cached.get("version") == previous:
                revalidated = _revalidate_previous_cached_value(field, cached.get("value"), context)
                if revalidated is None and _cache_value_present(cached.get("value")):
                    _invalidate_cached_field(
                        runtime, field, cached, current_version, "REVALIDATION_REJECTED"
                    )
                    continue
                cached["value"] = revalidated
                cached["version"] = current_version
            else:
                _invalidate_cached_field(
                    runtime, field, cached, current_version, "CONTRACT_VERSION_CHANGED"
                )
                continue

        value = cached.get("value")
        # Les caches V5 peuvent contenir des noms seuls issus d'articles dont
        # RawEntry.organisation était vide. On n'invalide que cette headline,
        # jamais les faits, identités ou autres champs du même article.
        headline = value.get("value") if isinstance(value, dict) else value
        if field == "summary" and is_organisation_name_only(headline, organisation):
            cached.update({"status": "miss", "misses": 0, "value": None})
            runtime.fields_invalidated += 1
            continue
        status = str(cached.get("status") or "").strip().lower()
        if not status:
            if _cache_value_present(value):
                status = "accepted"
                cached["status"] = status
                cached["misses"] = 0
            else:
                if not runtime.retry_legacy_nulls:
                    # Les caches historiques sans statut utilisaient value:null
                    # pour signifier qu'aucun fait n'avait été extrait. Une reconstruction
                    # normal respecte cet état sans repayer un LLM. Le backfill
                    # historique peut explicitement demander sa migration.
                    satisfied.add(field)
                    runtime.field_cache_hits += 1
                    runtime.legacy_null_skips += 1
                    continue
                status = "miss"
                cached["status"] = status
                cached["misses"] = max(1, _cache_miss_count(cached))
                runtime.legacy_null_migrations += 1

        if status == CACHE_STATUS_INVALIDATED:
            # Terminal : le champ est redemandé, mais son statut n'est pas
            # réécrit en `miss`, sans quoi la raison du retrait disparaîtrait
            # du cache après deux passes.
            continue

        if status == "miss":
            misses = max(1, _cache_miss_count(cached))
            cached["misses"] = misses
            if misses < MAX_FIELD_MISSES:
                continue
            cached["status"] = "abstained"
            status = "abstained"

        if status == "abstained":
            satisfied.add(field)
            runtime.field_cache_hits += 1
            runtime.abstained_field_cache_hits += 1
            continue

        if status != "accepted" or not _cache_value_present(value):
            cached["status"] = "miss"
            cached["misses"] = max(1, _cache_miss_count(cached))
            continue

        satisfied.add(field)
        runtime.field_cache_hits += 1
        runtime.accepted_field_cache_hits += 1
        result[field] = value
    return result, satisfied


def _store_field_cache(runtime: _Runtime, key: str, item: Item, entry: RawEntry, fields: set[str], normalized: dict) -> None:
    target = _cache_entry(runtime, key, item, entry)["fields"]
    for field in fields:
        previous = target.get(field)
        if (field in {"activity_description", "activity_sector_match"}
                and isinstance(previous, dict) and previous.get("version") != FIELD_VERSIONS[field]):
            previous = None
        previous_status = (
            str(previous.get("status") or "").strip().lower()
            if isinstance(previous, dict) else ""
        )
        previous_misses = _cache_miss_count(previous) if isinstance(previous, dict) else 0
        is_retry = previous_status == "miss" and previous_misses > 0
        if is_retry:
            runtime.semantic_retries += 1

        if field in normalized and _cache_value_present(normalized[field]):
            if is_retry:
                runtime.semantic_recovered_on_retry += 1
            target[field] = {
                "version": FIELD_VERSIONS[field],
                "status": "accepted",
                "misses": 0,
                "value": normalized[field],
            }
            continue

        misses = previous_misses + 1 if isinstance(previous, dict) else 1
        # Une absence explicite est terminale pour les nouveaux champs. Une
        # valeur fournie puis rejetée par le validateur est réouverte dans
        # source_facts_ai_execution afin de conserver une vraie seconde chance.
        if (field in NEW_SEMANTIC_FIELDS and not isinstance(previous, dict)
                and field not in {"activity_description", "activity_sector_match"}):
            misses = MAX_FIELD_MISSES
        next_status = "abstained" if misses >= MAX_FIELD_MISSES else "miss"
        if misses == 1:
            runtime.semantic_first_misses += 1
        if next_status == "abstained" and previous_status != "abstained":
            runtime.semantic_new_abstentions += 1
        target[field] = {
            "version": FIELD_VERSIONS[field],
            "status": next_status,
            "misses": misses,
            "value": None,
        }


def _migrate_legacy_cache(runtime: _Runtime, key: str, item: Item, entry: RawEntry, seed: dict, fields: set[str]) -> set[str]:
    legacy_fields = _legacy_fields_needed(item, entry, seed)
    if not legacy_fields:
        return set()
    legacy_key = _legacy_input_hash(item, entry, runtime, legacy_fields)
    legacy = runtime.legacy_cache.get(legacy_key)
    if not isinstance(legacy, dict):
        return set()
    reusable = (legacy_fields & LEGACY_REUSABLE_FIELDS) & fields
    if not reusable:
        return set()
    target = _cache_entry(runtime, key, item, entry)["fields"]
    for field in reusable:
        value = legacy.get(field)
        accepted = _cache_value_present(value)
        target[field] = {
            "version": FIELD_VERSIONS[field],
            "status": "accepted" if accepted else "miss",
            "misses": 0 if accepted else 1,
            "value": value if accepted else None,
        }
        runtime.legacy_field_cache_hits += 1
    return reusable


def _max_output_tokens(runtime: _Runtime, fields: set[str]) -> int:
    weights = {"attack_flow": 360, "data_types": 220, "summary": 160, "impact": 140}
    estimate = 260 + sum(weights.get(field, 140) for field in fields)
    return min(runtime.max_output_tokens, max(600, estimate))


def _error_category(exc: Exception) -> str:
    if isinstance(exc, json.JSONDecodeError):
        return "json_decode"
    if isinstance(exc, SourceFactsAiError):
        text = str(exc)
        if "max_output_tokens" in text or "max_output" in text:
            return "max_output_tokens"
        if "no_output_text" in text or "status=" in text:
            return "no_output_text"
        if text.startswith("HTTP_"):
            return text
        if text == "timeout":
            return "timeout"
        return "source_facts_ai_error"
    if isinstance(exc, TypeError):
        return "type_error"
    if isinstance(exc, ValueError):
        return "value_error"
    return type(exc).__name__


def _request_body(item: Item, context: str, fields: set[str], runtime: _Runtime) -> dict:
    return {
        "model": runtime.model,
        "input": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": _user_prompt(item, context, fields)},
        ],
        "text": {"format": {
            "type": "json_schema",
            "name": "cyberwatch_source_facts",
            "schema": _schema(fields),
            "strict": True,
        }},
        "reasoning": {"effort": "minimal"},
        "max_output_tokens": _max_output_tokens(runtime, fields),
    }


def _perform_request(item, entry, context, fields, runtime, key):
    from . import source_facts_ai as api
    from .source_facts_ai_execution import perform_request
    return perform_request(item, entry, context, fields, runtime, key, api)


def enrich(item: Item, entry: RawEntry, *,
           requested_fields: set[str] | None = None) -> dict | None:
    if item.Source_ID not in TARGET_SOURCES:
        return None
    full_context = _full_context(entry)
    if not full_context:
        return None

    runtime = _runtime()
    runtime.items_eligible += 1
    prepared = prepared_context(entry)
    context_meta = runtime.record_context(prepared)
    seed = _deterministic_seed(entry)
    fields = _fields_needed(item, entry, seed)
    requested = set(requested_fields or ())
    if requested_fields is not None:
        fields &= requested
    if not fields:
        runtime.skipped_no_missing_fields += 1
        return seed or None

    key = _cache_item_key(item, entry, runtime)
    forced_fields = getattr(runtime, "force_field_keys", {}).get(key, set())
    if forced_fields:
        fields |= set(forced_fields if requested_fields is None else forced_fields & requested)
    organisation = item.Organisation_Raw or entry.organisation
    cached, satisfied = _read_field_cache(runtime, key, fields, full_context, organisation)
    if key in getattr(runtime, "force_summary_keys", set()):
        cached.pop("summary", None)
        satisfied.discard("summary")
    if forced_fields:
        for field in forced_fields & fields:
            cached.pop(field, None)
            satisfied.discard(field)
    if satisfied != fields:
        migrated = _migrate_legacy_cache(runtime, key, item, entry, seed, fields - satisfied)
        if migrated:
            legacy_values, legacy_satisfied = _read_field_cache(
                runtime, key, migrated, full_context, organisation
            )
            cached.update(legacy_values)
            satisfied |= legacy_satisfied

    missing = fields - satisfied
    if missing & {"activity_description", "activity_sector_match"}:
        missing.update({"activity_description", "activity_sector_match"})
        for field in ("activity_description", "activity_sector_match"):
            cached.pop(field, None)
    if not missing:
        statuses = {field: "accepted" for field in fields}
        source_facts_ai_retry.settle(item, entry, fields, completed=True, statuses=statuses)
        runtime.cache_hits += 1
        runtime.items_fully_cached += 1
        _record_cache_read(runtime, item, entry, fields, cached, satisfied, context_meta)
        return {**seed, **cached} or None
    if satisfied:
        runtime.items_partially_cached += 1
        _record_cache_read(runtime, item, entry, satisfied, cached, satisfied, context_meta)
    runtime.items_would_call += 1
    if not runtime.enabled:
        source_facts_ai_retry.defer(
            item, entry, missing, getattr(runtime, "disabled_reason", "DISABLED")
        )
        runtime.record_event(item_id=item.Item_ID, url=item.URL, status="disabled",
                             requested_fields=sorted(missing), content_hash=_content_hash(entry),
                             context=context_meta, effective_model="",
                             reason=getattr(runtime, "disabled_reason", "DISABLED"))
        return {**seed, **cached} or None
    if runtime.calls >= runtime.max_calls or runtime.cost >= runtime.max_cost:
        reason = "CALL_LIMIT" if runtime.calls >= runtime.max_calls else "COST_LIMIT"
        source_facts_ai_retry.defer(item, entry, missing, reason)
        runtime.calls_budget_blocked += 1
        runtime.record_event(item_id=item.Item_ID, url=item.URL, status="budget_blocked",
                             requested_fields=sorted(missing), content_hash=_content_hash(entry),
                             context=context_meta, effective_model="",
                             reason="CALL_LIMIT" if runtime.calls >= runtime.max_calls else "COST_LIMIT")
        return {**seed, **cached} or None

    context = _truncate_context(full_context, runtime.max_context_chars)
    if len(context) != len(full_context):
        # La réduction imposée par la limite est tracée explicitement : sans
        # cela, une réponse jugée sur un texte amputé serait indiscernable
        # d'une réponse jugée sur l'article entier.
        context_meta = {**context_meta, "truncated": True, "submitted_chars": len(context)}
    normalized, completed = _perform_request(item, entry, context, missing, runtime, key)
    statuses = field_statuses(item, entry) if completed else None
    source_facts_ai_retry.settle(item, entry, missing, completed=completed, statuses=statuses)
    completed_forced_refresh = bool(forced_fields) and completed
    # Une invalidation complète est monousage : le résultat de cette passe est
    # transmis tel quel à SourceFacts. La conserver rendrait le second
    # consommateur du même article coûteux et non déterministe.
    if completed_forced_refresh:
        forced = getattr(runtime, "force_field_keys", {})
        remaining = set(forced.get(key, set())) - set(forced_fields & fields)
        if remaining:
            forced[key] = remaining
        else:
            forced.pop(key, None)
    return {**seed, **cached, **normalized} or None


def extract_semantic(item: Item, entry: RawEntry) -> SemanticExtraction:
    """Exécute les contrats éditorial et structuré, puis fige leur résultat."""
    # Compatibilité avec les adaptateurs/tests qui remplacent encore `enrich`
    # par une fonction historique à deux arguments.
    try:
        fields = enrich(item, entry, requested_fields=_EDITORIAL_FIELDS) or {}
    except TypeError as exc:
        if "requested_fields" not in str(exc):
            raise
        fields = enrich(item, entry) or {}
        return SemanticExtraction(
            item_id=item.Item_ID,
            content_hash=content_hash(entry),
            fields=dict(fields),
            statuses=dict(field_statuses(item, entry)),
        )
    context = _full_context(entry)
    # Les articles courts ont rarement des jeux de données ou une chronologie
    # suffisamment explicites. Une seconde passe leur ferait seulement payer
    # des abstentions ; les articles riches reçoivent ce contrat spécialisé.
    if len(context) >= 700 or _SEMANTIC_DATA_TYPES_TRIGGER.search(context):
        fields = {
            **fields,
            **(enrich(item, entry, requested_fields=_STRUCTURED_FIELDS) or {}),
        }
    return SemanticExtraction(
        item_id=item.Item_ID,
        content_hash=content_hash(entry),
        fields=dict(fields),
        statuses=dict(field_statuses(item, entry)),
    )


def force_summary_refresh(item: Item, entry: RawEntry) -> None:
    """Force la prochaine extraction de la seule headline pour cet article."""
    runtime = _runtime()
    keys = getattr(runtime, "force_summary_keys", None)
    if keys is None:
        keys = runtime.force_summary_keys = set()
    keys.add(_cache_item_key(item, entry, runtime))


def force_full_refresh(item: Item, entry: RawEntry) -> None:
    """Rouvre tous les faits sémantiques d'un article, sans toucher à son identité.

    Réservé aux backfills explicitement demandés : la collecte quotidienne
    conserve le cache par contenu et ne repaie jamais un article inchangé.
    """
    runtime = _runtime()
    key = _cache_item_key(item, entry, runtime)
    forced = getattr(runtime, "force_field_keys", None)
    if forced is None:
        forced = runtime.force_field_keys = {}
    forced[key] = set(_LLM_FIELDS)
