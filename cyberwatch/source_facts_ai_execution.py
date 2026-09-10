"""Exécution et journal complet d'une demande de faits, sans secrets HTTP."""
from __future__ import annotations
import json
import time
from . import article_body
from .model import Item
from .collectors.base import RawEntry
from .source_facts_ai_runtime import _Runtime, SourceFactsAiError
from .source_facts_ai_contract import FIELD_VERSIONS

def perform_request(item: Item, entry: RawEntry, context: str, fields: set[str],
                     runtime: _Runtime, key: str, api) -> tuple[dict, bool]:
    from .source_facts_ai_activity import normalize_activity

    body = api._request_body(item, context, fields, runtime)
    # Le contexte soumis est archivé une seule fois par empreinte ; l'événement
    # n'en porte que l'empreinte et la taille. Le corps de requête est conservé
    # tel quel : il fige les paramètres de troncature réellement appliqués.
    submitted = runtime.record_context(article_body.prepare(context))
    event = {"item_id": item.Item_ID, "source_id": item.Source_ID, "url": item.URL,
             "content_hash": api._content_hash(entry),
             "submitted_context_hash": submitted["prepared_hash"],
             "submitted_context_chars": submitted["prepared_chars"],
             "organisation": item.Organisation_Raw, "requested_fields": sorted(fields),
             "field_versions": {field: FIELD_VERSIONS[field] for field in fields},
             "request": body}
    started = time.monotonic()
    runtime.calls += 1
    runtime.fields_requested.update(fields)
    runtime.fields_requested_new.update(fields)
    try:
        payload = api._post_openai(body, runtime)
        event["response"] = payload
        raw = json.loads(api._extract_output_text(payload))
        if not isinstance(raw, dict):
            raise SourceFactsAiError("response_not_object")
        normalized = api._normalize(raw, context, fields, item.Organisation_Raw or entry.organisation)
        previous_entry = runtime.cache.get(key, {})
        previous_fields = (
            dict(previous_entry.get("fields", {}))
            if isinstance(previous_entry, dict) and isinstance(previous_entry.get("fields"), dict)
            else {}
        )
        api._store_field_cache(runtime, key, item, entry, fields, normalized)
        cache = runtime.cache[key]
        cache["effective_model"] = runtime.effective_model or payload.get("model", runtime.model)
        runtime.effective_model = cache["effective_model"]
        _, reasons = normalize_activity(raw, context, item.Organisation_Raw or entry.organisation)
        rejected = {field: reasons.get(field, "EMPTY_OR_REJECTED_BY_VALIDATOR")
                    for field in fields if field not in normalized}
        for field, reason in rejected.items():
            record = cache["fields"][field]
            record["rejection_reason"] = reason
            candidate = raw.get(field)
            has_candidate = bool(
                (isinstance(candidate, dict) and candidate.get("value") not in (None, "", [], {}))
                or (isinstance(candidate, list) and candidate)
            )
            if (
                has_candidate
                and record.get("status") == "abstained"
                and not isinstance(previous_fields.get(field), dict)
            ):
                record.update(status="miss", misses=1)
        runtime.record_event(**event, status="success", normalized=normalized, rejections=rejected)
        input_tokens, output_tokens = api._usage(payload)
        runtime.input_tokens += input_tokens
        runtime.output_tokens += output_tokens
        runtime.cost += api._usage_cost(payload, cache["effective_model"])
        runtime.calls_succeeded += 1
        return normalized, True
    except (SourceFactsAiError, ValueError, TypeError, json.JSONDecodeError) as exc:
        runtime.calls_failed += 1
        reason = api._error_category(exc)
        runtime.error_reasons[reason] += 1
        runtime.record_event(**event, status="failed", reason=reason)
        return {}, False
    finally:
        runtime.durations.append(time.monotonic() - started)
        runtime.progress()
        runtime.checkpoint()
