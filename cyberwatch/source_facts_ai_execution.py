"""Exécution et journal complet d'une demande de faits, sans secrets HTTP."""
from __future__ import annotations
from collections import Counter
import json
import time
from . import article_body, llm_runtime
from .model import Item
from .collectors.base import RawEntry
from .source_facts_ai_runtime import _Runtime, SourceFactsAiError
from .source_facts_ai_contract import FIELD_VERSIONS

def _proposals(raw: dict, fields: set[str]) -> dict:
    """Valeur et preuve brutes proposées, champ par champ.

    Sans elles, un champ rejeté n'a plus de valeur normalisée et le rapport
    n'affiche qu'un motif : la proposition ne survivrait que dans la réponse
    HTTP complète, inexploitable pour une revue.
    """
    out: dict = {}
    for field in sorted(fields):
        candidate = raw.get(field)
        if isinstance(candidate, dict):
            out[field] = {"value": candidate.get("value"),
                          "evidence": candidate.get("evidence"),
                          "confidence": candidate.get("confidence")}
        elif isinstance(candidate, list) and candidate:
            out[field] = {"value": candidate, "evidence": "", "confidence": None}
    return out


def _previous_fields(runtime: _Runtime, key: str) -> dict:
    entry = runtime.cache.get(key, {})
    if isinstance(entry, dict) and isinstance(entry.get("fields"), dict):
        return dict(entry["fields"])
    return {}


def _record_field_outcomes(runtime: _Runtime, cache: dict, fields: set[str]) -> dict:
    outcomes = {
        field: str(cache["fields"][field].get("status") or "unknown")
        for field in fields
    }
    runtime.field_outcomes.update(outcomes.values())
    for field, outcome in outcomes.items():
        runtime.field_outcomes_by_name.setdefault(field, Counter())[outcome] += 1
    return outcomes


def perform_request(item: Item, entry: RawEntry, context: str, fields: set[str],
                     runtime: _Runtime, key: str, api) -> tuple[dict, bool]:
    from .source_facts_ai_activity import normalize_activity, rejection_kind

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
        # Une réponse interrompue ou rejetée reste facturable. Comptabiliser
        # l'usage avant parsing/validation, sans écrire de décision dans le cache.
        model = (runtime.effective_model or str(payload.get("model") or "")
                 or llm_runtime.model_for_task("source_facts", runtime.model))
        input_tokens, output_tokens = api._usage(payload)
        runtime.input_tokens += input_tokens
        runtime.output_tokens += output_tokens
        runtime.cost += api._usage_cost(payload, model)
        raw = json.loads(api._extract_output_text(payload))
        if not isinstance(raw, dict):
            raise SourceFactsAiError("response_not_object")
        missing = fields - raw.keys()
        if missing:
            raise SourceFactsAiError("response_missing_fields: " + ",".join(sorted(missing)))
        organisation = item.Organisation_Raw or entry.organisation
        normalized = api._normalize(raw, context, fields, organisation)
        # Les motifs sont calculés avant l'écriture : c'est ce qui permet à
        # `_store_field_cache` de distinguer une absence explicite d'une valeur
        # proposée puis refusée, au lieu de le corriger après coup.
        _, reasons = normalize_activity(raw, context, organisation)
        previous_fields = _previous_fields(runtime, key)
        api._store_field_cache(runtime, key, item, entry, fields, normalized,
                               raw=raw, reasons=reasons)
        cache = runtime.cache[key]
        cache["effective_model"] = model
        cache["declared_model"] = str(payload.get("model") or "")
        runtime.effective_model = cache["effective_model"]
        rejected = {field: reasons.get(field, "EMPTY_OR_REJECTED_BY_VALIDATOR")
                    for field in fields if field not in normalized}
        for field, reason in rejected.items():
            record = cache["fields"][field]
            record.setdefault("rejection_reason", reason)
            if field in api.REJECTING_FIELDS:
                # Le compteur de tentatives a déjà tranché : ne rien réécrire.
                continue
            # Hors du couple activité/secteur, une valeur proposée puis rejetée
            # garde sa seconde chance historique.
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
        field_outcomes = _record_field_outcomes(runtime, cache, fields)
        if api.REJECTING_FIELDS & fields:
            api._record_pair_from_cache(runtime, item, entry, key, "call")
        runtime.record_event(**event, status="success", normalized=normalized,
                             proposals=_proposals(raw, fields), rejections=rejected,
                             field_outcomes=field_outcomes,
                             rejection_kinds={field: rejection_kind(reason)
                                              for field, reason in rejected.items()})
        runtime.calls_succeeded += 1
        return normalized, True
    except (SourceFactsAiError, ValueError, TypeError, json.JSONDecodeError) as exc:
        runtime.calls_failed += 1
        reason = api._error_category(exc)
        runtime.error_reasons[reason] += 1
        # Aucune écriture de cache sur ce chemin : une panne ne consomme jamais
        # de tentative sémantique et ne rend rien terminal.
        if api.REJECTING_FIELDS & fields:
            api._record_pair_failure(runtime, item, entry, reason)
        runtime.record_event(**event, status="failed", reason=reason)
        return {}, False
    finally:
        runtime.durations.append(time.monotonic() - started)
        runtime.progress()
        runtime.checkpoint()
