"""Exécution et journal complet d'une demande de faits, sans secrets HTTP."""
from __future__ import annotations
from collections import Counter
import json
import time
from . import article_body, llm_runtime
from .model import Item
from .collectors.base import RawEntry
from .source_facts_ai_runtime import _Runtime, SourceFactsAiError
from .source_facts_ai_contract import FIELD_VERSIONS, RETRY_EVIDENCE_INSTRUCTIONS
from .evidence_repair import repair_evidence
from . import evidence_repair_llm
from .source_facts_ai_activity import evidence_repair_eligibility

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



def _repair_evidence_in_place(api, runtime, raw: dict, context: str, fields: set[str],
                              organisation: str, normalized: dict, reasons: dict) -> dict:
    """Cherche une meilleure citation pour les champs refusés sur leur preuve.

    La valeur proposée n'est jamais touchée : seule `evidence` est remplacée,
    par un extrait exact de l'article. Rien n'est accepté ici — le fait n'existe
    que si `_normalize` le revalide, avec les mêmes contrôles qu'au premier
    passage. Rend la trace de réparation, champ par champ.
    """
    from .source_facts_ai_activity import field_rejection_kind
    from .source_facts_ai_normalize import field_rejection_reason

    trace: dict = {}
    repaired = False
    pending: dict[str, str] = {}
    for field in sorted(fields - normalized.keys()):
        reason = reasons.get(field) or field_rejection_reason(field, raw, context, organisation)
        kind = field_rejection_kind(field, reason)
        if not evidence_repair_eligibility(field, reason, kind):
            trace[field] = {"initial_rejection": reason, "eligible": False}
            continue
        candidate = raw.get(field)
        value = candidate.get("value") if isinstance(candidate, dict) else ""
        evidence = repair_evidence(field, str(value or ""), context, organisation)
        trace[field] = {"initial_rejection": reason, "eligible": True,
                        "method": "deterministic" if evidence else "none",
                        "evidence": evidence, "llm_called": False}
        if evidence:
            raw[field] = {**candidate, "evidence": evidence}
            repaired = True
            runtime.repair_deterministic_success += 1
        elif isinstance(candidate, dict) and str(value or "").strip():
            # Rien dans l'article ne se laisse valider déterministement : ce
            # champ part dans l'appel groupé, s'il y en a un.
            pending[field] = str(value)
    runtime.repair_eligible += sum(1 for record in trace.values() if record.get("eligible"))

    if pending:
        # Un seul appel par item, tous les champs réparables ensemble.
        runtime.repair_llm_calls += 1
        citations, repair_cost = evidence_repair_llm.request_evidence(context, pending, runtime.api_key)
        runtime.repair_cost += repair_cost
        runtime.cost += repair_cost
        for field, evidence in citations.items():
            candidate = raw.get(field)
            if not isinstance(candidate, dict) or not evidence:
                continue
            raw[field] = {**candidate, "evidence": evidence}
            repaired = True
            trace[field].update(method="llm", evidence=evidence, llm_called=True)
        for field in pending:
            trace[field]["llm_called"] = True

    if repaired:
        normalized.update(api._normalize(raw, context, fields, organisation))
    for field, record in trace.items():
        record["final_outcome"] = "accepted" if field in normalized else "rejected"
        if not record.get("eligible"):
            continue
        if record["final_outcome"] == "accepted":
            if record.get("method") == "llm":
                runtime.repair_llm_success += 1
        else:
            runtime.repair_failed += 1
            # Une citation refusée par les validateurs n'est pas une réparation.
            if record.get("method") == "deterministic":
                runtime.repair_deterministic_success -= 1
    return trace


def _record_field_outcomes(runtime: _Runtime, cache: dict, fields: set[str]) -> dict:
    outcomes = {
        field: str(cache["fields"][field].get("status") or "unknown")
        for field in fields
    }
    runtime.field_outcomes.update(outcomes.values())
    for field, outcome in outcomes.items():
        runtime.field_outcomes_by_name.setdefault(field, Counter())[outcome] += 1
    return outcomes


def _retry_reasons(previous_fields: dict, fields: set[str]) -> dict[str, str]:
    """Champs redemandés parce que leur preuve a été refusée, avec ce motif.

    Le motif vient du validateur déterministe, jamais du modèle : la reprise
    rappelle le contrat violé, sans rien assouplir.
    """
    out: dict[str, str] = {}
    for field in sorted(fields):
        record = previous_fields.get(field)
        if not isinstance(record, dict):
            continue
        reason = str(record.get("rejection_reason") or "")
        status = str(record.get("status") or "").strip().lower()
        if status in {"miss", "rejected"} and reason in RETRY_EVIDENCE_INSTRUCTIONS:
            out[field] = reason
    return out


def perform_request(item: Item, entry: RawEntry, context: str, fields: set[str],
                     runtime: _Runtime, key: str, api) -> tuple[dict, bool]:
    from .source_facts_ai_activity import field_rejection_kind, normalize_activity
    from .source_facts_ai_normalize import field_rejection_reason

    previous_fields = _previous_fields(runtime, key)
    retry_reasons = _retry_reasons(previous_fields, fields)
    body = api._request_body(item, context, fields, runtime, retry_reasons=retry_reasons)
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
             "retry_reasons": retry_reasons,
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
        # Réparation de preuve : une valeur juste refusée sur une mauvaise
        # citation retrouve sa chance, sans qu'aucun validateur soit assoupli.
        repair = _repair_evidence_in_place(api, runtime, raw, context, fields, organisation,
                                           normalized, reasons)
        api._store_field_cache(runtime, key, item, entry, fields, normalized,
                               raw=raw, reasons=reasons)
        cache = runtime.cache[key]
        cache["effective_model"] = model
        cache["declared_model"] = str(payload.get("model") or "")
        runtime.effective_model = cache["effective_model"]
        rejected = {field: reasons.get(field)
                    or field_rejection_reason(field, raw, context, organisation)
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
                             rejection_kinds={field: field_rejection_kind(field, reason)
                                              for field, reason in rejected.items()},
                             repair=repair)
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
