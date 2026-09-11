"""Schémas et transport de l'extraction sémantique."""

from __future__ import annotations

from . import config, llm_runtime
from .model import Item
from .source_facts_ai_contract import _LLM_FIELDS
from .source_facts_ai_runtime import SourceFactsAiError, _Runtime

def _fact_schema() -> dict:
    return {
        "type": "object",
        "properties": {
            "value": {"type": "string"},
            "confidence": {"type": "number"},
            "evidence": {"type": "string"},
        },
        "required": ["value", "confidence", "evidence"],
        "additionalProperties": False,
    }


def _schema(fields: set[str]) -> dict:
    definitions = {
        "summary": _fact_schema(),
        "incident_summary": {
            "type": "array", "items": _fact_schema(), "maxItems": 2,
        },
        "data_types": {"type": "array", "items": _fact_schema(), "maxItems": 20},
        "activity_description": _fact_schema(),
        "activity_sector_match": {**_fact_schema(), "properties": {**_fact_schema()["properties"], "value": {"type": "string", "enum": [*config.SECTORS]}}},
        "threat_candidate": {**_fact_schema(), "properties": {**_fact_schema()["properties"], "value": {"type": "string", "enum": ["", *config.THREATS]}}},
    }
    ordered = [name for name in _LLM_FIELDS if name in fields]
    return {
        "type": "object",
        "properties": {name: definitions[name] for name in ordered},
        "required": ordered,
        "additionalProperties": False,
    }


def _user_prompt(item: Item, context: str, fields: set[str]) -> str:
    requested = ", ".join(name for name in _LLM_FIELDS if name in fields)
    return (
        "=== Métadonnées fiables ===\n"
        f"Source: {item.Source_ID}\nVictime: {item.Organisation_Raw}\n"
        f"Date de publication: {item.Published_Date}\n\n"
        f"=== Article source ===\n{context}\n\n"
        f"=== Extraction demandée ===\nChamps uniquement: {requested}.\n"
        "N'ajoute aucun autre champ."
    )


def _extract_output_text(payload: dict) -> str:
    try:
        llm_runtime.ensure_response_completed(payload)
    except llm_runtime.LlmError as exc:
        raise SourceFactsAiError(str(exc)) from exc
    text = payload.get("output_text")
    if text:
        return str(text)
    for output in payload.get("output", []) or []:
        if not isinstance(output, dict) or output.get("type") != "message":
            continue
        for part in output.get("content", []) or []:
            if isinstance(part, dict) and part.get("type") in {"output_text", "text"} and part.get("text"):
                return str(part["text"])
    status_value = str(payload.get("status") or "")
    incomplete = payload.get("incomplete_details") or {}
    reason = str(incomplete.get("reason") or "") if isinstance(incomplete, dict) else ""
    detail = f"status={status_value},reason={reason}" if status_value or reason else "no_output_text"
    raise SourceFactsAiError(detail)


def _post_openai(body: dict, runtime: _Runtime) -> dict:
    shared = llm_runtime.runtime()
    before_retries = shared.stats.retries
    before_timeouts = shared.stats.timeouts
    before_429 = shared.stats.http_429
    before_5xx = shared.stats.http_5xx
    try:
        result = shared.post_response(
            task="source_facts",
            body=body,
            api_key=runtime.api_key,
        )
        runtime.effective_model = result.model
        return result.payload
    except llm_runtime.LlmError as exc:
        raise SourceFactsAiError(str(exc)) from exc
    finally:
        runtime.retries += max(0, shared.stats.retries - before_retries)
        runtime.timeouts += max(0, shared.stats.timeouts - before_timeouts)
        runtime.http_429 += max(0, shared.stats.http_429 - before_429)
        runtime.http_5xx += max(0, shared.stats.http_5xx - before_5xx)


def _usage(payload: dict) -> tuple[int, int]:
    usage = payload.get("usage") or {}
    return int(usage.get("input_tokens", 0) or 0), int(usage.get("output_tokens", 0) or 0)


def _usage_cost(payload: dict, model: str) -> float:
    return llm_runtime.extract_usage(payload, model).estimated_cost_usd
