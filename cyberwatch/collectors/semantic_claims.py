"""Extracteur sémantique partagé pour les articles éditoriaux.

Le modèle propose uniquement des faits atomiques ancrés dans un extrait exact de
l'article. Le runtime impose Structured Outputs ; cette couche revalide ensuite
mécaniquement les preuves, les types et les nombres avant de rendre un résultat.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any

from .. import llm_runtime
from ..normalize import searchable

STATUSES = {"confirmed", "reported", "claimed", "hypothesis", "denied", "negated", "unknown"}
CLAIM_TYPES = {
    "affected_count", "data_volume", "data_type", "system", "dataset", "initial_access",
    "attack_action", "impact", "remediation", "actor", "third_party", "vulnerability",
    "publication", "statement",
}
RELATIONS = {"uses", "compromised_via", "claimed_by", "published_by", "affects", "hosted_by", "provided_by", "exposed"}
MAX_EVIDENCE = 420


@dataclass(frozen=True)
class SemanticPolicy:
    task: str
    prompt_version: str
    system_prompt: str
    env_prefix: str
    cache_filename: str
    default_enabled: bool = True


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _schema() -> dict[str, Any]:
    nullable_string = {"type": ["string", "null"]}
    nullable_value = {"type": ["string", "number", "null"]}
    status = {"type": "string", "enum": sorted(STATUSES)}
    return {
        "type": "object",
        "properties": {
            "claims": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "type": {"type": "string", "enum": sorted(CLAIM_TYPES)},
                        "status": status,
                        "value": nullable_value,
                        "unit": nullable_string,
                        "scope": nullable_string,
                        "date": nullable_string,
                        "actor": nullable_string,
                        "evidence": {"type": "string"},
                    },
                    "required": ["type", "status", "value", "unit", "scope", "date", "actor", "evidence"],
                    "additionalProperties": False,
                },
            },
            "timeline": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "date": {"type": "string"},
                        "status": status,
                        "event": {"type": "string"},
                        "evidence": {"type": "string"},
                    },
                    "required": ["date", "status", "event", "evidence"],
                    "additionalProperties": False,
                },
            },
            "relations": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "subject": {"type": "string"},
                        "relation": {"type": "string", "enum": sorted(RELATIONS)},
                        "object": {"type": "string"},
                        "status": status,
                        "evidence": {"type": "string"},
                    },
                    "required": ["subject", "relation", "object", "status", "evidence"],
                    "additionalProperties": False,
                },
            },
        },
        "required": ["claims", "timeline", "relations"],
        "additionalProperties": False,
    }


def enabled(policy: SemanticPolicy, source_id: str = "") -> bool:
    if not llm_runtime.runtime().enabled:
        return False
    raw = os.getenv(f"{policy.env_prefix}_ENABLED", "1" if policy.default_enabled else "0").strip().lower()
    if raw in {"0", "false", "no", "off"}:
        return False
    sources_raw = os.getenv(f"{policy.env_prefix}_SOURCES", "").strip()
    if not sources_raw:
        return True
    sources = {part.strip().upper() for part in sources_raw.split(",") if part.strip()}
    source = str(source_id or "").strip().upper()
    return "*" in sources or source in sources


def is_candidate(text: str, deterministic: dict) -> bool:
    """Heuristique de valeur : n'appelle le LLM que pour un gap sémantique plausible."""
    low = searchable(text or "")
    ambiguous = any(token in low for token in (
        "pourrait", "pourraient", "susceptible", "hypothese", "non confirme", "dement",
        "n ont pas ete", "n a pas ete", "selon l attaquant", "revendique", "supply chain",
        "prestataire", "fournisseur", "sous traitant", "aws", "azure", "cloud",
    ))
    richness = sum(len(deterministic.get(key) or []) for key in (
        "affected_counts", "data_volumes", "timeline", "relations", "data_types"
    ))
    dates = len(re.findall(
        r"\b\d{1,2}\s+(?:janvier|f[ée]vrier|mars|avril|mai|juin|juillet|ao[uû]t|septembre|octobre|novembre|d[ée]cembre)\s+20\d{2}\b",
        text or "",
        re.I,
    ))
    # Un article long n'est plus, à lui seul, un motif suffisant. Il doit aussi
    # présenter un manque ou une complexité sémantique observable.
    missing_semantic = any(not deterministic.get(key) for key in (
        "timeline", "relations", "data_types", "affected_counts", "data_volumes"
    ))
    long_and_incomplete = len(text or "") >= 4500 and missing_semantic
    return ambiguous or richness >= 5 or dates >= 2 or long_and_incomplete


def _cache_path(policy: SemanticPolicy) -> Path:
    raw = os.getenv(f"{policy.env_prefix}_CACHE_PATH", "").strip()
    return Path(raw) if raw else Path(__file__).resolve().parents[2] / "data" / policy.cache_filename


def _load_cache(policy: SemanticPolicy) -> dict[str, Any]:
    try:
        data = json.loads(_cache_path(policy).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


def _save_cache(policy: SemanticPolicy, cache: dict[str, Any]) -> None:
    path = _cache_path(policy)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(cache, ensure_ascii=False, sort_keys=True), encoding="utf-8")
        tmp.replace(path)
    except OSError:
        pass


def content_hash(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def _cache_key(policy: SemanticPolicy, source_id: str, text: str, model: str) -> str:
    payload = f"{policy.prompt_version}\0{model}\0{source_id}\0{text}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _evidence_present(evidence: str, article: str) -> bool:
    return bool(evidence and len(evidence) <= MAX_EVIDENCE and searchable(evidence) in searchable(article))


def _numeric_supported(value: object, evidence: str) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return True
    digits = re.sub(r"\D", "", str(int(value)))
    evidence_digits = re.sub(r"\D", "", evidence)
    if digits and digits in evidence_digits:
        return True
    millions = re.search(r"(\d+(?:[.,]\d+)?)\s*millions?", evidence, re.I)
    if millions:
        try:
            return int(round(float(millions.group(1).replace(",", ".")) * 1_000_000)) == int(value)
        except ValueError:
            return False
    thousands = re.search(r"(\d+(?:[.,]\d+)?)\s*(?:milliers?|mille)\b", evidence, re.I)
    if thousands:
        try:
            return int(round(float(thousands.group(1).replace(",", ".")) * 1_000)) == int(value)
        except ValueError:
            return False
    return False


def _clean_claim(raw: object, article: str) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    evidence = str(raw.get("evidence") or "").strip()
    if not _evidence_present(evidence, article):
        return None
    claim_type = str(raw.get("type") or "").strip().lower()
    if claim_type not in CLAIM_TYPES:
        return None
    status = str(raw.get("status") or "unknown").strip().lower()
    status = status if status in STATUSES else "unknown"
    value = raw.get("value")
    if not _numeric_supported(value, evidence):
        return None
    result: dict[str, Any] = {"type": claim_type, "status": status, "evidence": evidence[:MAX_EVIDENCE]}
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        result["value"] = value
    else:
        text = str(value or "").strip()
        if text:
            result["value"] = text[:220]
    for key in ("unit", "scope", "date", "actor"):
        text = str(raw.get(key) or "").strip()
        if text:
            result[key] = text[:180]
    return result


def _clean_timeline(raw: object, article: str) -> dict[str, str] | None:
    if not isinstance(raw, dict):
        return None
    evidence = str(raw.get("evidence") or "").strip()
    date = str(raw.get("date") or "").strip()
    event = str(raw.get("event") or "").strip()
    if not date or not event or not _evidence_present(evidence, article):
        return None
    status = str(raw.get("status") or "unknown").strip().lower()
    return {
        "date": date[:32],
        "status": status if status in STATUSES else "unknown",
        "event": event[:240],
        "evidence": evidence[:MAX_EVIDENCE],
    }


def _relation_endpoint_grounded(endpoint: str, evidence: str) -> bool:
    """Un sujet/objet de relation doit apparaître dans sa propre preuve.

    Une preuve peut être un extrait réel de l'article (donc valider
    ``_evidence_present``) sans pour autant parler du sujet ou de l'objet
    annoncés par le modèle — signe d'une relation contaminée par le contexte
    d'un autre incident traité dans le même lot plutôt qu'ancrée dans le
    texte qu'elle prétend citer.
    """
    return bool(endpoint) and searchable(endpoint) in searchable(evidence)


def _clean_relation(raw: object, article: str) -> dict[str, str] | None:
    if not isinstance(raw, dict):
        return None
    evidence = str(raw.get("evidence") or "").strip()
    subject = str(raw.get("subject") or "").strip()
    obj = str(raw.get("object") or "").strip()
    relation = str(raw.get("relation") or "").strip().lower()
    if not subject or not obj or relation not in RELATIONS or not _evidence_present(evidence, article):
        return None
    if not _relation_endpoint_grounded(subject, evidence) and not _relation_endpoint_grounded(obj, evidence):
        return None
    status = str(raw.get("status") or "unknown").strip().lower()
    return {
        "subject": subject[:180],
        "relation": relation,
        "object": obj[:180],
        "status": status if status in STATUSES else "unknown",
        "evidence": evidence[:MAX_EVIDENCE],
    }


def enrich(
    text: str,
    deterministic: dict,
    *,
    source_id: str,
    policy: SemanticPolicy,
) -> dict[str, Any]:
    if not enabled(policy, source_id) or not is_candidate(text, deterministic):
        return {}

    model = os.getenv(
        f"{policy.env_prefix}_MODEL",
        os.getenv("OPENAI_MODEL", llm_runtime.DEFAULT_MODEL),
    ).strip() or llm_runtime.DEFAULT_MODEL
    cache_key = _cache_key(policy, source_id, text or "", model)
    cache = _load_cache(policy)
    cached = cache.get(cache_key)
    if isinstance(cached, dict):
        result = dict(cached)
        result["cache_hit"] = True
        return result

    max_chars = _env_int(f"{policy.env_prefix}_MAX_CONTEXT_CHARS", 18000)
    max_output_tokens = _env_int(f"{policy.env_prefix}_MAX_OUTPUT_TOKENS", 1400)
    # Plafond dynamique : le schéma riche reste borné mais évite 1800 tokens
    # systématiques pour des articles dont le gap déterministe est faible.
    missing = sum(not deterministic.get(key) for key in (
        "affected_counts", "data_volumes", "timeline", "relations", "data_types"
    ))
    max_output_tokens = min(max_output_tokens, 700 + 140 * max(1, missing))

    try:
        call = llm_runtime.runtime().call_json(
            task=policy.task,
            model=model,
            system_prompt=policy.system_prompt,
            user_content=(text or "")[:max_chars],
            schema_name="cyberwatch_semantic_claims",
            schema=_schema(),
            max_output_tokens=max_output_tokens,
            reasoning_effort="minimal",
        )
        raw = call.data
    except llm_runtime.LlmError:
        return {}

    raw_claims = list(raw.get("claims") or [])[:40]
    raw_timeline = list(raw.get("timeline") or [])[:20]
    raw_relations = list(raw.get("relations") or [])[:20]
    claims = [value for value in (_clean_claim(v, text) for v in raw_claims) if value]
    timeline = [value for value in (_clean_timeline(v, text) for v in raw_timeline) if value]
    relations = [value for value in (_clean_relation(v, text) for v in raw_relations) if value]
    accepted = len(claims) + len(timeline) + len(relations)
    proposed = len(raw_claims) + len(raw_timeline) + len(raw_relations)
    result = {
        "claims": claims,
        "timeline": timeline,
        "relations": relations,
        "model": model,
        "prompt_version": policy.prompt_version,
        "cache_hit": False,
        "proposed": proposed,
        "accepted": accepted,
        "rejected": proposed - accepted,
        "input_tokens": call.usage.input_tokens,
        "output_tokens": call.usage.output_tokens,
        "estimated_cost_usd": round(call.usage.estimated_cost_usd, 8),
        "duration_seconds": round(call.duration_seconds, 3),
        "retries": call.retries,
        "accepted_facts_per_call": accepted,
        "cost_per_accepted_fact": round(call.usage.estimated_cost_usd / accepted, 8) if accepted else 0.0,
        "latency_per_accepted_fact": round(call.duration_seconds / accepted, 3) if accepted else 0.0,
    }
    cache[cache_key] = result
    _save_cache(policy, cache)
    return result
