"""Filet de rattrapage LLM pour Threat/Sector/Location encore `Inconnu`.

Principe absolu : ce module n'intervient **jamais** avant que les règles
déterministes (`normalize.py`) et le backfill (`enrichment.py`) aient eu leur
mot à dire. Il ne touche que les champs encore `Inconnu` après cela, ne peut
jamais écraser une valeur déjà connue, et son absence (clé API manquante,
panne réseau, budget épuisé) ne bloque jamais une collecte : les champs
concernés restent simplement `Inconnu`.

Aucun appel n'est fait pendant `REPLAY` : ce module n'est sollicité que par
`runner.execute()` dans sa branche réseau (`offline=False`), jamais dans la
branche hors-ligne qui reconstruit `INCIDENTS` depuis `ITEMS`.

Le modèle est appelé directement en HTTPS via `requests` (l'API Responses
d'OpenAI, Structured Outputs) — pas de SDK, `requests` est déjà une
dépendance du projet.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field

import requests

from . import config, store
from .collectors.base import RawEntry, SourceSpec
from .identity import SEP
from .model import Item

# --------------------------------------------------------------------------
# Modèle et tarification
#
# Snapshot et tarifs choisis via recherche web le 2026-08-15 : la
# documentation officielle (developers.openai.com, openai.com, openrouter.ai)
# est inaccessible depuis cet environnement (politique réseau du bac à
# sable). Ces valeurs ne sont donc PAS vérifiées sur une source primaire —
# à corriger si la réponse API réelle (nom de modèle refusé) ou une facture
# les contredit. `OPENAI_MODEL` reste overridable sans toucher au code.
# --------------------------------------------------------------------------

DEFAULT_MODEL = "gpt-5-nano-2026-03-17"

#: Dollars US par million de tokens. `cached_input` n'est volontairement pas
#: utilisé dans le calcul de coût (voir `_estimate_cost`) : à défaut d'un
#: tarif remisé vérifié, tous les tokens d'entrée sont comptés au tarif
#: plein, ce qui majore l'estimation au lieu de la sous-évaluer.
PRICING = {
    DEFAULT_MODEL: {"input": 0.05, "output": 0.40},
}

PROMPT_VERSION = "2026-08-15.1"
SCHEMA_VERSION = "1"

OPENAI_URL = "https://api.openai.com/v1/responses"
OPENAI_TIMEOUT_SECONDS = 20
OPENAI_MAX_RETRIES = 2

EVIDENCE_MAX_CHARS = 200

#: Seuils de confiance par champ. Location est plus stricte : une mauvaise
#: localisation est plus visible et plus gênante qu'un secteur approximatif.
#: Modifier un seuil doit s'accompagner d'un bump de `SCHEMA_VERSION`, sinon
#: d'anciennes décisions en cache resteraient appliquées sous l'ancien seuil.
THRESHOLD_THREAT = 0.6
THRESHOLD_SECTOR = 0.6
THRESHOLD_LOCATION = 0.75

#: Nom du champ Item -> (clé JSON, taxonomie fermée, sentinelle Inconnu, seuil).
FIELD_SPECS = {
    "Threat": ("threat", config.THREATS, config.THREAT_UNKNOWN, THRESHOLD_THREAT),
    "Sector": ("sector", config.SECTORS, config.SECTOR_UNKNOWN, THRESHOLD_SECTOR),
    "Location": ("location", config.LOCATIONS, config.LOC_INCONNU, THRESHOLD_LOCATION),
}

SYSTEM_PROMPT = (
    "Tu es un classificateur strict pour un observatoire d'incidents cyber. "
    "On te donne le contexte brut d'un article ou d'un enregistrement déjà "
    "reconnu comme un incident cyber ; certains champs sont encore inconnus. "
    "Réponds uniquement à partir du texte fourni, jamais de connaissance "
    "générale supposée sur l'organisation citée. Si le contexte ne permet pas "
    "de trancher avec confiance, réponds Inconnu plutôt que de deviner : "
    "Inconnu est toujours une réponse valide et préférable à une erreur. "
    "L'evidence doit être une très courte citation ou paraphrase du texte "
    "fourni justifiant la valeur choisie (une phrase maximum), jamais une "
    "justification longue. Pour la localisation, n'indique un territoire que "
    "s'il est explicitement soutenu par le texte fourni : ne déduis jamais "
    "un territoire du seul nom ou secteur d'activité d'une organisation."
)


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if not value:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    value = os.getenv(name)
    if not value:
        return default
    try:
        return float(value)
    except ValueError:
        return default


class AiCallError(Exception):
    """Échec (réseau, HTTP ou format) d'un appel à l'API OpenAI."""


@dataclass
class AiRunState:
    """État mutable d'un run : budget, cache, compteurs d'usage."""

    enabled: bool
    api_key: str = ""
    model: str = DEFAULT_MODEL
    max_calls: int = 2000
    max_cost: float = 1.00
    max_context_chars: int = 4000
    max_output_tokens: int = 300

    cache: dict[tuple[str, str], dict] = field(default_factory=dict)

    candidates: int = 0
    cache_hits: int = 0
    calls_attempted: int = 0
    calls_succeeded: int = 0
    calls_failed: int = 0
    calls_budget_blocked: int = 0
    budget_stopped: bool = False

    unknown_before: dict[str, int] = field(default_factory=dict)
    qualified: dict[str, int] = field(default_factory=dict)

    input_tokens: int = 0
    cached_input_tokens: int = 0
    output_tokens: int = 0
    reasoning_tokens: int = 0
    total_tokens: int = 0
    estimated_cost_usd: float = 0.0

    started: float = field(default_factory=time.monotonic)


def start_run() -> AiRunState:
    """Prépare l'état du run : détecte la clé, charge le cache existant.

    L'absence de `OPENAI_API_KEY` n'est jamais une erreur : la qualification
    est simplement désactivée pour ce run, journalisée, et le run continue.
    """
    api_key = os.getenv("OPENAI_API_KEY", "")
    state = AiRunState(
        enabled=bool(api_key),
        api_key=api_key,
        model=os.getenv("OPENAI_MODEL", DEFAULT_MODEL),
        max_calls=_env_int("AI_MAX_CALLS_PER_RUN", 2000),
        max_cost=_env_float("AI_MAX_ESTIMATED_COST_USD_PER_RUN", 1.00),
        max_context_chars=_env_int("AI_MAX_CONTEXT_CHARS", 4000),
        max_output_tokens=_env_int("AI_MAX_OUTPUT_TOKENS", 300),
    )
    if not state.enabled:
        print("Qualification IA désactivée : OPENAI_API_KEY absente.")
        return state
    for row in store.load_ai_qualifications():
        key = (row.get("Item_ID", ""), row.get("Input_Hash", ""))
        state.cache[key] = row
    return state


def _pricing_for(model: str) -> dict:
    rates = PRICING.get(model)
    if rates is None:
        print(f"Qualification IA : tarif inconnu pour le modèle '{model}', "
              f"estimation basée sur {DEFAULT_MODEL}.")
        rates = PRICING[DEFAULT_MODEL]
    return rates


def _estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    rates = _pricing_for(model)
    return (input_tokens / 1_000_000) * rates["input"] + (output_tokens / 1_000_000) * rates["output"]


def _context(entry: RawEntry, max_chars: int) -> str:
    parts = [entry.title, entry.summary, entry.content]
    text = " ".join(part for part in parts if part).strip()
    return text[:max_chars]


def _input_hash(item: Item, entry: RawEntry, requested: list[str], model: str, max_chars: int) -> str:
    payload = SEP.join([
        item.Item_ID,
        item.Source_ID,
        ",".join(sorted(requested)),
        _context(entry, max_chars),
        model,
        PROMPT_VERSION,
        SCHEMA_VERSION,
    ])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _build_schema(requested: list[str]) -> dict:
    properties = {}
    for field_name in requested:
        json_key, taxonomy, _, _ = FIELD_SPECS[field_name]
        properties[json_key] = {
            "type": "object",
            "properties": {
                "value": {"type": "string", "enum": list(taxonomy)},
                "confidence": {"type": "number"},
                "evidence": {"type": "string"},
            },
            "required": ["value", "confidence", "evidence"],
            "additionalProperties": False,
        }
    return {
        "type": "object",
        "properties": properties,
        "required": [FIELD_SPECS[f][0] for f in requested],
        "additionalProperties": False,
    }


def _user_content(item: Item, entry: RawEntry, spec: SourceSpec, requested: list[str], max_chars: int) -> str:
    lines = [
        f"Source_ID: {item.Source_ID}",
        f"Organisation_Raw: {item.Organisation_Raw}",
        f"Published_Date: {item.Published_Date}",
        f"Event_Date: {item.Event_Date or '(absente)'}",
        f"Threat_Raw: {item.Threat_Raw or '(absent)'}",
        f"Threat actuel: {item.Threat}",
        f"Sector actuel: {item.Sector}",
        f"Location actuelle: {item.Location}",
        f"Titre: {entry.title}",
        f"Contexte: {_context(entry, max_chars)}",
        "",
        "Champs à qualifier (uniquement ceux-ci, les autres sont déjà connus "
        "et ne doivent pas être reconsidérés) : " + ", ".join(requested),
    ]
    return "\n".join(lines)


def _extract_output_json(payload: dict) -> dict:
    text = payload.get("output_text")
    if not text:
        for item in payload.get("output", []) or []:
            if not isinstance(item, dict) or item.get("type") != "message":
                continue
            for part in item.get("content", []) or []:
                if isinstance(part, dict) and part.get("type") in ("output_text", "text") and part.get("text"):
                    text = part["text"]
                    break
            if text:
                break
    if not text:
        raise AiCallError("réponse sans texte structuré")
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise AiCallError(f"JSON invalide: {exc}") from exc
    if not isinstance(parsed, dict):
        raise AiCallError("réponse JSON non conforme (pas un objet)")
    return parsed


def _extract_usage(payload: dict) -> dict:
    usage = payload.get("usage") or {}
    input_tokens = int(usage.get("input_tokens", 0) or 0)
    cached = int((usage.get("input_tokens_details") or {}).get("cached_tokens", 0) or 0)
    output_tokens = int(usage.get("output_tokens", 0) or 0)
    reasoning = int((usage.get("output_tokens_details") or {}).get("reasoning_tokens", 0) or 0)
    total = int(usage.get("total_tokens") or (input_tokens + output_tokens))
    return {
        "input_tokens": input_tokens,
        "cached_input_tokens": cached,
        "output_tokens": output_tokens,
        "reasoning_tokens": reasoning,
        "total_tokens": total,
    }


def _call_openai(item: Item, entry: RawEntry, spec: SourceSpec, requested: list[str], state: AiRunState) -> dict:
    """POST unique et indépendant, retry borné sur 429/5xx/timeout (§9)."""
    body = {
        "model": state.model,
        "input": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": _user_content(item, entry, spec, requested, state.max_context_chars)},
        ],
        "text": {
            "format": {
                "type": "json_schema",
                "name": "cyberwatch_qualification",
                "schema": _build_schema(requested),
                "strict": True,
            }
        },
        "max_output_tokens": state.max_output_tokens,
    }
    headers = {
        "Authorization": f"Bearer {state.api_key}",
        "Content-Type": "application/json",
    }
    attempt = 0
    while True:
        try:
            response = requests.post(OPENAI_URL, json=body, headers=headers, timeout=OPENAI_TIMEOUT_SECONDS)
        except requests.RequestException as exc:
            attempt += 1
            if attempt > OPENAI_MAX_RETRIES:
                raise AiCallError(f"réseau: {type(exc).__name__}") from exc
            time.sleep(2 ** attempt)
            continue

        if response.status_code == 200:
            return response.json()
        if response.status_code == 429 or 500 <= response.status_code < 600:
            attempt += 1
            if attempt > OPENAI_MAX_RETRIES:
                raise AiCallError(f"HTTP {response.status_code} après retries")
            time.sleep(2 ** attempt)
            continue
        raise AiCallError(f"HTTP {response.status_code}: {response.text[:200]}")


def _validate(raw: dict, requested: list[str], context: str) -> dict | None:
    """Valide strictement la réponse (§6). Tout échec => réponse rejetée."""
    decision: dict = {}
    context_lower = context.lower()
    for field_name in requested:
        json_key, taxonomy, unknown, _ = FIELD_SPECS[field_name]
        entry = raw.get(json_key)
        if not isinstance(entry, dict):
            return None
        value = entry.get("value")
        confidence = entry.get("confidence")
        evidence = entry.get("evidence")
        if not isinstance(value, str) or value not in taxonomy:
            return None
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
            return None
        confidence = float(confidence)
        if not 0.0 <= confidence <= 1.0:
            return None
        if not isinstance(evidence, str) or len(evidence) > EVIDENCE_MAX_CHARS:
            return None
        if field_name == "Location" and value != unknown:
            trimmed = evidence.strip()
            if not trimmed or trimmed.lower() not in context_lower:
                return None
        decision[field_name] = value
        decision[f"{field_name}_Confidence"] = confidence
        decision[f"{field_name}_Evidence"] = evidence
    return decision


def _apply_decision(item: Item, requested: list[str], decision: dict, state: AiRunState) -> None:
    for field_name in requested:
        _, _, unknown, threshold = FIELD_SPECS[field_name]
        value = decision.get(field_name)
        confidence = decision.get(f"{field_name}_Confidence", 0.0)
        if value is None or value == unknown:
            continue
        if confidence < threshold:
            continue
        if getattr(item, field_name) != unknown:
            continue  # Valeur déjà connue entre-temps : jamais écrasée.
        setattr(item, field_name, value)
        state.qualified[field_name] = state.qualified.get(field_name, 0) + 1


def qualify_item(item: Item, entry: RawEntry, spec: SourceSpec, state: AiRunState) -> None:
    """Complète Threat/Sector/Location de `item` s'ils sont encore Inconnu.

    Ne fait jamais rien si `state.enabled` est faux (clé absente), si la
    source est explicitement exclue (`skip_ai_qualification`), ou si aucun
    des trois champs n'est encore Inconnu (zéro appel dans ce cas).
    """
    if not state.enabled or spec.params.get("skip_ai_qualification"):
        return

    requested = [
        name for name in ("Threat", "Sector", "Location")
        if getattr(item, name) == FIELD_SPECS[name][2]
    ]
    if not requested:
        return

    state.candidates += 1
    for name in requested:
        state.unknown_before[name] = state.unknown_before.get(name, 0) + 1

    input_hash = _input_hash(item, entry, requested, state.model, state.max_context_chars)
    cache_key = (item.Item_ID, input_hash)

    cached = state.cache.get(cache_key)
    if cached is not None:
        state.cache_hits += 1
        _apply_decision(item, requested, _decision_from_row(cached), state)
        return

    if state.calls_attempted >= state.max_calls or state.estimated_cost_usd >= state.max_cost:
        state.budget_stopped = True
        state.calls_budget_blocked += 1
        return

    state.calls_attempted += 1
    context = _context(entry, state.max_context_chars)
    try:
        payload = _call_openai(item, entry, spec, requested, state)
        raw = _extract_output_json(payload)
    except AiCallError as exc:
        state.calls_failed += 1
        print(f"Qualification IA : appel échoué pour {item.Item_ID} ({exc}).")
        return

    usage = _extract_usage(payload)
    state.input_tokens += usage["input_tokens"]
    state.cached_input_tokens += usage["cached_input_tokens"]
    state.output_tokens += usage["output_tokens"]
    state.reasoning_tokens += usage["reasoning_tokens"]
    state.total_tokens += usage["total_tokens"]
    cost = _estimate_cost(state.model, usage["input_tokens"], usage["output_tokens"])
    state.estimated_cost_usd += cost

    decision = _validate(raw, requested, context)
    if decision is None:
        state.calls_failed += 1
        print(f"Qualification IA : réponse invalide pour {item.Item_ID}, Inconnu conservé.")
        return

    state.calls_succeeded += 1
    row = _row_from_decision(item, input_hash, requested, decision, state.model, usage, cost)
    state.cache[cache_key] = row
    _apply_decision(item, requested, decision, state)


def _row_from_decision(item: Item, input_hash: str, requested: list[str], decision: dict,
                        model: str, usage: dict, cost: float) -> dict:
    row = {
        "Item_ID": item.Item_ID,
        "Source_ID": item.Source_ID,
        "Input_Hash": input_hash,
        "Model": model,
        "Prompt_Version": PROMPT_VERSION,
        "Threat": "", "Threat_Confidence": "", "Threat_Evidence": "",
        "Sector": "", "Sector_Confidence": "", "Sector_Evidence": "",
        "Location": "", "Location_Confidence": "", "Location_Evidence": "",
        "Input_Tokens": usage["input_tokens"],
        "Cached_Input_Tokens": usage["cached_input_tokens"],
        "Output_Tokens": usage["output_tokens"],
        "Total_Tokens": usage["total_tokens"],
        "Estimated_Cost_USD": round(cost, 6),
    }
    for name in requested:
        row[name] = decision.get(name, "")
        row[f"{name}_Confidence"] = decision.get(f"{name}_Confidence", "")
        row[f"{name}_Evidence"] = decision.get(f"{name}_Evidence", "")
    return row


def _decision_from_row(row: dict) -> dict:
    decision = {}
    for name in ("Threat", "Sector", "Location"):
        if row.get(name):
            decision[name] = row[name]
            try:
                decision[f"{name}_Confidence"] = float(row.get(f"{name}_Confidence") or 0)
            except (TypeError, ValueError):
                decision[f"{name}_Confidence"] = 0.0
            decision[f"{name}_Evidence"] = row.get(f"{name}_Evidence", "")
    return decision


def finish_run(state: AiRunState, run_id: str, as_of: str, mode: str) -> dict:
    """Persiste le cache mis à jour et construit la ligne `ai_usage.csv`."""
    if state.enabled:
        rows = sorted(state.cache.values(), key=lambda r: (r.get("Item_ID", ""), r.get("Input_Hash", "")))
        store.save_ai_qualifications(rows)

    if not state.enabled:
        run_status = "DISABLED"
    elif state.budget_stopped:
        run_status = "BUDGET_STOP"
    elif state.calls_attempted and state.calls_succeeded == 0:
        run_status = "API_ERROR"
    elif state.calls_failed:
        run_status = "DEGRADED"
    else:
        run_status = "OK"

    still_unknown = sum(state.unknown_before.values()) - sum(state.qualified.values())

    return {
        "Run_ID": run_id,
        "As_Of": as_of,
        "Mode": mode,
        "Model": state.model,
        "Prompt_Version": PROMPT_VERSION,
        "Candidates": state.candidates,
        "Cache_Hits": state.cache_hits,
        "Calls_Attempted": state.calls_attempted,
        "Calls_Succeeded": state.calls_succeeded,
        "Calls_Failed": state.calls_failed,
        "Calls_Budget_Blocked": state.calls_budget_blocked,
        "Threat_Unknown_Before": state.unknown_before.get("Threat", 0),
        "Threat_Qualified": state.qualified.get("Threat", 0),
        "Sector_Unknown_Before": state.unknown_before.get("Sector", 0),
        "Sector_Qualified": state.qualified.get("Sector", 0),
        "Location_Unknown_Before": state.unknown_before.get("Location", 0),
        "Location_Qualified": state.qualified.get("Location", 0),
        "Still_Unknown": still_unknown,
        "Input_Tokens": state.input_tokens,
        "Cached_Input_Tokens": state.cached_input_tokens,
        "Output_Tokens": state.output_tokens,
        "Reasoning_Tokens": state.reasoning_tokens,
        "Total_Tokens": state.total_tokens,
        "Estimated_Cost_USD": round(state.estimated_cost_usd, 6),
        "Duration_s": round(time.monotonic() - state.started, 1),
        "Status": run_status,
    }
