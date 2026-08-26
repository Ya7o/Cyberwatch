"""Filet de rattrapage LLM pour Threat/Sector/Location encore `Inconnu`.

Principe absolu : ce module n'intervient jamais avant les règles déterministes
et le référentiel. Il ne touche que les champs encore `Inconnu`, ne peut jamais
écraser une valeur connue et reste non bloquant en cas d'absence de clé, panne
réseau ou budget épuisé.

Pour `Sector`, le LLM est un classifieur de preuve métier : il n'est demandé que
lorsqu'une description d'activité explicite a été extraite de la source et son
evidence doit être ancrée dans cette description, jamais seulement dans le
récit cyber ou le nom de l'organisation.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from dataclasses import asdict, dataclass, field

import requests

from . import config, llm_runtime, org_enrichment, store
from .collectors.base import RawEntry, SourceSpec
from .identity import SEP
from .model import Item
from .normalize import extract_activity_description, organisation_key, searchable

DEFAULT_MODEL = "gpt-5-nano"
PRICING = {DEFAULT_MODEL: {"input": 0.05, "output": 0.40}}

#: Origine de provenance pour la mutation directe de Sector à l'ingestion
#: via le registre entreprise (audit 2026-08-26, cf. AiRunState.provenance).
ORIGIN_ORG_ENRICHMENT_DETERMINISTIC_ITEM = "ORG_ENRICHMENT_DETERMINISTIC_ITEM"

PROMPT_VERSION = "2026-08-16.1"
SCHEMA_VERSION = "2"

OPENAI_URL = "https://api.openai.com/v1/responses"
OPENAI_TIMEOUT_SECONDS = 20
OPENAI_MAX_RETRIES = 2
EVIDENCE_MAX_CHARS = 200

THRESHOLD_THREAT = 0.6
THRESHOLD_SECTOR = 0.6
THRESHOLD_LOCATION = 0.75

FIELD_SPECS = {
    "Threat": ("threat", config.THREATS, config.THREAT_UNKNOWN, THRESHOLD_THREAT),
    "Sector": ("sector", config.SECTORS, config.SECTOR_UNKNOWN, THRESHOLD_SECTOR),
    "Location": ("location", config.LOCATIONS, config.LOC_INCONNU, THRESHOLD_LOCATION),
}

SYSTEM_PROMPT = (
    "Tu es un classificateur strict pour un observatoire d'incidents cyber. "
    "Réponds uniquement à partir du texte fourni, jamais de connaissance "
    "générale supposée sur l'organisation citée. Si le contexte ne permet pas "
    "de trancher avec confiance, réponds Inconnu plutôt que de deviner. "
    "Pour la localisation, n'indique un territoire que s'il est explicitement "
    "soutenu par le texte fourni. Pour le secteur, n'indique une valeur que si "
    "la section Activity_Description décrit explicitement l'activité de "
    "l'organisation ; le nom de l'organisation et le récit cyber ne sont "
    "jamais des preuves métier."
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
    pass


@dataclass
class AiRunState:
    enabled: bool
    api_key: str = ""
    model: str = DEFAULT_MODEL
    max_calls: int = 2000
    max_cost: float = 1.00
    max_context_chars: int = 4000
    max_output_tokens: int = 600
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
    llm_duration_seconds: float = 0.0
    org_enrichment: "org_enrichment.OrgEnrichmentState" = field(
        default_factory=org_enrichment.OrgEnrichmentState
    )
    sector_resolved_source_llm: int = 0
    sector_evidence_rejected: int = 0
    sector_resolved_enrichment_cache: int = 0
    sector_resolved_enriched_deterministic: int = 0
    sector_resolved_enriched_llm: int = 0
    sector_llm_skipped: int = 0
    started: float = field(default_factory=time.monotonic)
    #: Lignes de provenance pour les mutations Sector/Location faites ici,
    #: à l'ingestion (audit 2026-08-26) : cette escalade mutait Item.Sector
    #: sans jamais laisser de trace dans qualification_provenance.csv,
    #: obligeant à croiser org_enrichment_cache.csv pour comprendre une
    #: décision. Fusionnées par runner.py dans report.qualification_provenance.
    provenance: list[dict] = field(default_factory=list)


def start_run() -> AiRunState:
    api_key = os.getenv("OPENAI_API_KEY", "")
    state = AiRunState(
        enabled=bool(api_key),
        api_key=api_key,
        model=os.getenv("OPENAI_MODEL", DEFAULT_MODEL),
        max_calls=_env_int("AI_MAX_CALLS_PER_RUN", 2000),
        max_cost=_env_float("AI_MAX_ESTIMATED_COST_USD_PER_RUN", 1.00),
        max_context_chars=_env_int("AI_MAX_CONTEXT_CHARS", 4000),
        max_output_tokens=_env_int("AI_MAX_OUTPUT_TOKENS", 600),
        org_enrichment=org_enrichment.start_state(),
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
        print(
            f"Qualification IA : tarif inconnu pour le modèle '{model}', "
            f"estimation basée sur {DEFAULT_MODEL}."
        )
        rates = PRICING[DEFAULT_MODEL]
    return rates


def _estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    return llm_runtime.estimate_cost(model, input_tokens, output_tokens)



def _context(entry: RawEntry, max_chars: int) -> str:
    parts = [entry.title, entry.summary, entry.content]
    return " ".join(part for part in parts if part).strip()[:max_chars]


_EXPLICIT_ACTIVITY_FALLBACKS = (
    re.compile(
        r"\b(?:est|sont)\s+(?:un|une|des|le|la|les)?\s*"
        r"(?:hébergeur|hebergeur|opérateur|operateur|gestionnaire|fournisseur|prestataire|cabinet)\b"
        r"[^.!?]{0,180}",
        re.I,
    ),
    re.compile(
        r"\b(?:gère|gere|exploite|fournit|propose|produit)\s+"
        r"(?:un|une|des|du|de la|les)?\s*[^.!?]{5,180}",
        re.I,
    ),
)


def _sector_activity_context(entry: RawEntry, max_chars: int) -> str:
    """Seule preuve source recevable pour Sector."""
    context = _context(entry, max_chars)
    activity = extract_activity_description(context)
    if activity:
        return activity
    for pattern in _EXPLICIT_ACTIVITY_FALLBACKS:
        match = pattern.search(context)
        if match:
            return match.group(0).strip()
    return ""


def _sector_llm_worth_calling(
    entry: RawEntry, spec: SourceSpec, organisation_key_: str, max_chars: int
) -> bool:
    del spec, organisation_key_
    return bool(_sector_activity_context(entry, max_chars))


def _sector_skip_is_structural(
    item: Item, entry: RawEntry, spec: SourceSpec, max_chars: int
) -> bool:
    """Compte séparément les skips structurels historiques."""
    if spec.source_id == "BONJOURLAFUITE":
        return True
    context = _context(entry, max_chars)
    return bool(item.Organisation_Key) and organisation_key(context) == item.Organisation_Key


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
    del spec
    activity = _sector_activity_context(entry, max_chars)
    lines = [
        "=== A. Métadonnées ===",
        f"Source_ID: {item.Source_ID}",
        f"Organisation_Raw: {item.Organisation_Raw}",
        f"Published_Date: {item.Published_Date}",
        f"Event_Date: {item.Event_Date or '(absente)'}",
        f"Threat_Raw: {item.Threat_Raw or '(absent)'}",
        f"Threat actuel: {item.Threat}",
        f"Sector actuel: {item.Sector}",
        f"Location actuelle: {item.Location}",
        "",
        "=== B. Contexte incident (Threat/Location uniquement) ===",
        f"Titre: {entry.title}",
        f"Contexte: {_context(entry, max_chars)}",
        "",
        "=== B2. Activity_Description (SEULE preuve admissible pour Sector) ===",
        activity or "(absente)",
        "",
        "=== C. Champs à qualifier ===",
        ", ".join(requested),
    ]
    if "Sector" in requested:
        lines.append(
            "Pour Sector, l'evidence doit être une sous-chaîne de B2. Si B2 est "
            "absente ou insuffisante, réponds Inconnu."
        )
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
        status = payload.get("status")
        reason = (payload.get("incomplete_details") or {}).get("reason")
        detail = f"status={status}" + (f", incomplete_reason={reason}" if reason else "")
        raise AiCallError(f"réponse sans texte structuré ({detail})")
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


def _post_openai(body: dict, state: AiRunState) -> dict:
    started = time.monotonic()
    try:
        try:
            result = llm_runtime.runtime().post_response(
                task="qualification",
                body=body,
                api_key=state.api_key,
            )
            return result.payload
        except llm_runtime.LlmError as exc:
            raise AiCallError(str(exc)) from exc
    finally:
        state.llm_duration_seconds += time.monotonic() - started


def _call_openai(item: Item, entry: RawEntry, spec: SourceSpec, requested: list[str], state: AiRunState) -> dict:
    body = {
        "model": state.model,
        "input": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": _user_content(
                    item, entry, spec, requested, state.max_context_chars
                ),
            },
        ],
        "text": {
            "format": {
                "type": "json_schema",
                "name": "cyberwatch_qualification",
                "schema": _build_schema(requested),
                "strict": True,
            }
        },
        "reasoning": {"effort": "minimal"},
        "max_output_tokens": state.max_output_tokens,
    }
    return _post_openai(body, state)


_SECTOR_INCIDENT_VOCAB: set[str] | None = None


def _sector_incident_vocab() -> set[str]:
    global _SECTOR_INCIDENT_VOCAB
    if _SECTOR_INCIDENT_VOCAB is None:
        markers = set(config.CYBER_PREFIXES) | set(config.CYBER_PHRASES) | set(config.RANSOMWARE_GROUPS)
        for _threat, patterns in config.THREAT_RULES:
            markers.update(patterns)
        _SECTOR_INCIDENT_VOCAB = markers
    return _SECTOR_INCIDENT_VOCAB


def _looks_like_bare_org_name(evidence: str, organisation_key_: str) -> bool:
    return bool(organisation_key_) and organisation_key(evidence) == organisation_key_


def _looks_like_incident_narrative(evidence_searchable: str) -> bool:
    return any(marker in evidence_searchable for marker in _sector_incident_vocab())


def _sector_evidence_reason(evidence: str, organisation_key_: str, context_lower: str) -> str | None:
    trimmed = (evidence or "").strip()
    if not trimmed:
        return "empty"
    if trimmed.lower() not in context_lower:
        return "not_grounded"
    if _looks_like_bare_org_name(trimmed, organisation_key_):
        return "org_name_only"
    if _looks_like_incident_narrative(searchable(trimmed)):
        return "incident_vocabulary"
    return None


def _validate(
    raw: dict,
    requested: list[str],
    context: str,
    organisation_key_: str,
    sector_context: str = "",
) -> tuple[dict, dict[str, str]]:
    decision: dict = {}
    rejected: dict[str, str] = {}
    context_lower = context.lower()
    sector_context_lower = (sector_context or context).lower()
    for field_name in requested:
        json_key, taxonomy, unknown, _ = FIELD_SPECS[field_name]
        response_field = raw.get(json_key)
        if not isinstance(response_field, dict):
            rejected[field_name] = "malformed"
            continue
        value = response_field.get("value")
        confidence = response_field.get("confidence")
        evidence = response_field.get("evidence")
        if not isinstance(value, str) or value not in taxonomy:
            rejected[field_name] = "bad_enum"
            continue
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
            rejected[field_name] = "bad_confidence"
            continue
        confidence = float(confidence)
        if not 0.0 <= confidence <= 1.0:
            rejected[field_name] = "bad_confidence"
            continue
        if not isinstance(evidence, str) or len(evidence) > EVIDENCE_MAX_CHARS:
            rejected[field_name] = "bad_evidence"
            continue
        if field_name == "Location" and value != unknown:
            trimmed = evidence.strip()
            if not trimmed or trimmed.lower() not in context_lower:
                rejected[field_name] = "not_grounded"
                continue
        if field_name == "Sector" and value != unknown:
            reason = _sector_evidence_reason(
                evidence,
                organisation_key_,
                sector_context_lower,
            )
            if reason:
                rejected[field_name] = reason
                continue
        decision[field_name] = value
        decision[f"{field_name}_Confidence"] = confidence
        decision[f"{field_name}_Evidence"] = evidence
    return decision, rejected


def _apply_decision(item: Item, requested: list[str], decision: dict, state: AiRunState) -> None:
    for field_name in requested:
        _, _, unknown, threshold = FIELD_SPECS[field_name]
        value = decision.get(field_name)
        confidence = decision.get(f"{field_name}_Confidence", 0.0)
        if value is None or value == unknown or confidence < threshold:
            continue
        if getattr(item, field_name) != unknown:
            continue
        setattr(item, field_name, value)
        state.qualified[field_name] = state.qualified.get(field_name, 0) + 1


def qualify_item(item: Item, entry: RawEntry, spec: SourceSpec, state: AiRunState) -> None:
    if spec.params.get("skip_ai_qualification"):
        return

    initially_unknown = [
        name for name in ("Threat", "Sector", "Location")
        if getattr(item, name) == FIELD_SPECS[name][2]
    ]
    if not initially_unknown:
        return
    for name in initially_unknown:
        state.unknown_before[name] = state.unknown_before.get(name, 0) + 1

    if item.Sector == config.SECTOR_UNKNOWN or item.Location == config.LOC_INCONNU:
        _escalate_org_enrichment_deterministic(item, entry, spec, state)

    if (
        item.Location == config.LOC_INCONNU
        and spec.location_rule in config.LOCATIONS
        and spec.location_rule != config.LOC_INCONNU
    ):
        item.Location = spec.location_rule
        state.qualified["Location"] = state.qualified.get("Location", 0) + 1

    requested = [
        name for name in ("Threat", "Sector", "Location")
        if getattr(item, name) == FIELD_SPECS[name][2]
    ]
    if not requested:
        return

    state.candidates += 1
    sector_requested = "Sector" in requested
    sector_activity = (
        _sector_activity_context(entry, state.max_context_chars)
        if sector_requested
        else ""
    )
    # Cause racine 5 (audit 2026-08-25, cas réel YouFid) : ce filet par item
    # ne doit plus jamais trancher Sector lui-même à partir du seul texte de
    # CET article. organisation_sector.py (§qualify) recollecte déjà ce même
    # signal (Activity_Description) via un classificateur plus strict et
    # l'arbitre face aux autres sources/items de la même organisation avant
    # d'appliquer quoi que ce soit ; un appel isolé ici pouvait produire un
    # verdict différent de cette arbitration et l'emporter simplement parce
    # qu'il s'exécutait plus tôt (Item.Sector non-Inconnu avant l'arbitrage).
    # Sector reste décidé plus loin dans ce même module uniquement via les
    # escalades ancrées sur un enrichissement officiel validé
    # (_escalate_org_enrichment_deterministic / _escalate_sector_llm), jamais
    # par ce texte brut à l'aveugle.
    call_requested = [name for name in requested if name != "Sector"]
    if sector_requested and not sector_activity:
        state.sector_evidence_rejected += 1
        if _sector_skip_is_structural(item, entry, spec, state.max_context_chars):
            state.sector_llm_skipped += 1

    if call_requested and state.enabled:
        input_hash = _input_hash(
            item,
            entry,
            call_requested,
            state.model,
            state.max_context_chars,
        )
        cache_key = (item.Item_ID, input_hash)
        cached = state.cache.get(cache_key)
        if cached is not None:
            state.cache_hits += 1
            _apply_and_count_sector(
                item,
                call_requested,
                _decision_from_row(cached),
                state,
            )
        elif state.calls_attempted >= state.max_calls or state.estimated_cost_usd >= state.max_cost:
            state.budget_stopped = True
            state.calls_budget_blocked += 1
        else:
            state.calls_attempted += 1
            context = _context(entry, state.max_context_chars)
            raw = None
            payload = None
            try:
                payload = _call_openai(
                    item,
                    entry,
                    spec,
                    call_requested,
                    state,
                )
                raw = _extract_output_json(payload)
            except AiCallError as exc:
                state.calls_failed += 1
                print(f"Qualification IA : appel échoué pour {item.Item_ID} ({exc}).")

            if raw is not None:
                usage = _extract_usage(payload)
                state.input_tokens += usage["input_tokens"]
                state.cached_input_tokens += usage["cached_input_tokens"]
                state.output_tokens += usage["output_tokens"]
                state.reasoning_tokens += usage["reasoning_tokens"]
                state.total_tokens += usage["total_tokens"]
                cost = _estimate_cost(
                    state.model,
                    usage["input_tokens"],
                    usage["output_tokens"],
                )
                state.estimated_cost_usd += cost

                decision, rejected = _validate(
                    raw,
                    call_requested,
                    context,
                    item.Organisation_Key,
                    sector_context=sector_activity,
                )
                if rejected.get("Sector") in (
                    "not_grounded",
                    "org_name_only",
                    "incident_vocabulary",
                    "empty",
                ):
                    state.sector_evidence_rejected += 1
                if not decision:
                    state.calls_failed += 1
                    print(f"Qualification IA : réponse invalide pour {item.Item_ID}, Inconnu conservé.")
                else:
                    state.calls_succeeded += 1
                    row = _row_from_decision(
                        item,
                        input_hash,
                        call_requested,
                        decision,
                        state.model,
                        usage,
                        cost,
                    )
                    state.cache[cache_key] = row
                    _apply_and_count_sector(
                        item,
                        call_requested,
                        decision,
                        state,
                    )

    # Refonte 2026-08-26 : _escalate_sector_llm retiré, Sector n'est plus
    # jamais décidé par une escalade LLM précoce ici — voir
    # organisation_sector_llm.py, devenu l'étape finale obligatoire dans
    # qualification.qualify(), qui voit l'ensemble des preuves plutôt qu'un
    # seul item isolé.


def _apply_and_count_sector(
    item: Item,
    requested: list[str],
    decision: dict,
    state: AiRunState,
) -> None:
    was_unknown = "Sector" in requested and item.Sector == config.SECTOR_UNKNOWN
    _apply_decision(item, requested, decision, state)
    if was_unknown and item.Sector != config.SECTOR_UNKNOWN:
        state.sector_resolved_source_llm += 1


def _org_enrichment_provenance_row(item: Item, sector: str, record) -> dict:
    """Trace la mutation Sector faite par ``_escalate_org_enrichment_deterministic``.

    Auparavant silencieuse (audit 2026-08-26) : reconstituer une décision
    exigeait de croiser org_enrichment_cache.csv en plus de ce fichier.
    """
    return {
        "Item_ID": item.Item_ID,
        "Source_ID": item.Source_ID,
        "Field": "Sector",
        "Previous_Value": config.SECTOR_UNKNOWN,
        "Candidate_Value": sector,
        "Final_Value": sector,
        "Origin": ORIGIN_ORG_ENRICHMENT_DETERMINISTIC_ITEM,
        "Confidence": "HIGH",
        "Evidence": f"registre entreprise: Activity_Code={record.Activity_Code}; Activity_Label={record.Activity_Label}"[:2000],
        "Match_Strategy": "organisation_key_exact+recherche_entreprises_api_gouv",
        "Decision": "APPLIED",
    }


def _escalate_org_enrichment_deterministic(
    item: Item,
    entry: RawEntry,
    spec: SourceSpec,
    state: AiRunState,
) -> None:
    del entry, spec
    if item.Sector != config.SECTOR_UNKNOWN and item.Location != config.LOC_INCONNU:
        return
    org_state = state.org_enrichment
    if not org_state.enabled:
        return

    record = org_enrichment.resolve(
        item.Organisation_Key,
        item.Organisation_Raw,
        item.Collected_As_Of,
        org_state,
    )
    if record is None or record.Match_Status != org_enrichment.MATCHED:
        return

    if item.Location == config.LOC_INCONNU:
        location = org_enrichment.location_for_headquarters_department(
            record.Headquarters_Department
        )
        if location != config.LOC_INCONNU:
            item.Location = location
            state.qualified["Location"] = state.qualified.get("Location", 0) + 1

    if item.Sector != config.SECTOR_UNKNOWN or not record.Activity_Label:
        return

    # Refonte 2026-08-26 ("preuves partout, décision unique à la fin") : seul
    # un vrai code NAF (Validated_Via == "deterministic") court-circuite ici.
    # Cas réel qui a motivé ce garde-fou : Klark AI, dont le cache portait
    # Validated_Sector="Services aux entreprises"/Validated_Via="official_site"
    # (texte du site officiel scrappé, classé par un regex — jamais un code
    # NAF) et qui était pourtant appliqué directement ici sans distinction,
    # avant que la moindre autre preuve (ex. "intelligence artificielle")
    # n'ait sa chance. Un secteur non-NAF déjà en cache reste lu comme preuve
    # par organisation_sector.py (canal EVIDENCE_OFFICIAL_SITE), jamais
    # appliqué ici.
    if record.Validated_Sector and record.Validated_Via == "deterministic":
        state.provenance.append(_org_enrichment_provenance_row(item, record.Validated_Sector, record))
        item.Sector = record.Validated_Sector
        state.sector_resolved_enrichment_cache += 1
        state.qualified["Sector"] = state.qualified.get("Sector", 0) + 1
        return

    # Un Validated_Via déjà renseigné (ex. "official_site"/"official_site_text")
    # signifie que ce record vient du repli site officiel, jamais du candidat
    # registre lui-même : sector_for_activity_label ne mappe que des libellés
    # de section NAF, jamais du texte de site scrappé.
    if record.Validated_Via:
        return

    sector = org_enrichment.sector_for_activity_label(record.Activity_Label)
    if sector == config.SECTOR_UNKNOWN:
        return

    state.provenance.append(_org_enrichment_provenance_row(item, sector, record))
    item.Sector = sector
    record.Validated_Sector = sector
    record.Validated_Via = "deterministic"
    record.Cache_Version = org_enrichment.ORG_ENRICHMENT_CACHE_VERSION
    org_state.cache[item.Organisation_Key] = asdict(record)
    state.sector_resolved_enriched_deterministic += 1
    state.qualified["Sector"] = state.qualified.get("Sector", 0) + 1


def _row_from_decision(
    item: Item,
    input_hash: str,
    requested: list[str],
    decision: dict,
    model: str,
    usage: dict,
    cost: float,
) -> dict:
    row = {
        "Item_ID": item.Item_ID,
        "Source_ID": item.Source_ID,
        "Input_Hash": input_hash,
        "Model": model,
        "Prompt_Version": PROMPT_VERSION,
        "Threat": "",
        "Threat_Confidence": "",
        "Threat_Evidence": "",
        "Sector": "",
        "Sector_Confidence": "",
        "Sector_Evidence": "",
        "Location": "",
        "Location_Confidence": "",
        "Location_Evidence": "",
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


def finish_run(
    state: AiRunState,
    run_id: str,
    as_of: str,
    mode: str,
    sector_pre_stats: dict | None = None,
) -> dict:
    if state.enabled:
        rows = sorted(
            state.cache.values(),
            key=lambda r: (r.get("Item_ID", ""), r.get("Input_Hash", "")),
        )
        store.save_ai_qualifications(rows)

    if state.org_enrichment.enabled:
        org_rows = sorted(
            state.org_enrichment.cache.values(),
            key=lambda r: r.get("Organisation_Key", ""),
        )
        store.save_org_enrichment_cache(org_rows)

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
    pre = sector_pre_stats or {}
    sector_resolved_native = pre.get("resolved_native", 0)
    sector_initial_unknown = pre.get("initial_unknown", 0)
    sector_resolved_reference = pre.get("resolved_reference", 0)
    sector_resolved_deterministic = pre.get("resolved_deterministic", 0)
    org_state = state.org_enrichment
    org_calls_total = (
        org_state.calls_matched
        + org_state.calls_ambiguous
        + org_state.calls_not_found
        + org_state.calls_error
    )
    org_lookups = org_calls_total + org_state.cache_hits
    org_cache_hit_rate = round(org_state.cache_hits / org_lookups, 4) if org_lookups else 0.0
    sector_remaining_unknown = (
        sector_initial_unknown
        - sector_resolved_reference
        - sector_resolved_deterministic
        - state.sector_resolved_source_llm
        - state.sector_resolved_enrichment_cache
        - state.sector_resolved_enriched_deterministic
        - state.sector_resolved_enriched_llm
    )

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
        "Sector_Initial_Unknown": sector_initial_unknown,
        "Sector_Resolved_Reference": sector_resolved_reference,
        "Sector_Resolved_Deterministic": sector_resolved_deterministic,
        "Sector_Resolved_Source_LLM": state.sector_resolved_source_llm,
        "Sector_Evidence_Rejected": state.sector_evidence_rejected,
        "Sector_Enrichment_Cache_Hit": state.sector_resolved_enrichment_cache,
        "Sector_Enrichment_Http_Attempted": org_state.calls_attempted,
        "Sector_Enrichment_Http_Matched": org_state.calls_matched,
        "Sector_Enrichment_Http_Ambiguous": org_state.calls_ambiguous,
        "Sector_Enrichment_Http_Not_Found": org_state.calls_not_found,
        "Sector_Enrichment_Http_Error": org_state.calls_error,
        "Sector_Resolved_Enriched_Deterministic": state.sector_resolved_enriched_deterministic,
        "Sector_Resolved_Enriched_LLM": state.sector_resolved_enriched_llm,
        "Sector_Remaining_Unknown": sector_remaining_unknown,
        "Sector_Resolved_Native": sector_resolved_native,
        "Sector_LLM_Skipped_No_Evidence": state.sector_llm_skipped,
        "Org_Enrichment_Calls": org_state.calls_attempted,
        "Org_Enrichment_Duration_s": round(org_state.duration_seconds, 3),
        "Org_Enrichment_Cache_Hit_Rate": org_cache_hit_rate,
    }
