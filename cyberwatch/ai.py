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
from dataclasses import asdict, dataclass, field

import requests

from . import config, org_enrichment, store
from .collectors.base import RawEntry, SourceSpec
from .identity import SEP
from .model import Item
from .normalize import organisation_key, searchable

# --------------------------------------------------------------------------
# Modèle et tarification
#
# Le snapshot daté "gpt-5-nano-2026-03-17" (issu d'une recherche web, faute
# d'accès à la doc officielle depuis ce bac à sable) a été rejeté par l'API
# réelle le 2026-08-15 : HTTP 400 model_not_found, confirmé sur un run
# GitHub Actions réel (secrets.Cyberwatchapi). On retombe donc sur l'alias
# flottant "gpt-5-nano" : moins figé qu'un snapshot vérifié, mais un alias
# qui résout vers un modèle réellement existant vaut mieux qu'un snapshot
# deviné et refusé par l'API. À épingler sur un snapshot exact dès qu'il est
# possible de le vérifier sur la documentation officielle. `OPENAI_MODEL`
# reste overridable sans toucher au code.
# --------------------------------------------------------------------------

DEFAULT_MODEL = "gpt-5-nano"

#: Dollars US par million de tokens. Tarif de "gpt-5-nano" trouvé par
#: recherche web (non vérifié sur la doc officielle, cf. ci-dessus) :
#: $0.05 / $0.40 par 1M tokens (input/output). `cached_input` n'est
#: volontairement pas utilisé dans le calcul de coût (voir `_estimate_cost`) :
#: à défaut d'un tarif remisé vérifié, tous les tokens d'entrée sont comptés
#: au tarif plein, ce qui majore l'estimation au lieu de la sous-évaluer.
PRICING = {
    DEFAULT_MODEL: {"input": 0.05, "output": 0.40},
}

PROMPT_VERSION = "2026-08-15.2"
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
    "un territoire du seul nom ou secteur d'activité d'une organisation. "
    "Pour le secteur, n'indique une valeur que si le contexte décrit "
    "explicitement l'activité de l'organisation (ce qu'elle fait, vend, gère "
    "ou exploite) : ne déduis jamais un secteur du seul nom de l'organisation, "
    "ni du vocabulaire de l'incident (rançongiciel, fuite de données, groupe "
    "cybercriminel, etc.)."
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

    #: Pipeline Secteur (§12 METHODOLOGY.md) — enrichissement et métriques
    #: dédiées, distinctes des compteurs génériques ci-dessus.
    org_enrichment: "org_enrichment.OrgEnrichmentState" = field(
        default_factory=org_enrichment.OrgEnrichmentState
    )
    sector_resolved_source_llm: int = 0
    sector_evidence_rejected: int = 0
    sector_resolved_enrichment_cache: int = 0
    sector_resolved_enriched_deterministic: int = 0
    #: Toujours 0 : l'enrichissement gratuit ne fournit qu'un des 21 titres
    #: de section NAF, déjà classés de façon exhaustive et déterministe
    #: (org_enrichment.NAF_SECTIONS) — aucun second appel LLM n'est déclenché
    #: (§12 METHODOLOGY.md). Colonne conservée pour la forme de la métrique
    #: `Sector_Resolved_Enriched_LLM` (data/ai_usage.csv).
    sector_resolved_enriched_llm: int = 0

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
    """Structuré en 3 sections (§12 METHODOLOGY.md) pour que le modèle ne
    confonde jamais métadonnées/récit d'incident avec une preuve d'activité
    métier : seule la section B peut justifier une valeur de Secteur."""
    lines = [
        "=== A. Métadonnées (jamais une preuve d'activité métier) ===",
        f"Source_ID: {item.Source_ID}",
        f"Organisation_Raw: {item.Organisation_Raw}",
        f"Published_Date: {item.Published_Date}",
        f"Event_Date: {item.Event_Date or '(absente)'}",
        f"Threat_Raw: {item.Threat_Raw or '(absent)'}",
        f"Threat actuel: {item.Threat}",
        f"Sector actuel: {item.Sector}",
        f"Location actuelle: {item.Location}",
        "",
        "=== B. Contexte brut (seule source de preuve admissible) ===",
        f"Titre: {entry.title}",
        f"Contexte: {_context(entry, max_chars)}",
        "",
        "=== C. Champs à qualifier ===",
        "Uniquement ceux-ci, les autres sont déjà connus et ne doivent pas "
        "être reconsidérés : " + ", ".join(requested),
    ]
    if "Sector" in requested:
        lines.append(
            "Pour Secteur : la valeur ne peut être choisie que si la section B "
            "décrit explicitement l'activité de l'organisation. Si la section B "
            "ne contient aucune description d'activité, réponds Inconnu pour Secteur."
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
        # Diagnostic explicite : un modèle de raisonnement (famille gpt-5) peut
        # consommer tout `max_output_tokens` en jetons de raisonnement internes
        # avant de produire le message final, auquel cas l'API répond 200 avec
        # `status: "incomplete"` et aucun item "message" — jamais une erreur
        # HTTP. `reasoning.effort: "minimal"` (cf. `_call_openai`) et une marge
        # de tokens suffisante limitent ce cas ; s'il se reproduit malgré tout,
        # le statut/la raison sont journalisés ici pour éviter une nouvelle
        # supposition à l'aveugle.
        status = payload.get("status")
        reason = (payload.get("incomplete_details") or {}).get("reason")
        detail = f"status={status}"
        if reason:
            detail += f", incomplete_reason={reason}"
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
    """POST unique et indépendant, retry borné sur 429/5xx/timeout (§9)."""
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


def _call_openai(item: Item, entry: RawEntry, spec: SourceSpec, requested: list[str], state: AiRunState) -> dict:
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
        # "minimal" : la tâche est une classification fermée sur un contexte
        # court, pas un raisonnement à plusieurs étapes. Sans ceci, un modèle
        # de raisonnement (famille gpt-5) peut consommer tout
        # `max_output_tokens` en jetons de raisonnement internes et renvoyer
        # un HTTP 200 sans aucun message (cf. `_extract_output_json`).
        "reasoning": {"effort": "minimal"},
        "max_output_tokens": state.max_output_tokens,
    }
    return _post_openai(body, state)


_SECTOR_INCIDENT_VOCAB: set[str] | None = None


def _sector_incident_vocab() -> set[str]:
    """Vocabulaire d'incident (rançongiciel, fuite, groupe cybercriminel...),
    construit une fois à partir des tables déjà existantes et testées de
    `config.py` — aucune nouvelle liste de mots à maintenir ici."""
    global _SECTOR_INCIDENT_VOCAB
    if _SECTOR_INCIDENT_VOCAB is None:
        markers = set(config.CYBER_PREFIXES) | set(config.CYBER_PHRASES) | set(config.RANSOMWARE_GROUPS)
        for _threat, patterns in config.THREAT_RULES:
            markers.update(patterns)
        _SECTOR_INCIDENT_VOCAB = markers
    return _SECTOR_INCIDENT_VOCAB


def _looks_like_bare_org_name(evidence: str, organisation_key_: str) -> bool:
    """Vrai si l'evidence ne décrit rien de plus que le nom de l'organisation
    lui-même (§12 : « le simple nom de l'entreprise » n'est jamais une preuve)."""
    return bool(organisation_key_) and organisation_key(evidence) == organisation_key_


def _looks_like_incident_narrative(evidence_searchable: str) -> bool:
    """Vrai si l'evidence s'appuie sur le vocabulaire de la menace plutôt que
    sur l'activité de la victime. Générique (aucun cas par source) : couvre
    RANSOMWARE_LIVE (nom de groupe, "rançongiciel"...) sans code dédié."""
    return any(marker in evidence_searchable for marker in _sector_incident_vocab())


def _sector_evidence_reason(evidence: str, organisation_key_: str, context_lower: str) -> str | None:
    """`None` si l'evidence est recevable comme preuve d'activité métier,
    sinon le motif du rejet. Volontairement un simple test de sous-chaîne
    (même rigueur que Location) : sur une evidence courte (≤200 car.),
    sur-rejeter est le mode de défaillance sûr — Inconnu reste préférable à
    un secteur deviné."""
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
    raw: dict, requested: list[str], context: str, organisation_key_: str
) -> tuple[dict, dict[str, str]]:
    """Valide chaque champ demandé indépendamment (§6/§12).

    Un champ rejeté n'invalide plus les autres champs de la même réponse
    combinée : sinon un rejet de Secteur (preuve stricte, nouvelle) casserait
    Threat/Location déjà validés dans le même appel. Renvoie (décision
    partielle, motif de rejet par champ rejeté).
    """
    decision: dict = {}
    rejected: dict[str, str] = {}
    context_lower = context.lower()
    for field_name in requested:
        json_key, taxonomy, unknown, _ = FIELD_SPECS[field_name]
        entry = raw.get(json_key)
        if not isinstance(entry, dict):
            rejected[field_name] = "malformed"
            continue
        value = entry.get("value")
        confidence = entry.get("confidence")
        evidence = entry.get("evidence")
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
            reason = _sector_evidence_reason(evidence, organisation_key_, context_lower)
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

    Ne fait jamais rien si la source est explicitement exclue
    (`skip_ai_qualification`), ou si aucun des trois champs n'est encore
    Inconnu (zéro appel dans ce cas). Le premier appel LLM (contexte source)
    n'a lieu que si `state.enabled` (clé OpenAI présente) ; l'escalade
    Secteur (§12) peut ensuite intervenir même sans clé si l'enrichissement
    obtient un libellé d'activité mappable déterministiquement.
    """
    if spec.params.get("skip_ai_qualification"):
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

    if state.enabled:
        input_hash = _input_hash(item, entry, requested, state.model, state.max_context_chars)
        cache_key = (item.Item_ID, input_hash)

        cached = state.cache.get(cache_key)
        if cached is not None:
            state.cache_hits += 1
            _apply_and_count_sector(item, requested, _decision_from_row(cached), state)
        elif state.calls_attempted >= state.max_calls or state.estimated_cost_usd >= state.max_cost:
            state.budget_stopped = True
            state.calls_budget_blocked += 1
        else:
            state.calls_attempted += 1
            context = _context(entry, state.max_context_chars)
            raw = None
            payload = None
            try:
                payload = _call_openai(item, entry, spec, requested, state)
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
                cost = _estimate_cost(state.model, usage["input_tokens"], usage["output_tokens"])
                state.estimated_cost_usd += cost

                decision, rejected = _validate(raw, requested, context, item.Organisation_Key)
                if rejected.get("Sector") in ("not_grounded", "org_name_only", "incident_vocabulary", "empty"):
                    state.sector_evidence_rejected += 1
                if not decision:
                    state.calls_failed += 1
                    print(f"Qualification IA : réponse invalide pour {item.Item_ID}, Inconnu conservé.")
                else:
                    state.calls_succeeded += 1
                    row = _row_from_decision(item, input_hash, requested, decision, state.model, usage, cost)
                    state.cache[cache_key] = row
                    _apply_and_count_sector(item, requested, decision, state)

    if "Sector" in requested and item.Sector == config.SECTOR_UNKNOWN:
        _escalate_sector(item, entry, spec, state)


def _apply_and_count_sector(item: Item, requested: list[str], decision: dict, state: AiRunState) -> None:
    """`_apply_decision` (inchangé) puis comptabilise une résolution Secteur
    par contexte source — premier appel LLM, qu'il vienne d'un cache hit ou
    d'un appel frais."""
    was_unknown = "Sector" in requested and item.Sector == config.SECTOR_UNKNOWN
    _apply_decision(item, requested, decision, state)
    if was_unknown and item.Sector != config.SECTOR_UNKNOWN:
        state.sector_resolved_source_llm += 1


def _escalate_sector(item: Item, entry: RawEntry, spec: SourceSpec, state: AiRunState) -> None:
    """Enrichissement gratuit d'entreprise pour Secteur (§12 METHODOLOGY.md),
    déclenché uniquement si Secteur est toujours Inconnu après la tentative
    sur le contexte source. Ne lève jamais, ne devine jamais : toute étape
    infructueuse laisse Secteur à Inconnu.
    """
    if item.Sector != config.SECTOR_UNKNOWN:
        return
    org_state = state.org_enrichment
    if not org_state.enabled:
        return

    record = org_enrichment.resolve(
        item.Organisation_Key, item.Organisation_Raw, item.Collected_As_Of, org_state
    )
    if record is None or record.Match_Status != org_enrichment.MATCHED or not record.Activity_Label:
        # AMBIGUOUS/NOT_FOUND/ERROR/budget épuisé -> Inconnu reste Inconnu,
        # jamais de choix arbitraire.
        return

    if record.Validated_Sector:
        item.Sector = record.Validated_Sector
        state.sector_resolved_enrichment_cache += 1
        state.qualified["Sector"] = state.qualified.get("Sector", 0) + 1
        return
    if record.Validated_Via == "llm_declined":
        # Déjà tenté par le passé, jamais concluant : pas de nouvelle
        # tentative à chaque run.
        return

    # Mapping déterministe — table dédiée aux 21 sections NAF
    # (org_enrichment.NAF_SECTIONS), pas classify_sector() : ce dernier est
    # réglé sur du texte libre d'article et fait correspondre "distribution"
    # à Commerce, ce qui classerait à tort "Production et distribution
    # d'électricité..." en Commerce au lieu d'Énergie (constaté au premier
    # benchmark réel, cf. org_enrichment.py).
    #
    # Aucun appel LLM supplémentaire : le seul texte que l'API gratuite
    # fournit est l'un des 21 titres de section NAF, déjà classés de façon
    # exhaustive et délibérée par NAF_SECTIONS (y compris vers Inconnu quand
    # aucune correspondance n'est claire) — payer un appel pour reclassifier
    # une valeur déjà connue violerait le principe « jamais de LLM pour
    # confirmer une valeur fiable déterministe » (§11).
    sector = org_enrichment.sector_for_activity_label(record.Activity_Label)
    if sector == config.SECTOR_UNKNOWN:
        record.Validated_Via = "no_deterministic_match"
        org_state.cache[item.Organisation_Key] = asdict(record)
        return

    item.Sector = sector
    record.Validated_Sector = sector
    record.Validated_Via = "deterministic"
    org_state.cache[item.Organisation_Key] = asdict(record)
    state.sector_resolved_enriched_deterministic += 1
    state.qualified["Sector"] = state.qualified.get("Sector", 0) + 1


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


def finish_run(
    state: AiRunState, run_id: str, as_of: str, mode: str, sector_pre_stats: dict | None = None
) -> dict:
    """Persiste le cache mis à jour et construit la ligne `ai_usage.csv`.

    `sector_pre_stats` (§12 METHODOLOGY.md) porte les compteurs déterministes
    calculés en amont dans `runner.py` (avant tout appel IA) :
    `initial_unknown`/`resolved_reference`/`resolved_deterministic`. Optionnel
    pour rester rétro-compatible avec les appels existants à 4 arguments.
    """
    if state.enabled:
        rows = sorted(state.cache.values(), key=lambda r: (r.get("Item_ID", ""), r.get("Input_Hash", "")))
        store.save_ai_qualifications(rows)

    if state.org_enrichment.enabled:
        org_rows = sorted(
            state.org_enrichment.cache.values(), key=lambda r: r.get("Organisation_Key", "")
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
    sector_initial_unknown = pre.get("initial_unknown", 0)
    sector_resolved_reference = pre.get("resolved_reference", 0)
    sector_resolved_deterministic = pre.get("resolved_deterministic", 0)
    org_state = state.org_enrichment
    org_calls_total = (
        org_state.calls_matched + org_state.calls_ambiguous
        + org_state.calls_not_found + org_state.calls_error
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
        "Org_Enrichment_Calls": org_state.calls_attempted,
        "Org_Enrichment_Duration_s": round(org_state.duration_seconds, 3),
        "Org_Enrichment_Cache_Hit_Rate": org_cache_hit_rate,
    }
