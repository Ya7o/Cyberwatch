"""Candidat LLM organisationnel (P1) — jamais de recherche Internet.

Ce module ne remplace pas :mod:`cyberwatch.ai` (classifieur item-level à
partir d'``Activity_Description``). Il répond à une question différente :
quel est le meilleur secteur candidat pour une ORGANISATION, à partir des
informations déjà présentes dans Cyberwatch ? Aucune recherche web, aucun
outil, aucun accès réseau autre que l'appel structuré au modèle lui-même.

Le LLM ne produit jamais, seul, une preuve suffisante pour ``CONFIRMED`` : son
candidat reste ``TENTATIVE`` tant qu'aucune preuve indépendante ne converge
(cf. :mod:`cyberwatch.organisation_sector`, qui applique cette règle et relit
le cache écrit ici hors-ligne).

``replay`` reste strictement offline : ce module n'est appelé que par les
commandes explicites ``sector-llm`` / ``sector-backfill``, jamais par
``qualify()``. Une clé absente, un budget épuisé ou une panne réseau ne
bloquent jamais : les organisations concernées restent simplement ``UNKNOWN``.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlparse

from . import config, llm_runtime, organisation_sector as osec, store
from .model import Item

TASK = "organisation_sector"
PROMPT_VERSION = "2026-08-23.1"
DEFAULT_BATCH_SIZE = 40
MAX_OUTPUT_TOKENS = 4000
#: Bornes de compacité du contexte transmis (§13 du plan) : reproductible et
#: hashable, jamais le corpus complet des incidents.
MAX_ALIASES = 5
MAX_TITLES = 3
MAX_ACTIVITY_DESCRIPTIONS = 3
MAX_SOURCE_SECTOR_RAW = 3

CACHE_CSV = osec.LLM_CACHE_CSV
CACHE_COLUMNS = [
    "Organisation_Key", "Organisation", "Input_Hash", "Sector", "Confidence",
    "Basis", "Reason", "Model", "Prompt_Version", "Created_At",
]

BASIS_VALUES = (
    "explicit_activity", "structured_metadata", "naf_support", "name_semantics",
    "organisation_knowledge", "multiple_signals", "insufficient",
)

SYSTEM_PROMPT = (
    "Tu es un classificateur strict pour un observatoire d'incidents cyber.\n"
    "Tu n'as pas accès à Internet. Tu ne dois pas supposer avoir effectué une "
    "recherche web. Utilise uniquement les informations fournies.\n"
    "Le secteur correspond à l'activité principale de l'organisation victime.\n"
    "Ne déduis jamais le secteur depuis : le type de données volées ; les "
    "victimes de la fuite ; le type d'incident cyber.\n"
    "Exemples : présence de RIB != Finance ; données médicales != forcément "
    "Santé ; données de livraison != Transport.\n"
    "Si tu ne peux pas déterminer le secteur avec suffisamment de confiance, "
    "réponds Inconnu (basis=insufficient).\n"
    "'organisation_knowledge' signifie uniquement que tu utilises tes "
    "connaissances internes préexistantes sur cette organisation : cela ne "
    "signifie jamais une recherche web, une preuve officielle ou une preuve "
    "externe."
)

_SCHEMA_NAME = "cyberwatch_organisation_sector"


def _schema() -> dict:
    return {
        "type": "object",
        "properties": {
            "organisations": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "organisation_key": {"type": "string"},
                        "sector": {"type": "string", "enum": list(config.SECTORS)},
                        "confidence": {"type": "number"},
                        "basis": {"type": "string", "enum": list(BASIS_VALUES)},
                        "reason": {"type": "string"},
                    },
                    "required": ["organisation_key", "sector", "confidence", "basis", "reason"],
                    "additionalProperties": False,
                },
            },
        },
        "required": ["organisations"],
        "additionalProperties": False,
    }


# --------------------------------------------------------------------------
# Contexte organisationnel (§13 du plan)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class OrganisationContext:
    organisation_key: str
    organisation: str
    aliases: tuple[str, ...] = ()
    source_ids: tuple[str, ...] = ()
    source_sector_raw: tuple[str, ...] = ()
    activity_descriptions: tuple[str, ...] = ()
    victim_website: str = ""
    activity_code: str = ""
    activity_label: str = ""
    titles: tuple[str, ...] = ()
    candidate_sectors: tuple[str, ...] = ()
    evidence_types: tuple[str, ...] = ()

    def to_payload(self) -> dict:
        return {
            "organisation_key": self.organisation_key,
            "organisation": self.organisation,
            "aliases": list(self.aliases),
            "source_ids": list(self.source_ids),
            "source_sector_raw": list(self.source_sector_raw),
            "activity_descriptions": list(self.activity_descriptions),
            "victim_website": self.victim_website,
            "activity_code": self.activity_code,
            "activity_label": self.activity_label,
            "titles": list(self.titles),
            "candidate_sectors": list(self.candidate_sectors),
            "evidence_types": list(self.evidence_types),
        }


def build_organisation_context(
    organisation_key: str,
    items: list[Item],
    *,
    source_fact_rows: list[dict],
    org_cache_rows: list[dict],
    evidence: list[osec.OrganisationSectorEvidence] | None = None,
) -> OrganisationContext:
    org_items = [item for item in items if item.Organisation_Key == organisation_key]
    display = osec.display_names(org_items).get(organisation_key, organisation_key)
    aliases = tuple(sorted({item.Organisation_Raw for item in org_items if item.Organisation_Raw}))[:MAX_ALIASES]
    source_ids = tuple(sorted({item.Source_ID for item in org_items if item.Source_ID}))
    titles = tuple(sorted({item.Title for item in org_items if item.Title}))[:MAX_TITLES]

    item_ids = {item.Item_ID for item in org_items}
    raw_sectors: set[str] = set()
    descriptions: set[str] = set()
    for row in source_fact_rows:
        if (row.get("Item_ID") or "").strip() not in item_ids:
            continue
        raw = (row.get("Source_Sector_Raw") or "").strip()
        if raw:
            raw_sectors.add(raw)
        description = (row.get("Activity_Description") or "").strip()
        if description:
            descriptions.add(description)

    cache_row = next(
        (row for row in org_cache_rows if (row.get("Organisation_Key") or "").strip() == organisation_key),
        None,
    ) or {}
    website = ""
    if cache_row.get("Evidence_URL"):
        website = urlparse(cache_row["Evidence_URL"]).netloc

    evidence = evidence or []
    candidate_sectors = tuple(sorted({e.sector for e in evidence if e.sector != config.SECTOR_UNKNOWN}))
    evidence_types = tuple(sorted({e.evidence_type for e in evidence}))

    return OrganisationContext(
        organisation_key=organisation_key,
        organisation=display,
        aliases=aliases,
        source_ids=source_ids,
        source_sector_raw=tuple(sorted(raw_sectors))[:MAX_SOURCE_SECTOR_RAW],
        activity_descriptions=tuple(sorted(descriptions))[:MAX_ACTIVITY_DESCRIPTIONS],
        victim_website=website,
        activity_code=(cache_row.get("Activity_Code") or "").strip(),
        activity_label=(cache_row.get("Activity_Label") or "").strip(),
        titles=titles,
        candidate_sectors=candidate_sectors,
        evidence_types=evidence_types,
    )


def compute_input_hash(context: OrganisationContext, *, model: str, prompt_version: str) -> str:
    """Hash déterministe : organisation + contexte transmis + taxonomie +
    modèle + version de prompt (§18 du plan). Un cache hit n'appelle jamais
    le LLM à nouveau."""
    payload = {
        "context": context.to_payload(),
        "taxonomy": list(config.SECTORS),
        "model": model,
        "prompt_version": prompt_version,
    }
    blob = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------
# Cache (§18)
# --------------------------------------------------------------------------


def _aux_path(path):
    return store.ITEMS_CSV.parent / path.name


def load_cache(path=None) -> list[dict]:
    return store.read_csv(path or _aux_path(CACHE_CSV))


def save_cache(rows: list[dict], path=None) -> None:
    ordered = sorted(rows, key=lambda row: row.get("Organisation_Key", ""))
    store.write_csv(path or _aux_path(CACHE_CSV), CACHE_COLUMNS, ordered)


def _cache_by_key(rows: list[dict]) -> dict[str, dict]:
    return {row.get("Organisation_Key", ""): row for row in rows if row.get("Organisation_Key")}


# --------------------------------------------------------------------------
# Sélection et batching (§12, §16)
# --------------------------------------------------------------------------


def select_organisations_for_llm(
    items: list[Item],
    decisions: dict[str, osec.OrganisationSectorDecision],
    *,
    organisation_keys: set[str] | None = None,
) -> list[str]:
    """File organisationnelle déterministe : une organisation, une fois.

    Exclut toute organisation déjà ``CONFIRMED`` ou en ``CONFLICT`` (un
    conflit, fort ou entre candidats faibles, n'est jamais arbitré par le
    LLM — §6, §12). ``TENTATIVE`` reste sélectionnable : un précédent
    candidat LLM devenu obsolète (Input_Hash différent) doit pouvoir être
    redemandé ; un cache toujours valide sera de toute façon un cache hit et
    n'appellera pas le LLM (cf. ``enrich_unknown_organisation_sectors``).
    """
    known_keys = {item.Organisation_Key for item in items if item.Organisation_Key}
    candidates = sorted(known_keys | set(decisions))
    selected = []
    for key in candidates:
        if organisation_keys is not None and key not in organisation_keys:
            continue
        decision = decisions.get(key)
        if decision is None or decision.status not in (osec.STATUS_UNKNOWN, osec.STATUS_TENTATIVE):
            continue
        selected.append(key)
    return selected


def build_batches(entries: list, batch_size: int = DEFAULT_BATCH_SIZE) -> list[list]:
    """Découpe une liste déjà triée en lots stables (déterministe)."""
    if batch_size <= 0:
        batch_size = DEFAULT_BATCH_SIZE
    return [entries[i:i + batch_size] for i in range(0, len(entries), batch_size)]


# --------------------------------------------------------------------------
# Appel LLM structuré (§14, §15, §17)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class LlmOrganisationCandidate:
    organisation_key: str
    sector: str
    confidence: float
    basis: str
    reason: str


def _validate_candidate(entry: object, requested_keys: set[str]) -> LlmOrganisationCandidate | None:
    if not isinstance(entry, dict):
        return None
    key = str(entry.get("organisation_key") or "").strip()
    sector = str(entry.get("sector") or "").strip()
    basis = str(entry.get("basis") or "").strip()
    confidence = entry.get("confidence")
    reason = str(entry.get("reason") or "").strip()
    if not key or key not in requested_keys:
        return None
    if sector not in config.SECTORS:
        return None
    if basis not in BASIS_VALUES:
        return None
    if not isinstance(confidence, (int, float)) or not (0.0 <= float(confidence) <= 1.0):
        return None
    return LlmOrganisationCandidate(key, sector, float(confidence), basis, reason)


def call_llm_batch(
    batch: list[tuple[str, OrganisationContext]],
    *,
    api_key: str | None = None,
) -> dict[str, LlmOrganisationCandidate]:
    """Un seul appel structuré pour tout le lot. Résilient : une réponse
    invalide, partielle, dupliquée ou hors taxonomie ne bloque jamais — les
    organisations absentes ou invalides restent simplement non résolues."""
    if not batch:
        return {}
    requested_keys = {key for key, _context in batch}
    user_payload = {
        "organisations": [context.to_payload() for _key, context in batch],
    }
    user_content = json.dumps(user_payload, ensure_ascii=False, sort_keys=True)

    result = llm_runtime.runtime().call_json(
        task=TASK,
        system_prompt=SYSTEM_PROMPT,
        user_content=user_content,
        schema_name=_SCHEMA_NAME,
        schema=_schema(),
        max_output_tokens=MAX_OUTPUT_TOKENS,
    )
    raw = result.data.get("organisations")
    if not isinstance(raw, list):
        return {}

    resolved: dict[str, LlmOrganisationCandidate] = {}
    for entry in raw:
        candidate = _validate_candidate(entry, requested_keys)
        if candidate is None:
            continue
        if candidate.organisation_key in resolved:
            # Duplicat d'organisation dans la réponse : on garde le premier,
            # jamais un écrasement silencieux qui masquerait l'anomalie.
            continue
        if candidate.sector == config.SECTOR_UNKNOWN or candidate.basis == "insufficient":
            continue
        resolved[candidate.organisation_key] = candidate
    return resolved


# --------------------------------------------------------------------------
# Orchestration (§26, §27) — seule porte d'entrée réseau de ce module
# --------------------------------------------------------------------------


@dataclass
class EnrichmentReport:
    organisations_selected: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    calls: int = 0
    candidates: int = 0
    abstentions: int = 0
    llm_available: bool = False
    dry_run: bool = False
    cost_usd: float = 0.0
    cache_rows: list[dict] = field(default_factory=list)


def enrich_unknown_organisation_sectors(
    items: list[Item],
    *,
    reference: dict,
    source_fact_rows: list[dict] | None = None,
    org_cache_rows: list[dict] | None = None,
    previous_provenance: list[dict] | None = None,
    cache_rows: list[dict] | None = None,
    batch_size: int = DEFAULT_BATCH_SIZE,
    limit: int | None = None,
    organisation_keys: set[str] | None = None,
    dry_run: bool = False,
    force: bool = False,
    no_llm: bool = False,
    api_key: str | None = None,
    model: str | None = None,
    prompt_version: str = PROMPT_VERSION,
) -> EnrichmentReport:
    """Seule fonction de ce module autorisée à appeler le réseau/LLM.

    ``dry_run=True`` : aucune écriture, aucun appel LLM (simulation complète).
    ``no_llm=True`` : calcule la sélection et les cache hits normalement, mais
    n'appelle jamais le LLM pour les cache misses (utile pour mesurer le
    reliquat P0 sans consommer de budget). ``force=True`` : ignore un cache
    hit existant et redemande un candidat (Input_Hash rejoué à l'identique si
    rien n'a changé, donc jamais destructif).
    """
    source_fact_rows = source_fact_rows if source_fact_rows is not None else store.read_csv(store.SOURCE_FACTS_CSV)
    org_cache_rows = org_cache_rows if org_cache_rows is not None else store.load_org_enrichment_cache()
    previous_provenance = previous_provenance or []
    cache_rows = list(cache_rows) if cache_rows is not None else load_cache()
    effective_model = llm_runtime.model_for_task(TASK, model)

    decisions = osec.resolve_all_organisation_sectors(
        items,
        reference=reference,
        source_fact_rows=source_fact_rows,
        org_cache_rows=org_cache_rows,
        previous_provenance=previous_provenance,
        llm_cache_rows=cache_rows,
    )
    selected = select_organisations_for_llm(items, decisions, organisation_keys=organisation_keys)
    if limit is not None:
        selected = selected[:limit]

    # Le contexte transmis au LLM (et son Input_Hash) ne doit refléter que des
    # signaux déterministes (§13) : y inclure le candidat LLM déjà en cache
    # rendrait le hash instable d'un run à l'autre (auto-référence).
    evidence_by_org = osec.collect_organisation_evidence(
        items,
        reference=reference,
        source_fact_rows=source_fact_rows,
        org_cache_rows=org_cache_rows,
        previous_provenance=previous_provenance,
        llm_cache_rows=[],
    )

    cache_by_key = _cache_by_key(cache_rows)
    report = EnrichmentReport(
        organisations_selected=len(selected),
        llm_available=llm_runtime.runtime().enabled,
        dry_run=dry_run,
    )

    pending: list[tuple[str, OrganisationContext, str]] = []
    for key in selected:
        context = build_organisation_context(
            key, items, source_fact_rows=source_fact_rows, org_cache_rows=org_cache_rows,
            evidence=evidence_by_org.get(key, []),
        )
        input_hash = compute_input_hash(context, model=effective_model, prompt_version=prompt_version)
        cached = cache_by_key.get(key)
        if not force and cached is not None and cached.get("Input_Hash") == input_hash:
            report.cache_hits += 1
            continue
        report.cache_misses += 1
        pending.append((key, context, input_hash))

    updated_rows = dict(cache_by_key)
    if not dry_run and not no_llm and pending and llm_runtime.runtime().enabled:
        now = datetime.now(timezone.utc).isoformat()
        for batch in build_batches([(key, context) for key, context, _hash in pending], batch_size):
            try:
                results = call_llm_batch(batch, api_key=api_key)
            except llm_runtime.LlmBudgetExceeded:
                break
            except llm_runtime.LlmError:
                continue
            report.calls += 1
            batch_keys = {key for key, _context in batch}
            hash_by_key = {key: input_hash for key, _context, input_hash in pending if key in batch_keys}
            for key, _context in batch:
                candidate = results.get(key)
                if candidate is None:
                    report.abstentions += 1
                    continue
                report.candidates += 1
                context = next(context for pending_key, context, _hash in pending if pending_key == key)
                updated_rows[key] = {
                    "Organisation_Key": key,
                    "Organisation": context.organisation,
                    "Input_Hash": hash_by_key.get(key, ""),
                    "Sector": candidate.sector,
                    "Confidence": f"{candidate.confidence:.2f}",
                    "Basis": candidate.basis,
                    "Reason": candidate.reason[:500],
                    "Model": effective_model,
                    "Prompt_Version": prompt_version,
                    "Created_At": now,
                }

    report.cost_usd = llm_runtime.runtime().stats.by_task.get(TASK, {}).get("estimated_cost_usd", 0.0)
    report.cache_rows = sorted(updated_rows.values(), key=lambda row: row.get("Organisation_Key", ""))
    if not dry_run and updated_rows != cache_by_key:
        save_cache(report.cache_rows)
    return report
