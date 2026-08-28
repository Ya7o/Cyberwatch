"""Décision LLM organisationnelle finale — jamais de recherche Internet.

Refonte 2026-08-26 ("preuves partout, décision unique à la fin", cas réel
Klark AI qui a motivé cette refonte : un mécanisme d'ingestion séparé avait
appliqué directement un secteur approximatif avant que la moindre autre
preuve n'ait sa chance). Ce module répond désormais à la question qui
tranche Sector pour toute organisation que ni la référence manuelle ni un
code NAF précis n'ont résolue : à partir de l'ensemble des preuves faibles
déjà collectées par :mod:`cyberwatch.organisation_sector`
(``collect_organisation_evidence`` — structured_source, safe_name,
official_subject_activity, source_activity, domain_page, official_site),
quel est le secteur le plus proche pour cette organisation ? Aucune
recherche web, aucun outil, aucun accès réseau autre que l'appel structuré
au modèle lui-même.

Ce module ne remplace pas :mod:`cyberwatch.ai` (classifieur item-level à
partir d'``Activity_Description``, jamais Sector depuis la refonte).

Étape **obligatoire** de ``qualification.qualify()`` (plus une commande
manuelle à part) : appelée automatiquement pour toute organisation encore
``UNKNOWN`` après le passage des deux autorités (référence manuelle, NAF
précis). Sa réponse (``llm_organisation``) devient alors la décision
(confidence toujours ``LOW``, jamais une preuve forte — cf. le revirement de
politique "plus proche que Inconnu" de :mod:`cyberwatch.organisation_sector`).
``sector-llm``/``sector-backfill`` restent utiles en rattrapage manuel (ex.
budget épuisé lors du run d'origine), mais ne sont plus le seul chemin
d'accès. Une clé absente, un budget épuisé ou une panne réseau ne bloquent
jamais : les organisations concernées restent simplement ``UNKNOWN``.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlparse

from . import config, llm_runtime, org_identity, organisation_sector as osec, store
from .model import Item

TASK = "organisation_sector"
PROMPT_VERSION = "2026-08-28.7"
#: Audit 2026-08-26 (run réel 32968633926) : 11 organisations très
#: différentes traitées en un seul appel n'ont produit que 75 tokens de
#: sortie au total (~7/organisation) — famine de tokens qui expliquait des
#: jugements incohérents (ex. Klark AI classé sur la base de la fuite de
#: données plutôt que son activité, pourtant présente dans le contexte).
#: Réduit fortement pour que chaque organisation reçoive une part
#: significative de l'attention du modèle.
DEFAULT_BATCH_SIZE = 6
# Run réel 33139189464 (2026-08-28) : avec un lot de 4 organisations et
# ``reasoning_effort="medium"``, gpt-5-nano a consommé 3 968 des 4 000 tokens
# autorisés en raisonnement puis a rendu une réponse ``incomplete`` sans le
# moindre JSON visible. La limite Responses englobe raisonnement + sortie ;
# 25 000 est la réserve initiale recommandée par la documentation OpenAI pour
# éviter précisément ce cas. Le batch reste borné à 6 organisations et le
# plafond de coût du runtime continue de s'appliquer avant chaque appel.
MAX_OUTPUT_TOKENS = 25_000
#: Bornes de compacité du contexte transmis (§13 du plan) : reproductible et
#: hashable, jamais le corpus complet des incidents.
MAX_ALIASES = 5
MAX_TITLES = 3
MAX_ACTIVITY_DESCRIPTIONS = 3
MAX_SOURCE_SECTOR_RAW = 3
#: Nombre maximal de preuves détaillées transmises (audit 2026-08-26, refonte
#: "preuves partout, décision unique à la fin") : chaque étape qui a déposé
#: une preuve pour cette organisation (structured_source, safe_name,
#: official_subject_activity, source_activity, domain_page, official_site)
#: doit être visible du LLM final, pas seulement résumée en un ensemble de
#: secteurs candidats — borné pour rester reproductible et hashable.
MAX_EVIDENCE_ITEMS = 12
MAX_EVIDENCE_TEXT_CHARS = 300

CACHE_CSV = osec.LLM_CACHE_CSV
CACHE_COLUMNS = [
    "Organisation_Key", "Organisation", "Input_Hash", "Sector", "Confidence",
    "Basis", "Reason", "Model", "Prompt_Version", "Created_At",
]

BASIS_VALUES = (
    "explicit_activity", "structured_metadata", "naf_support", "name_semantics",
    "organisation_knowledge", "multiple_signals", "insufficient",
)
ACTIONABLE_BASIS_VALUES = {
    "explicit_activity", "structured_metadata", "naf_support", "multiple_signals",
}
MIN_ACTIONABLE_CONFIDENCE = 0.70

SYSTEM_PROMPT = (
    "Tu es un classificateur strict pour un observatoire d'incidents cyber.\n"
    "Tu n'as pas accès à Internet. Tu ne dois pas supposer avoir effectué une "
    "recherche web. Utilise uniquement les informations fournies.\n"
    "Tu es l'étape finale : chaque organisation te parvient avec "
    "evidence_details, la liste de TOUTES les preuves déjà rassemblées par "
    "les étapes précédentes (registre entreprise, site officiel, extraction "
    "d'article, mots-clés déterministes...), chacune avec son type, le "
    "secteur qu'elle suggère, son texte et sa source. Examine l'ensemble de "
    "cette liste avant de trancher — ne te limite jamais à la première "
    "entrée ; en cas de désaccord entre preuves, retiens le secteur le "
    "mieux corroboré par l'ensemble, pas seulement la preuve la plus "
    "récente ou la plus détaillée.\n"
    "evidence_stage_outcomes indique aussi, pour chaque technique attendue, "
    "si elle a produit une preuve ou n'a trouvé aucun match. Une étape sans "
    "match n'est pas une preuve négative contre les autres.\n"
    "Le secteur correspond à l'activité principale de l'organisation victime.\n"
    "Ne déduis jamais le secteur depuis : le type de données volées ; les "
    "victimes de la fuite ; le type d'incident cyber.\n"
    "Exemples : présence de RIB != Finance ; données médicales != forcément "
    "Santé ; données de livraison != Transport.\n"
    "Ne tranche que si une activité explicite, une métadonnée structurée, un "
    "appui NAF ou plusieurs signaux indépendants étayent le secteur. Le nom "
    "seul, une intuition ou une connaissance interne non corroborée ne sont "
    "pas des preuves publiables : réponds alors Inconnu avec "
    "basis=insufficient.\n"
    "La taxonomie n'est pas exhaustive : n'oblige jamais une activité sociale, "
    "caritative ou associative à entrer dans 'Services aux entreprises', qui "
    "désigne exclusivement des prestations B2B. Exemple : une banque alimentaire "
    "qui fournit de l'aide alimentaire reste Inconnu dans cette taxonomie. "
    "Vérifie le sens du texte de preuve indépendamment du secteur candidat qui "
    "l'accompagne ; un candidat mal mappé ne doit pas être recopié.\n"
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
                    # Audit 2026-08-26 : "reason" et "basis" sont déclarés AVANT
                    # "sector" à dessein — en Structured Outputs strict, le
                    # modèle génère les champs dans cet ordre. Un cas réel
                    # (Banque Alimentaire de la Croix-Rouge à Strasbourg)
                    # montrait "sector" déclaré en premier : le modèle committait
                    # sa réponse avant même d'avoir raisonné, produisant un
                    # "reason" qui se corrigeait lui-même ("... n'est pas exact
                    # mais le secteur le plus pertinent est ...") sans que
                    # "sector" en tienne compte. Raisonner d'abord, décider
                    # ensuite.
                    "properties": {
                        "organisation_key": {"type": "string"},
                        "reason": {"type": "string"},
                        "basis": {"type": "string", "enum": list(BASIS_VALUES)},
                        "confidence": {"type": "number"},
                        "sector": {"type": "string", "enum": list(config.SECTORS)},
                    },
                    "required": ["organisation_key", "reason", "basis", "confidence", "sector"],
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
    evidence_stage_outcomes: tuple[dict, ...] = ()
    #: Une entrée par preuve faible collectée par
    #: organisation_sector.collect_organisation_evidence (audit 2026-08-26,
    #: refonte "preuves partout, décision unique à la fin") :
    #: {"type", "sector", "text", "source", "url"}. Remplace le résumé
    #: agrégé (candidate_sectors/evidence_types) par le détail complet —
    #: le LLM voit ce que CHAQUE étape a réellement trouvé, pas seulement
    #: l'ensemble des secteurs qui en ressortent.
    evidence_details: tuple[dict, ...] = ()

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
            "evidence_stage_outcomes": [dict(value) for value in self.evidence_stage_outcomes],
            "evidence_details": [dict(e) for e in self.evidence_details],
        }


def build_organisation_context(
    organisation_key: str,
    items: list[Item],
    *,
    source_fact_rows: list[dict],
    org_cache_rows: list[dict],
    evidence: list[osec.OrganisationSectorEvidence] | None = None,
) -> OrganisationContext:
    org_items = [
        item for item in items
        if osec.sector_organisation_key(item) == organisation_key
    ]
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
        (
            row for row in org_cache_rows
            if org_identity.effective_organisation_key(
                row.get("Matched_Name") or row.get("Query_Name") or "",
                (row.get("Organisation_Key") or "").strip(),
            ) == organisation_key
        ),
        None,
    ) or {}
    website = ""
    if cache_row.get("Evidence_URL"):
        website = urlparse(cache_row["Evidence_URL"]).netloc

    evidence = evidence or []
    candidate_sectors = tuple(sorted({e.sector for e in evidence if e.sector != config.SECTOR_UNKNOWN}))
    evidence_types = tuple(sorted({e.evidence_type for e in evidence}))
    ordered_evidence = sorted(
        evidence,
        key=lambda e: (e.evidence_type, e.sector, e.source, e.evidence_text, e.evidence_url),
    )
    # Réserver d'abord une place à chaque canal produit, puis compléter avec
    # les preuves restantes. Une simple tranche globale pouvait masquer un
    # canal entier lorsque les premières étapes étaient très prolifiques.
    selected_evidence = []
    seen_details: set[tuple] = set()
    for evidence_type in osec.AUDITED_EVIDENCE_TYPES:
        candidate = next((e for e in ordered_evidence if e.evidence_type == evidence_type), None)
        if candidate is None:
            continue
        marker = (candidate.evidence_type, candidate.sector, candidate.source, candidate.evidence_text, candidate.evidence_url)
        selected_evidence.append(candidate)
        seen_details.add(marker)
    for candidate in ordered_evidence:
        marker = (candidate.evidence_type, candidate.sector, candidate.source, candidate.evidence_text, candidate.evidence_url)
        if marker in seen_details:
            continue
        selected_evidence.append(candidate)
        seen_details.add(marker)
        if len(selected_evidence) >= MAX_EVIDENCE_ITEMS:
            break
    evidence_details = tuple(
        {
            "type": e.evidence_type,
            "sector": e.sector,
            "text": (e.evidence_text or "")[:MAX_EVIDENCE_TEXT_CHARS],
            "source": e.source,
            "url": e.evidence_url,
        }
        for e in selected_evidence[:max(MAX_EVIDENCE_ITEMS, len(osec.AUDITED_EVIDENCE_TYPES))]
    )
    evidence_stage_outcomes = tuple(
        {
            "type": evidence_type,
            "outcome": "PRODUCED" if evidence_type in evidence_types else "NO_MATCH",
        }
        for evidence_type in osec.AUDITED_EVIDENCE_TYPES
        if evidence_type != osec.EVIDENCE_LLM_ORGANISATION
    )

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
        evidence_stage_outcomes=evidence_stage_outcomes,
        evidence_details=evidence_details,
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
    indexed: dict[str, dict] = {}
    for row in rows:
        key = org_identity.effective_organisation_key(
            row.get("Organisation", ""), row.get("Organisation_Key", ""),
        )
        if not key:
            continue
        canonical = dict(row)
        canonical["Organisation_Key"] = key
        indexed[key] = canonical
    return indexed


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

    Exclut toute organisation déjà ``CONFIRMED`` (qu'elle le soit via une
    preuve forte ou via un rapprochement faible/LLM déjà appliqué — audit
    2026-08-26, ``STATUS_TENTATIVE`` retiré, tout type de preuve gagnant
    applique désormais ``Item.Sector``) ou en ``CONFLICT`` (un conflit
    interne au type le plus prioritaire n'est jamais arbitré par le LLM —
    §6, §12). Seul ``UNKNOWN`` (aucune preuve du tout) reste sélectionnable.
    """
    known_keys = {
        osec.sector_organisation_key(item)
        for item in items if osec.sector_organisation_key(item)
    }
    if organisation_keys is not None:
        organisation_keys = {
            org_identity.effective_organisation_key("", key)
            for key in organisation_keys
        }
    candidates = sorted(known_keys | set(decisions))
    selected = []
    for key in candidates:
        if organisation_keys is not None and key not in organisation_keys:
            continue
        decision = decisions.get(key)
        if decision is None or decision.status != osec.STATUS_UNKNOWN:
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
    # Le LLM tranche à la fin du faisceau de preuves, mais ne peut fabriquer
    # une preuve à partir du seul nom ou de sa mémoire. Ces réponses restent
    # des abstentions et ne sont jamais injectées dans le registre publié.
    if sector == config.SECTOR_UNKNOWN or basis not in ACTIONABLE_BASIS_VALUES:
        return None
    if float(confidence) < MIN_ACTIONABLE_CONFIDENCE:
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
        # Audit 2026-08-26 : seule tâche du code à s'écarter de "minimal"
        # (partout ailleurs par défaut) — justifié par la preuve concrète de
        # famine de tokens (run 32968633926, 75 tokens de sortie pour 11
        # organisations) et un coût actuel négligeable pour cette tâche.
        reasoning_effort="medium",
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
    outcomes: dict[str, str] = field(default_factory=dict)


def enrich_unknown_organisation_sectors(
    items: list[Item],
    *,
    reference: dict,
    source_fact_rows: list[dict] | None = None,
    org_cache_rows: list[dict] | None = None,
    domain_page_rows: list[dict] | None = None,
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
    persist: bool = True,
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

    # Sélection sans cache LLM : une ligne obsolète ne doit jamais devenir
    # CONFIRMED avant la comparaison de son Input_Hash au contexte courant.
    decisions = osec.resolve_all_organisation_sectors(
        items,
        reference=reference,
        source_fact_rows=source_fact_rows,
        org_cache_rows=org_cache_rows,
        domain_page_rows=domain_page_rows,
        previous_provenance=previous_provenance,
        llm_cache_rows=[],
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
        domain_page_rows=domain_page_rows,
        previous_provenance=previous_provenance,
        llm_cache_rows=[],
    )

    cache_by_key = _cache_by_key(cache_rows)
    report = EnrichmentReport(
        organisations_selected=len(selected),
        llm_available=llm_runtime.runtime().enabled,
        dry_run=dry_run,
    )
    for key, decision in decisions.items():
        if decision.status != osec.STATUS_UNKNOWN:
            report.outcomes[key] = "NOT_APPLICABLE"

    updated_rows = dict(cache_by_key)
    present_keys = {
        osec.sector_organisation_key(item)
        for item in items if osec.sector_organisation_key(item)
    }
    selected_set = set(selected)
    # Une organisation résolue par une autorité n'a plus de décision LLM
    # active. Retirer son ancienne ligne évite de la présenter comme preuve
    # secondaire valide dans le rapport final.
    for key in present_keys - selected_set:
        updated_rows.pop(key, None)
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
            report.outcomes[key] = "PRODUCED"
            continue
        # Une entrée périmée ne doit pas être réinjectée si le nouvel appel
        # échoue, si le budget est épuisé ou si le LLM est désactivé.
        updated_rows.pop(key, None)
        report.cache_misses += 1
        pending.append((key, context, input_hash))

    if not dry_run and not no_llm and pending and llm_runtime.runtime().enabled:
        now = datetime.now(timezone.utc).isoformat()
        for batch in build_batches([(key, context) for key, context, _hash in pending], batch_size):
            try:
                results = call_llm_batch(batch, api_key=api_key)
            except llm_runtime.LlmBudgetExceeded:
                for key, _context in batch:
                    report.outcomes.setdefault(key, "BUDGET_BLOCKED")
                break
            except llm_runtime.LlmError:
                for key, _context in batch:
                    report.outcomes[key] = "ERROR"
                continue
            report.calls += 1
            batch_keys = {key for key, _context in batch}
            hash_by_key = {key: input_hash for key, _context, input_hash in pending if key in batch_keys}
            for key, _context in batch:
                candidate = results.get(key)
                if candidate is None:
                    report.abstentions += 1
                    report.outcomes[key] = "NO_MATCH"
                    continue
                report.candidates += 1
                report.outcomes[key] = "PRODUCED"
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

    if dry_run or no_llm:
        fallback_outcome = "NOT_APPLICABLE" if dry_run or no_llm else "ERROR"
        for key, _context, _input_hash in pending:
            report.outcomes.setdefault(key, fallback_outcome)
    elif pending and not llm_runtime.runtime().enabled:
        for key, _context, _input_hash in pending:
            report.outcomes.setdefault(key, "ERROR")
    else:
        for key, _context, _input_hash in pending:
            report.outcomes.setdefault(key, "BUDGET_BLOCKED")

    report.cost_usd = llm_runtime.runtime().stats.by_task.get(TASK, {}).get("estimated_cost_usd", 0.0)
    report.cache_rows = sorted(updated_rows.values(), key=lambda row: row.get("Organisation_Key", ""))
    if persist and not dry_run and updated_rows != cache_by_key:
        save_cache(report.cache_rows)
    return report
