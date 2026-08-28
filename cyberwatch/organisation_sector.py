"""Résolution organisationnelle du secteur (Sector) — P0.

``Sector`` décrit l'activité principale de l'organisation victime. Il ne décrit
ni la nature des données volées, ni le contexte de l'incident.

Ce module résout ``Sector`` au niveau ``Organisation_Key``, à partir des
preuves déjà collectées ailleurs dans Cyberwatch (référentiel manuel, sources
structurées, cache d'enrichissement entreprise, provenance de qualification).
Aucun accès réseau, aucun LLM ici : le complément par LLM organisationnel vit
dans :mod:`cyberwatch.organisation_sector_llm`.

Refonte 2026-08-26 (« preuves partout, décision unique à la fin », audit du
cas réel Klark AI — voir ``EVIDENCE_OFFICIAL_SITE`` — appliqué à tort par un
mécanisme d'ingestion séparé avant que ce module n'ait pu arbitrer quoi que
ce soit) : seules deux autorités court-circuitent tout le reste sans jamais
solliciter de LLM — ``manual_reference`` (validation humaine) et
``naf_precise_v2`` (code NAF officiel). Tous les autres types de preuve
(``structured_source``, ``safe_name``, ``official_subject_activity``,
``source_activity``, ``domain_page``, ``official_site``) ne décident plus
jamais seuls : ils sont uniquement collectés ici pour alimenter le contexte
transmis au LLM organisationnel, devenu une étape **obligatoire** de
``qualify()`` (plus une commande manuelle à part) pour toute organisation
qu'aucune des deux autorités n'a résolue. Sa réponse (``llm_organisation``)
devient alors la décision, avec une confiance toujours ``LOW`` (jamais une
preuve forte, mais appliquée : voir le revirement de politique du
2026-08-26 sur "plus proche que Inconnu", ci-dessous).

Statuts possibles :

    CONFIRMED   manual_reference, naf_precise_v2, ou (après son passage
                obligatoire) llm_organisation a tranché pour cette
                organisation — HIGH pour les deux premiers, LOW pour le LLM
    CONFLICT    preuves du même type (manual_reference ou naf_precise_v2)
                qui se contredisent entre elles
    UNKNOWN     aucune des deux autorités, et le LLM final n'a pas encore
                tranché (budget épuisé, erreur API non bloquante, ou pas
                encore exécuté pour cette organisation)

Règle d'arbitrage (déterministe, indépendante de l'ordre des candidats —
cf. ``PRECEDENCE``, réduite à ces 3 types) : le premier type présent pour
l'organisation tranche, sans jamais redescendre vers un type moins
prioritaire même unanime ; seule une contradiction interne au type le plus
prioritaire présent reste un ``CONFLICT``.

Revirement de politique (audit 2026-08-26, décision explicite, préexistant à
cette refonte et toujours en vigueur) : une proposition LLM seule est
appliquée à Item.Sector comme une preuve forte (statut ``TENTATIVE``, jamais
appliqué, retiré) — ce module choisit systématiquement le secteur le plus
proche disponible plutôt que ``Inconnu``, y compris pour une activité
associative/caritative/politique ; seule une absence totale de résolution
(les deux autorités absentes ET le LLM final non concluant) reste
``UNKNOWN``.

Anti-bouclage : une décision appliquée par ce module (``Origin`` égal à
``ORIGIN`` ou ``ORIGIN_LLM`` dans ``qualification_provenance.csv``) n'est
jamais relue comme preuve primaire. ``restore_organisation_sector_applications``
réinitialise les items concernés avant toute nouvelle collecte, exactement
comme :func:`cyberwatch.sector_registry.restore_registry_applications`.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, replace
import hashlib
from pathlib import Path
import re

from . import (
    company_subject_evidence,
    config,
    context_sector,
    org_identity,
    org_enrichment,
    sector as sector_policy,
    sector_registry,
    store,
    watchlists,
)
from .model import Item
from .normalize import organisation_key

STATUS_CONFIRMED = "CONFIRMED"
STATUS_CONFLICT = "CONFLICT"
STATUS_UNKNOWN = "UNKNOWN"

#: Origine appliquée par la résolution déterministe (P0).
ORIGIN = "ORGANISATION_SECTOR_P0"
#: Origine appliquée par convergence avec le candidat LLM organisationnel (P1).
ORIGIN_LLM = "ORGANISATION_SECTOR_LLM"

DECISIONS_CSV = store.DATA_DIR / "organisation_sector_decisions.csv"
DECISIONS_COLUMNS = [
    "Organisation_Key", "Organisation", "Sector", "Status", "Confidence",
    "Evidence_Types", "Evidence_Count", "Evidence", "Conflicting_Sectors",
    "Evidence_IDs", "Winning_Evidence_Type", "Decision_Origin", "Updated_At",
]

EVIDENCE_CSV = store.DATA_DIR / "organisation_sector_evidence.csv"
EVIDENCE_COLUMNS = [
    "Evidence_ID", "Organisation_Key", "Organisation", "Item_ID",
    "Evidence_Type", "Producer", "Outcome", "Candidate_Sector",
    "Confidence", "Authority", "Source", "Evidence_Text", "Evidence_URL",
]

#: Cache du candidat LLM organisationnel (P1, cf. organisation_sector_llm.py).
#: Toujours lu hors-ligne : ce module ne déclenche jamais d'appel réseau.
LLM_CACHE_CSV = store.DATA_DIR / "organisation_sector_llm.csv"

#: Cache page officielle (cf. domain_page_sector.py), relu hors-ligne comme
#: le cache LLM ci-dessus : le worker fait le réseau, ce module ne fait que
#: relire ce qu'il a persisté.
DOMAIN_PAGE_CACHE_CSV = store.DATA_DIR / "organisation_domain_page.csv"

EVIDENCE_MANUAL_REFERENCE = "manual_reference"
EVIDENCE_STRUCTURED_SOURCE = "structured_source"
EVIDENCE_WATCHLIST_HINT = "watchlist_hint"
EVIDENCE_SAFE_NAME = "safe_name"
EVIDENCE_OFFICIAL_SUBJECT_ACTIVITY = "official_subject_activity"
EVIDENCE_NAF_PRECISE = "naf_precise_v2"
EVIDENCE_VALIDATED_ITEM = "validated_item"
EVIDENCE_SOURCE_ACTIVITY = "source_activity"
EVIDENCE_DOMAIN_PAGE = "domain_page"
EVIDENCE_LLM_ORGANISATION = "llm_organisation"
#: Audit 2026-08-26 (refonte "preuves partout, décision unique à la fin") :
#: un site officiel trouvé par la recherche générale
#: (company_evidence.resolve_official_site), classé par un regex déterministe
#: (classify_official_activity), PAS un code NAF. Cas réel qui a motivé cette
#: refonte : Klark AI classé "Services aux entreprises" sur le seul mot
#: "consulting firm", appliqué directement à l'ingestion avant que la
#: moindre autre preuve (ex. "intelligence artificielle") ait sa chance.
#: Ce canal n'est plus jamais appliqué seul : une preuve parmi d'autres,
#: transmise au LLM final (§organisation_sector_llm.py).
EVIDENCE_OFFICIAL_SITE = "official_site"

#: Types de preuve qui court-circuitent tout le reste : une autorité externe
#: (NAF officiel) ou une validation humaine, jamais un LLM. Audit 2026-08-26
#: (refonte "preuves partout, décision unique à la fin") : tous les autres
#: types de preuve (safe_name, official_subject_activity, validated_item,
#: structured_source, domain_page, official_site, source_activity) ne
#: confirment plus jamais seuls — ils alimentent uniquement le contexte du
#: LLM final (cf. PRECEDENCE plus bas, qui ne les liste plus).
STRONG_EVIDENCE_TYPES = frozenset({
    EVIDENCE_MANUAL_REFERENCE,
    EVIDENCE_NAF_PRECISE,
})

#: Origines de ``qualification_provenance.csv`` acceptées comme preuve qu'un
#: ``Item.Sector`` actuel a bien été validé par un mécanisme fort. Ne jamais y
#: ajouter ``ORIGIN``/``ORIGIN_LLM`` (ce module) ni ``sector_registry.ORIGIN`` :
#: une propagation ne doit jamais devenir sa propre preuve (§30, §41).
_STRONG_ITEM_ORIGINS = frozenset({
    "MANUAL_REFERENCE",
    "SAFE_NAME_RULE",
    "OFFICIAL_SUBJECT_ACTIVITY",
    "STRUCTURED_SOURCE",
})

# --------------------------------------------------------------------------
# NAF précis v2 (§7 du plan)
# --------------------------------------------------------------------------

from .sector_completion import SECTOR_AGRICULTURE, SECTOR_CULTURE, SECTOR_HOSPITALITY  # noqa: E402

_NAF_AGRICULTURE = frozenset({"01", "02", "03"})
_NAF_INDUSTRY = frozenset(f"{i:02d}" for i in range(10, 34))
_NAF_ENERGY = frozenset({"35", "36", "37", "38", "39"})
_NAF_CONSTRUCTION = frozenset({"41", "42", "43"})
_NAF_RETAIL = frozenset({"45", "46", "47"})
_NAF_TRANSPORT = frozenset({"49", "50", "51", "52", "53"})
_NAF_HOSPITALITY = frozenset({"55", "56", "79"})
#: Uniquement les familles suffisamment discriminantes de la section J
#: (édition de logiciels, programmation/conseil informatique, télécoms) :
#: la section J entière (60, 63.9...) reste trop large pour être généralisée.
_NAF_TECH_PREFIXES = ("61", "62", "631")
_NAF_FINANCE = frozenset({"64", "65", "66"})
#: Sous-classes fortes de services aux entreprises. 70.1 (sièges sociaux) en
#: est exclu : trop proche d'une structure de holding pour représenter le
#: métier réel de la marque.
_NAF_SERVICES_PREFIXES = ("691", "692", "702")
_NAF_SERVICES_DIVISIONS = frozenset({"78", "80", "81"})
#: Holdings et structures purement patrimoniales : jamais assimilées au métier
#: réel de la marque, même au sein d'une division Finance par ailleurs retenue.
_NAF_HOLDING_PREFIXES = ("6420", "6430", "701")


def _normalize_naf(activity_code: str) -> str:
    return str(activity_code or "").strip().upper().replace(".", "").replace(" ", "")


def precise_naf_sector(activity_code: str) -> str:
    """Mappe un code NAF/APE précis vers un secteur canonique (v2).

    Seules des sous-classes suffisamment discriminantes sont retenues ; le
    reste de la nomenclature (y compris un code vide, invalide, une holding ou
    une activité ambiguë) reste ``Inconnu`` plutôt que d'être généralisé.
    """
    code = _normalize_naf(activity_code)
    if len(code) < 2 or not code[:2].isdigit():
        return config.SECTOR_UNKNOWN
    if code.startswith(_NAF_HOLDING_PREFIXES):
        return config.SECTOR_UNKNOWN

    division = code[:2]
    if division in _NAF_AGRICULTURE:
        return SECTOR_AGRICULTURE
    if division in _NAF_INDUSTRY:
        return config.SECTOR_INDUSTRY
    if division in _NAF_ENERGY:
        return config.SECTOR_ENERGY
    if division in _NAF_CONSTRUCTION:
        return config.SECTOR_CONSTRUCTION
    if division in _NAF_RETAIL:
        return config.SECTOR_RETAIL
    if division in _NAF_TRANSPORT:
        return config.SECTOR_TRANSPORT
    if division in _NAF_HOSPITALITY:
        return SECTOR_HOSPITALITY
    if code.startswith(_NAF_TECH_PREFIXES):
        return config.SECTOR_TECH
    if division in _NAF_FINANCE:
        return config.SECTOR_FINANCE
    if code.startswith(_NAF_SERVICES_PREFIXES) or division in _NAF_SERVICES_DIVISIONS:
        return config.SECTOR_SERVICES
    if division == "85":
        return config.SECTOR_EDUCATION
    if division == "86":
        return config.SECTOR_HEALTH
    return config.SECTOR_UNKNOWN


# --------------------------------------------------------------------------
# Modèle de preuve et de décision
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class OrganisationSectorEvidence:
    organisation_key: str
    organisation: str
    sector: str
    evidence_type: str
    confidence: str
    source: str = ""
    evidence_text: str = ""
    evidence_url: str = ""
    item_id: str = ""


AUDITED_EVIDENCE_TYPES: tuple[str, ...] = (
    EVIDENCE_MANUAL_REFERENCE,
    EVIDENCE_NAF_PRECISE,
    EVIDENCE_STRUCTURED_SOURCE,
    EVIDENCE_WATCHLIST_HINT,
    EVIDENCE_SAFE_NAME,
    EVIDENCE_OFFICIAL_SUBJECT_ACTIVITY,
    EVIDENCE_OFFICIAL_SITE,
    EVIDENCE_SOURCE_ACTIVITY,
    EVIDENCE_DOMAIN_PAGE,
    EVIDENCE_LLM_ORGANISATION,
)


@dataclass(frozen=True)
class OrganisationSectorDecision:
    organisation_key: str
    organisation: str
    sector: str
    status: str
    confidence: str
    evidence_types: tuple[str, ...]
    evidence_count: int
    evidence: tuple[str, ...]
    conflicting_sectors: tuple[str, ...] = ()
    #: Type de preuve qui a tranché (§ arbitrage par préséance, audit
    #: 2026-08-26) : le premier type présent dans PRECEDENCE pour cette
    #: organisation. Vide seulement pour UNKNOWN (aucune preuve). Sur
    #: CONFLICT, désigne le type le plus prioritaire présent mais dont les
    #: preuves internes se contredisent (jamais arbitré silencieusement).
    winning_evidence_type: str = ""
    evidence_ids: tuple[str, ...] = ()

    def to_row(self, *, updated_at: str = "") -> dict:
        origin = ORIGIN_LLM if self.winning_evidence_type == EVIDENCE_LLM_ORGANISATION else ORIGIN
        return {
            "Organisation_Key": self.organisation_key,
            "Organisation": self.organisation,
            "Sector": self.sector,
            "Status": self.status,
            "Confidence": self.confidence,
            "Evidence_Types": " | ".join(self.evidence_types),
            "Evidence_Count": str(self.evidence_count),
            "Evidence": " | ".join(self.evidence),
            "Conflicting_Sectors": " | ".join(self.conflicting_sectors),
            "Evidence_IDs": " | ".join(self.evidence_ids),
            "Winning_Evidence_Type": self.winning_evidence_type,
            "Decision_Origin": origin,
            "Updated_At": updated_at,
        }


def _aux_path(path: Path) -> Path:
    """Suit le répertoire d'ITEMS_CSV pour garder les tests isolés."""
    return store.ITEMS_CSV.parent / path.name


def _evidence_string(evidence: OrganisationSectorEvidence) -> str:
    text = (evidence.evidence_text or "").strip().replace("|", "/")[:160]
    parts = [evidence.evidence_type, evidence.sector]
    if text:
        parts.append(text)
    return ":".join(parts)


def _evidence_id(evidence: OrganisationSectorEvidence) -> str:
    raw = "|".join((
        evidence.organisation_key, evidence.evidence_type, evidence.sector,
        evidence.source, evidence.item_id, evidence.evidence_url,
        evidence.evidence_text,
    ))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def sector_organisation_key(item: Item) -> str:
    """Identité canonique utilisée pour une unique décision Sector.

    Le registre d'identité peut être enrichi pendant le même run, juste avant
    ``qualify``. Deux alias déjà reconnus comme une même organisation doivent
    donc partager leurs preuves et la décision LLM finale, même si leurs
    ``Item.Organisation_Key`` historiques restent distinctes.
    """
    return org_identity.effective_organisation_key(
        item.Organisation_Raw, item.Organisation_Key,
    )


def display_names(items: list[Item]) -> dict[str, str]:
    counters: dict[str, Counter] = defaultdict(Counter)
    for item in items:
        key = sector_organisation_key(item)
        if key and item.Organisation_Raw:
            counters[key][item.Organisation_Raw] += 1
    return {
        key: sorted(counter.items(), key=lambda pair: (-pair[1], pair[0]))[0][0]
        for key, counter in counters.items()
    }


# --------------------------------------------------------------------------
# Collecte des preuves (§4 du plan)
# --------------------------------------------------------------------------


def _manual_reference_evidence(reference: dict, allowed_keys: set[str]):
    for key, entry in reference.items():
        if key not in allowed_keys:
            continue
        sector = getattr(entry, "sector", "")
        if not key or sector not in config.SECTORS or sector == config.SECTOR_UNKNOWN:
            continue
        yield OrganisationSectorEvidence(
            key, getattr(entry, "organisation", "") or key, sector,
            EVIDENCE_MANUAL_REFERENCE, "HIGH",
            source="enrichment_reference.csv",
            evidence_text=getattr(entry, "reason", ""),
            evidence_url=getattr(entry, "validation_url", ""),
        )


def _watchlist_evidence(items: list[Item]):
    """Expose les secteurs des entités surveillées comme indices faibles."""
    by_label: dict[str, tuple[str, str]] = {}
    for entity in watchlists.ALL_ENTITIES:
        for label in watchlists.identifying_labels(entity):
            key = organisation_key(label)
            if key and entity.sector_hint:
                by_label[key] = (entity.sector_hint, entity.name)
    seen: set[tuple[str, str]] = set()
    for item in items:
        match = by_label.get(item.Organisation_Key)
        marker = (item.Organisation_Key, item.Item_ID)
        if match is None or marker in seen:
            continue
        sector, canonical_name = match
        if sector not in config.SECTORS or sector == config.SECTOR_UNKNOWN:
            continue
        seen.add(marker)
        yield OrganisationSectorEvidence(
            item.Organisation_Key, item.Organisation_Raw, sector,
            EVIDENCE_WATCHLIST_HINT, "MEDIUM",
            source="watchlists.ALL_ENTITIES", evidence_text=canonical_name,
            item_id=item.Item_ID,
        )


def _structured_source_evidence(items: list[Item], source_fact_rows: list[dict], policy: dict):
    del policy
    by_id = {item.Item_ID: item for item in items if item.Item_ID}
    for row in source_fact_rows:
        item = by_id.get((row.get("Item_ID") or "").strip())
        if item is None:
            continue
        raw = (row.get("Source_Sector_Raw") or "").strip()
        sector = sector_policy.classify_source_sector(raw)
        if sector == config.SECTOR_UNKNOWN:
            continue
        yield OrganisationSectorEvidence(
            item.Organisation_Key, item.Organisation_Raw, sector,
            EVIDENCE_STRUCTURED_SOURCE, "MEDIUM",
            source=f"{row.get('Source_ID', item.Source_ID)}:sector", evidence_text=raw,
            evidence_url=item.URL, item_id=item.Item_ID,
        )


def _safe_name_evidence(items: list[Item]):
    for item in items:
        sector = sector_policy.classify_sector_name(item.Organisation_Raw)
        if sector == config.SECTOR_UNKNOWN:
            continue
        yield OrganisationSectorEvidence(
            item.Organisation_Key, item.Organisation_Raw, sector,
            EVIDENCE_SAFE_NAME, "HIGH",
            source="sector.classify_sector_name", evidence_text=item.Organisation_Raw,
            item_id=item.Item_ID,
        )


def _official_subject_activity_evidence(items: list[Item], org_cache_rows: list[dict]):
    cache_by_key: dict[str, dict] = {}
    for row in org_cache_rows:
        key = (row.get("Organisation_Key") or "").strip()
        sector = (row.get("Validated_Sector") or "").strip()
        if (
            key
            and row.get("Match_Status") == org_enrichment.MATCHED
            and row.get("Validated_Via") == "official_subject_activity"
            and sector in config.SECTORS
            and sector != config.SECTOR_UNKNOWN
        ):
            cache_by_key[key] = row

    seen_orgs: set[str] = set()
    for item in items:
        row = cache_by_key.get(item.Organisation_Key)
        if row is None or item.Organisation_Key in seen_orgs:
            continue
        sector = (row.get("Validated_Sector") or "").strip()
        activity = (row.get("Activity_Label") or "").strip()
        strong = company_subject_evidence.strong_subject_attributed_activity(item.Organisation_Raw, activity)
        if strong is None or strong[0] != sector:
            continue
        seen_orgs.add(item.Organisation_Key)
        yield OrganisationSectorEvidence(
            item.Organisation_Key, item.Organisation_Raw, sector,
            EVIDENCE_OFFICIAL_SUBJECT_ACTIVITY, "HIGH",
            source=row.get("Evidence_Source", ""), evidence_text=strong[1],
            evidence_url=row.get("Evidence_URL", ""), item_id=item.Item_ID,
        )


def _official_site_evidence(org_cache_rows: list[dict]):
    """Site officiel trouvé par la recherche générale, classé par un regex
    déterministe (:func:`cyberwatch.company_evidence.classify_official_activity`),
    jamais par un code NAF. Audit 2026-08-26 : cas réel Klark AI, appliqué à
    tort directement à l'ingestion (``Services aux entreprises`` sur le seul
    mot "consulting firm"). Preuve faible désormais : jamais dans
    ``STRONG_EVIDENCE_TYPES``, jamais dans ``PRECEDENCE`` — uniquement du
    contexte pour le LLM final.
    """
    for row in org_cache_rows:
        key = (row.get("Organisation_Key") or "").strip()
        sector = (row.get("Validated_Sector") or "").strip()
        if (
            key
            and row.get("Match_Status") == org_enrichment.MATCHED
            and row.get("Validated_Via") == "official_site"
            and sector in config.SECTORS
            and sector != config.SECTOR_UNKNOWN
        ):
            yield OrganisationSectorEvidence(
                key, row.get("Matched_Name") or row.get("Query_Name") or key, sector,
                EVIDENCE_OFFICIAL_SITE, "MEDIUM",
                source=row.get("Evidence_Source", ""),
                evidence_text=(row.get("Activity_Label") or "")[:400],
                evidence_url=row.get("Evidence_URL", ""),
            )


def _naf_precise_evidence(org_cache_rows: list[dict]):
    for row in org_cache_rows:
        key = (row.get("Organisation_Key") or "").strip()
        if (
            not key
            or row.get("Match_Status") != org_enrichment.MATCHED
            or not (row.get("Company_ID") or "").strip()
            or row.get("Cache_Version") != org_enrichment.ORG_ENRICHMENT_CACHE_VERSION
        ):
            continue
        code = (row.get("Activity_Code") or "").strip()
        sector = precise_naf_sector(code)
        if sector == config.SECTOR_UNKNOWN:
            continue
        organisation = row.get("Matched_Name") or row.get("Query_Name") or key
        yield OrganisationSectorEvidence(
            key, organisation, sector, EVIDENCE_NAF_PRECISE, "HIGH",
            source="registre entreprise",
            evidence_text=f"Activity_Code={code}; Company_ID={row.get('Company_ID', '')}",
            evidence_url=row.get("Evidence_URL", ""),
        )


def _source_activity_evidence(items: list[Item], source_fact_rows: list[dict]):
    """Rapproche la description d'activité d'un secteur de la taxonomie.

    Priorité au rapprochement produit par le LLM d'extraction lui-même
    (Activity_Sector_Match, §audit 2026-08-26) : il lit l'article complet et
    n'est pas sensible à la reformulation d'un run à l'autre, contrairement au
    classificateur déterministe (cas réel : "Distribution de véhicules" ->
    "Distribution automobile" faisait perdre le match d'un run au suivant).
    classify_explicit_activity reste un filet pour les lignes plus anciennes
    sans ce champ, ou pour le petit nombre de formulations très sûres qu'il
    reconnaît déjà — jamais retiré, seulement plus jamais étendu.
    """
    pairs: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for row in source_fact_rows:
        item_id = (row.get("Item_ID") or "").strip()
        description = (row.get("Activity_Description") or "").strip()
        sector_match = (row.get("Activity_Sector_Match") or "").strip()
        if item_id and description:
            pairs[item_id].add((description, sector_match))
    by_id = {item.Item_ID: item for item in items if item.Item_ID}
    for item_id, texts in pairs.items():
        item = by_id.get(item_id)
        if item is None:
            continue
        for text, sector_match in sorted(texts):
            sector = sector_match if sector_match in config.SECTORS else config.SECTOR_UNKNOWN
            if sector == config.SECTOR_UNKNOWN:
                sector = context_sector.classify_explicit_activity(text)
            if sector == config.SECTOR_UNKNOWN:
                continue
            yield OrganisationSectorEvidence(
                item.Organisation_Key, item.Organisation_Raw, sector,
                EVIDENCE_SOURCE_ACTIVITY, "MEDIUM",
                source="source_facts:Activity_Description", evidence_text=text,
                item_id=item.Item_ID,
            )


def _domain_page_evidence(domain_page_rows: list[dict]):
    """Relit le cache page officielle (:mod:`cyberwatch.domain_page_sector`).

    Purement offline, comme tous les collecteurs de ce module : le worker a
    déjà fait l'accès réseau et persisté son résultat. Preuve faible
    (``MEDIUM``, hors ``STRONG_EVIDENCE_TYPES``) : le nom d'une organisation
    étant son domaine prouve à qui appartient la page, pas que la
    présentation commerciale qu'on y lit soit une qualification de secteur
    fiable — elle entre donc dans l'arbitrage, elle ne le tranche pas.
    """
    for row in domain_page_rows:
        key = (row.get("Organisation_Key") or "").strip()
        sector = (row.get("Activity_Sector_Match") or "").strip()
        if not key or sector not in config.SECTORS or sector == config.SECTOR_UNKNOWN:
            continue
        yield OrganisationSectorEvidence(
            key, row.get("Organisation", "") or key, sector,
            EVIDENCE_DOMAIN_PAGE, "MEDIUM",
            source=f"domain_page:{row.get('Extraction_Source', '')}" if row.get("Extraction_Source") else "domain_page",
            evidence_text=(row.get("Activity_Description") or row.get("Page_Description") or row.get("Page_Title") or ""),
            evidence_url=row.get("URL", ""),
        )


def _llm_organisation_evidence(llm_cache_rows: list[dict]):
    """Relit le cache LLM organisationnel (P1) déjà persisté sur disque.

    Purement offline : aucune décision ici ne déclenche un appel réseau. Un
    candidat LLM n'est jamais, à lui seul, une preuve forte (§19 du plan) :
    il n'entre donc jamais dans ``STRONG_EVIDENCE_TYPES``.
    """
    for row in llm_cache_rows:
        key = (row.get("Organisation_Key") or "").strip()
        sector = (row.get("Sector") or "").strip()
        if not key or sector not in config.SECTORS or sector == config.SECTOR_UNKNOWN:
            continue
        yield OrganisationSectorEvidence(
            key, row.get("Organisation", "") or key, sector,
            EVIDENCE_LLM_ORGANISATION, row.get("Confidence", ""),
            source=f"llm:{row.get('Model', '')}",
            evidence_text=row.get("Reason", ""),
        )


def _validated_item_evidence(items: list[Item], previous_provenance: list[dict]):
    """Reconstitue le canal ``validated_org_sector`` (§5) : un item déjà
    validé par un mécanisme fort et retrouvé inchangé devient une preuve
    forte pour les autres items de la même organisation. Jamais une valeur
    Sector courante n'est acceptée sans remonter à sa provenance d'origine.
    """
    strong_by_item: dict[str, tuple[str, str]] = {}
    for row in previous_provenance:
        if (
            row.get("Field") != "Sector"
            or row.get("Decision") != "APPLIED"
            or row.get("Origin") not in _STRONG_ITEM_ORIGINS
        ):
            continue
        item_id = (row.get("Item_ID") or "").strip()
        final = (row.get("Final_Value") or "").strip()
        if item_id and final:
            strong_by_item[item_id] = (final, row.get("Origin", ""))

    for item in items:
        info = strong_by_item.get(item.Item_ID)
        if info is None:
            continue
        sector, origin = info
        if sector not in config.SECTORS or sector == config.SECTOR_UNKNOWN or item.Sector != sector:
            continue
        yield OrganisationSectorEvidence(
            item.Organisation_Key, item.Organisation_Raw, sector,
            EVIDENCE_VALIDATED_ITEM, "HIGH",
            source=f"item:{origin}",
            evidence_text=f"item {item.Item_ID} déjà validé via {origin}",
            item_id=item.Item_ID,
        )


def collect_organisation_evidence(
    items: list[Item],
    *,
    reference: dict,
    source_fact_rows: list[dict] | None = None,
    org_cache_rows: list[dict] | None = None,
    previous_provenance: list[dict] | None = None,
    llm_cache_rows: list[dict] | None = None,
    domain_page_rows: list[dict] | None = None,
    policy: dict | None = None,
) -> dict[str, list[OrganisationSectorEvidence]]:
    """Agrège toutes les preuves connues, groupées par ``Organisation_Key``.

    Chaque type de preuve conserve sa provenance d'origine ; aucune preuve
    n'est jamais fabriquée depuis une décision précédente de ce module. La
    lecture du cache LLM (``llm_cache_rows``) est toujours locale : ce module
    ne déclenche jamais lui-même d'appel réseau ou LLM (P0 comme P1 relu).
    """
    source_fact_rows = source_fact_rows if source_fact_rows is not None else store.read_csv(store.SOURCE_FACTS_CSV)
    org_cache_rows = org_cache_rows if org_cache_rows is not None else store.load_org_enrichment_cache()
    previous_provenance = previous_provenance or []
    llm_cache_rows = llm_cache_rows if llm_cache_rows is not None else store.read_csv(_aux_path(LLM_CACHE_CSV))
    if domain_page_rows is None:
        domain_page_rows = store.read_csv(_aux_path(DOMAIN_PAGE_CACHE_CSV))
    policy = policy or sector_registry.load_policy()

    present_keys = {sector_organisation_key(item) for item in items if sector_organisation_key(item)}
    reference_keys = present_keys | {item.Organisation_Key for item in items if item.Organisation_Key}
    grouped: dict[str, list[OrganisationSectorEvidence]] = defaultdict(list)
    seen: set[tuple] = set()

    def _add(evidence: OrganisationSectorEvidence) -> None:
        canonical_key = org_identity.effective_organisation_key(
            evidence.organisation, evidence.organisation_key,
        )
        if canonical_key not in present_keys:
            return
        if canonical_key != evidence.organisation_key:
            evidence = replace(evidence, organisation_key=canonical_key)
        marker = (
            evidence.organisation_key, evidence.sector, evidence.evidence_type,
            evidence.source, evidence.item_id, evidence.evidence_url, evidence.evidence_text,
        )
        if marker in seen:
            return
        seen.add(marker)
        grouped[evidence.organisation_key].append(evidence)

    collectors = (
        _manual_reference_evidence(reference, reference_keys),
        _structured_source_evidence(items, source_fact_rows, policy),
        _watchlist_evidence(items),
        _safe_name_evidence(items),
        _official_subject_activity_evidence(items, org_cache_rows),
        _official_site_evidence(org_cache_rows),
        _naf_precise_evidence(org_cache_rows),
        _source_activity_evidence(items, source_fact_rows),
        _domain_page_evidence(domain_page_rows),
        _llm_organisation_evidence(llm_cache_rows),
    )
    for collector in collectors:
        for evidence in collector:
            _add(evidence)

    return {
        key: sorted(
            values,
            key=lambda e: (e.evidence_type, e.sector, e.source, e.evidence_text, e.evidence_url, e.item_id),
        )
        for key, values in grouped.items()
    }


# --------------------------------------------------------------------------
# Arbitrage (§9, §20 à §23 du plan)
# --------------------------------------------------------------------------


#: Ordre de préséance (audit 2026-08-26, refonte "preuves partout, décision
#: unique à la fin"). Réduit à 3 types depuis le revirement précédent :
#: ``manual_reference``/``naf_precise_v2`` restent deux autorités qui
#: court-circuitent tout le reste (aucun appel LLM, comportement inchangé).
#: Tous les autres types de preuve (structured_source, safe_name,
#: official_subject_activity, source_activity, domain_page, official_site)
#: NE sont PLUS dans cette liste : ils ne décident plus jamais seuls, ils ne
#: font qu'alimenter le contexte transmis au LLM organisationnel
#: (:mod:`cyberwatch.organisation_sector_llm`), devenu une étape obligatoire
#: de ``qualify()``. ``llm_organisation`` reste en 3e position : après son
#: passage obligatoire, sa réponse (dernier recours, jamais une preuve
#: forte : confidence toujours LOW) devient la décision pour toute
#: organisation qu'aucune des deux autorités n'a su résoudre. Une
#: contradiction interne à un même type reste un CONFLICT, jamais arbitrée
#: silencieusement ; le déterminisme est préservé (fonction pure de la
#: préséance déclarée ici, jamais de l'ordre d'arrivée des preuves).
PRECEDENCE: tuple[str, ...] = (
    EVIDENCE_MANUAL_REFERENCE,
    EVIDENCE_NAF_PRECISE,
    EVIDENCE_LLM_ORGANISATION,
)


def _build_decision(
    organisation_key: str,
    organisation: str,
    status: str,
    sector: str,
    conflicting_sectors: tuple[str, ...],
    evidence_list: list[OrganisationSectorEvidence],
    *,
    confidence: str = "",
    winning_evidence_type: str = "",
) -> OrganisationSectorDecision:
    evidence_types = tuple(sorted({e.evidence_type for e in evidence_list}))
    evidence_strings = tuple(_evidence_string(e) for e in evidence_list)
    evidence_ids = tuple(_evidence_id(e) for e in evidence_list)
    return OrganisationSectorDecision(
        organisation_key, organisation, sector, status, confidence,
        evidence_types, len(evidence_list), evidence_strings, conflicting_sectors,
        winning_evidence_type, evidence_ids,
    )


def resolve_organisation_sector(
    organisation_key: str,
    organisation: str,
    evidence_list: list[OrganisationSectorEvidence],
) -> OrganisationSectorDecision:
    """Résout un secteur pour une organisation à partir de ses preuves.

    Fonction pure, indépendante de l'ordre de ``evidence_list`` : le tri est
    effectué en interne pour que la sortie ne dépende jamais de l'ordre
    d'entrée (déterminisme requis par §9, §30). Arbitrage par préséance
    (cf. ``PRECEDENCE`` et le docstring du module) : le premier type présent
    tranche, quel que soit un désaccord d'un type moins prioritaire.
    """
    ordered = sorted(
        evidence_list,
        key=lambda e: (e.evidence_type, e.sector, e.source, e.evidence_text, e.evidence_url, e.item_id),
    )
    if not ordered:
        return _build_decision(
            organisation_key, organisation, STATUS_UNKNOWN, config.SECTOR_UNKNOWN, (), ordered,
        )

    by_type: dict[str, list[OrganisationSectorEvidence]] = defaultdict(list)
    for e in ordered:
        by_type[e.evidence_type].append(e)

    for evidence_type in PRECEDENCE:
        candidates = by_type.get(evidence_type)
        if not candidates:
            continue
        sectors_at_type = sorted({e.sector for e in candidates})
        if len(sectors_at_type) > 1:
            # Contradiction interne au type le plus prioritaire présent :
            # jamais arbitrée silencieusement, jamais résolue en redescendant
            # vers un type moins prioritaire même unanime.
            return _build_decision(
                organisation_key, organisation, STATUS_CONFLICT, config.SECTOR_UNKNOWN,
                tuple(sectors_at_type), ordered, winning_evidence_type=evidence_type,
            )
        winning_sector = sectors_at_type[0]
        # Audit 2026-08-26 (revirement de politique, confirmé explicitement) :
        # une proposition faible/LLM seule est désormais appliquée comme les
        # preuves fortes, plutôt que journalisée sans effet (§ancien
        # STATUS_TENTATIVE, retiré). Seule la confiance distingue encore une
        # preuve forte d'un rapprochement LLM.
        status = STATUS_CONFIRMED
        confidence = "HIGH" if evidence_type in STRONG_EVIDENCE_TYPES else "LOW"
        # Types moins prioritaires en désaccord : journalisés pour audit,
        # jamais capables de l'emporter sur le type gagnant.
        losing_sectors = sorted({
            e.sector for e in ordered
            if e.evidence_type != evidence_type and e.sector != winning_sector
        })
        return _build_decision(
            organisation_key, organisation, status, winning_sector,
            tuple(losing_sectors), ordered, confidence=confidence,
            winning_evidence_type=evidence_type,
        )

    # Garde défensive : un evidence_type absent de PRECEDENCE ne devrait
    # jamais exister en pratique (tous les collecteurs de ce module émettent
    # un type listé ci-dessus).
    return _build_decision(
        organisation_key, organisation, STATUS_UNKNOWN, config.SECTOR_UNKNOWN, (), ordered,
    )


def resolve_all_organisation_sectors(
    items: list[Item],
    *,
    reference: dict,
    source_fact_rows: list[dict] | None = None,
    org_cache_rows: list[dict] | None = None,
    previous_provenance: list[dict] | None = None,
    llm_cache_rows: list[dict] | None = None,
    domain_page_rows: list[dict] | None = None,
    policy: dict | None = None,
) -> dict[str, OrganisationSectorDecision]:
    evidence_by_org = collect_organisation_evidence(
        items,
        reference=reference,
        source_fact_rows=source_fact_rows,
        org_cache_rows=org_cache_rows,
        previous_provenance=previous_provenance,
        llm_cache_rows=llm_cache_rows,
        domain_page_rows=domain_page_rows,
        policy=policy,
    )
    display = display_names(items)
    keys = sorted(set(evidence_by_org) | set(display))
    decisions: dict[str, OrganisationSectorDecision] = {}
    for key in keys:
        organisation = display.get(key, key)
        decisions[key] = resolve_organisation_sector(key, organisation, evidence_by_org.get(key, []))
    return decisions


# --------------------------------------------------------------------------
# Application aux items et provenance (§10 du plan)
# --------------------------------------------------------------------------


def restore_organisation_sector_applications(items: list[Item], previous_provenance: list[dict]) -> int:
    """Réinitialise avant recalcul les items mutés par ce module (anti-boucle)."""
    by_id = {item.Item_ID: item for item in items if item.Item_ID}
    restored = 0
    for row in previous_provenance:
        if (
            row.get("Field") != "Sector"
            or row.get("Decision") != "APPLIED"
            or row.get("Origin") not in (ORIGIN, ORIGIN_LLM)
        ):
            continue
        item = by_id.get(row.get("Item_ID", ""))
        if item is None:
            continue
        final = row.get("Final_Value", "")
        previous = row.get("Previous_Value") or config.SECTOR_UNKNOWN
        if final and item.Sector == final:
            item.Sector = previous
            restored += 1
    return restored


def apply_organisation_sector_decisions(
    items: list[Item],
    decisions: dict[str, OrganisationSectorDecision],
) -> tuple[int, list[dict]]:
    """Applique la décision organisationnelle à tous les items concernés.

    Ce résolveur est l'unique écrivain final de ``Item.Sector``. Une valeur
    historique ou préremplie ne protège donc plus une ancienne erreur.
    """
    changed = 0
    provenance: list[dict] = []
    for item in items:
        decision = decisions.get(sector_organisation_key(item))
        if decision is None or decision.status != STATUS_CONFIRMED:
            continue
        if item.Sector == decision.sector:
            continue
        previous = item.Sector
        item.Sector = decision.sector
        changed += 1
        origin = ORIGIN_LLM if decision.winning_evidence_type == EVIDENCE_LLM_ORGANISATION else ORIGIN
        provenance.append({
            "Item_ID": item.Item_ID,
            "Source_ID": item.Source_ID,
            "Field": "Sector",
            "Previous_Value": previous,
            "Candidate_Value": decision.sector,
            "Final_Value": decision.sector,
            "Origin": origin,
            "Confidence": decision.confidence or "HIGH",
            "Evidence": " | ".join(decision.evidence)[:2000],
            "Match_Strategy": "organisation_key_exact+organisation_sector_resolver",
            "Decision": "APPLIED",
        })
    provenance.sort(key=lambda row: (row["Item_ID"], row["Field"], row["Decision"]))
    return changed, provenance


def evidence_audit_rows(
    items: list[Item],
    evidence_by_org: dict[str, list[OrganisationSectorEvidence]],
    *,
    org_cache_rows: list[dict] | None = None,
    domain_page_rows: list[dict] | None = None,
    llm_outcomes: dict[str, str] | None = None,
) -> list[dict[str, str]]:
    """Matérialise une ligne par preuve et par étape sans résultat."""
    display = display_names(items)
    org_cache_by_key = {}
    for row in org_cache_rows or []:
        key = org_identity.effective_organisation_key(
            row.get("Matched_Name") or row.get("Query_Name") or "",
            row.get("Organisation_Key", ""),
        )
        if key:
            org_cache_by_key[key] = row
    domain_by_key = {}
    for row in domain_page_rows or []:
        key = org_identity.effective_organisation_key(
            row.get("Organisation", ""), row.get("Organisation_Key", ""),
        )
        if key:
            domain_by_key[key] = row
    llm_outcomes = llm_outcomes or {}

    def missing_outcome(key: str, evidence_type: str) -> str:
        if evidence_type == EVIDENCE_LLM_ORGANISATION:
            return llm_outcomes.get(key, "NO_MATCH")
        if evidence_type == EVIDENCE_WATCHLIST_HINT:
            return "NOT_APPLICABLE"
        if evidence_type == EVIDENCE_DOMAIN_PAGE:
            if not re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+", display[key].casefold().rstrip(".")):
                return "NOT_APPLICABLE"
            status = (domain_by_key.get(key) or {}).get("Status", "")
            return "ERROR" if status == "UNREACHABLE" else "NO_MATCH"
        if evidence_type in {
            EVIDENCE_NAF_PRECISE, EVIDENCE_OFFICIAL_SUBJECT_ACTIVITY,
            EVIDENCE_OFFICIAL_SITE,
        }:
            status = (org_cache_by_key.get(key) or {}).get("Match_Status", "")
            return "ERROR" if status == org_enrichment.ERROR else "NO_MATCH"
        return "NO_MATCH"

    rows: list[dict[str, str]] = []
    for key in sorted(display):
        by_type: dict[str, list[OrganisationSectorEvidence]] = defaultdict(list)
        for evidence in evidence_by_org.get(key, []):
            by_type[evidence.evidence_type].append(evidence)
        for evidence_type in AUDITED_EVIDENCE_TYPES:
            values = by_type.get(evidence_type, [])
            if not values:
                outcome = missing_outcome(key, evidence_type)
                raw_id = f"{key}|{evidence_type}|{outcome}"
                rows.append({
                    "Evidence_ID": hashlib.sha256(raw_id.encode("utf-8")).hexdigest()[:24],
                    "Organisation_Key": key,
                    "Organisation": display[key],
                    "Item_ID": "",
                    "Evidence_Type": evidence_type,
                    "Producer": evidence_type,
                    "Outcome": outcome,
                    "Candidate_Sector": "",
                    "Confidence": "",
                    "Authority": "",
                    "Source": "",
                    "Evidence_Text": "",
                    "Evidence_URL": "",
                })
                continue
            for evidence in values:
                authority = (
                    "MANUAL" if evidence.evidence_type == EVIDENCE_MANUAL_REFERENCE
                    else "NAF" if evidence.evidence_type == EVIDENCE_NAF_PRECISE
                    else ""
                )
                rows.append({
                    "Evidence_ID": _evidence_id(evidence),
                    "Organisation_Key": key,
                    "Organisation": display[key],
                    "Item_ID": evidence.item_id,
                    "Evidence_Type": evidence.evidence_type,
                    "Producer": evidence.evidence_type,
                    "Outcome": "PRODUCED",
                    "Candidate_Sector": evidence.sector,
                    "Confidence": evidence.confidence,
                    "Authority": authority,
                    "Source": evidence.source,
                    "Evidence_Text": evidence.evidence_text,
                    "Evidence_URL": evidence.evidence_url,
                })
    return rows


def write_evidence_csv(rows: list[dict], *, path: Path | None = None) -> None:
    store.write_csv(path or _aux_path(EVIDENCE_CSV), EVIDENCE_COLUMNS, rows)


def write_decisions_csv(
    decisions: dict[str, OrganisationSectorDecision],
    *,
    updated_at: str = "",
    path: Path | None = None,
) -> None:
    rows = [decisions[key].to_row(updated_at=updated_at) for key in sorted(decisions)]
    store.write_csv(path or _aux_path(DECISIONS_CSV), DECISIONS_COLUMNS, rows)


def load_decisions_csv(path: Path | None = None) -> list[dict]:
    return store.read_csv(path or _aux_path(DECISIONS_CSV))


def summary(decisions: dict[str, OrganisationSectorDecision]) -> dict:
    """Métriques d'observabilité (§35 du plan).

    Les sous-canaux ``sector_resolved_by_*`` distinguent, parmi les
    organisations ``CONFIRMED``, celles qui n'ont convergé qu'avec le
    candidat LLM (``llm_consensus``) des autres, résolues sans lui.

    ``sector_winning_evidence_type`` (audit 2026-08-26, arbitrage par
    préséance) donne, pour tout le run, le décompte par type de preuve
    *gagnant* (celui qui a réellement tranché, cf. ``PRECEDENCE``) parmi les
    décisions CONFIRMED — la vue qui répond directement à « quel canal
    contribue vraiment » sans relire le code.
    """
    counts = Counter(decision.status for decision in decisions.values())
    confirmed = [d for d in decisions.values() if d.status == STATUS_CONFIRMED]
    resolved_by_validated_org = sum(
        EVIDENCE_VALIDATED_ITEM in d.evidence_types for d in confirmed
    )
    resolved_by_naf_v2 = sum(EVIDENCE_NAF_PRECISE in d.evidence_types for d in confirmed)
    resolved_by_llm_consensus = sum(
        EVIDENCE_LLM_ORGANISATION in d.evidence_types for d in confirmed
    )
    winning_type_counts = Counter(
        decision.winning_evidence_type
        for decision in decisions.values()
        if decision.status == STATUS_CONFIRMED and decision.winning_evidence_type
    )
    result = {
        "organisation_sector_total": len(decisions),
        "organisation_sector_confirmed": counts.get(STATUS_CONFIRMED, 0),
        "organisation_sector_conflict": counts.get(STATUS_CONFLICT, 0),
        "organisation_sector_unknown": counts.get(STATUS_UNKNOWN, 0),
        "sector_resolved_by_validated_org": resolved_by_validated_org,
        "sector_resolved_by_naf_v2": resolved_by_naf_v2,
        "sector_resolved_by_llm_consensus": resolved_by_llm_consensus,
    }
    # Compteur par type de preuve gagnant, une clé plate par type (jamais un
    # dict imbriqué : `changes` reste un `dict[str, int]` partout ailleurs).
    for evidence_type in PRECEDENCE:
        result[f"sector_won_by_{evidence_type}"] = winning_type_counts.get(evidence_type, 0)
    return result
