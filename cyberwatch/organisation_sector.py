"""Résolution organisationnelle du secteur (Sector) — P0.

``Sector`` décrit l'activité principale de l'organisation victime. Il ne décrit
ni la nature des données volées, ni le contexte de l'incident.

Ce module résout ``Sector`` au niveau ``Organisation_Key``, à partir des
preuves déjà collectées ailleurs dans Cyberwatch (référentiel manuel, sources
structurées, cache d'enrichissement entreprise, provenance de qualification).
Aucun accès réseau, aucun LLM : le complément par LLM organisationnel (P1) vit
dans :mod:`cyberwatch.organisation_sector_llm` et n'alimente ce resolver que
via une preuve explicite ``llm_organisation``, jamais suffisante seule.

Statuts possibles :

    CONFIRMED   suffisamment prouvé pour renseigner Item.Sector
    TENTATIVE   candidat crédible mais non confirmé (alimente sector_tentative)
    CONFLICT    preuves fortes contradictoires
    UNKNOWN     aucune conclusion exploitable

Règle d'arbitrage (déterministe, indépendante de l'ordre des candidats) :

    - une seule preuve forte                      -> CONFIRMED
    - plusieurs preuves fortes convergentes        -> CONFIRMED
    - plusieurs preuves fortes contradictoires      -> CONFLICT (jamais tranché
      par majorité, par confiance LLM ou par ordre d'arrivée)
    - uniquement des preuves faibles / LLM seul     -> TENTATIVE si un candidat
      unique se dégage, sinon UNKNOWN
    - candidats faibles/LLM contradictoires entre eux -> CONFLICT

Anti-bouclage : une décision appliquée par ce module (``Origin`` égal à
``ORIGIN`` ou ``ORIGIN_LLM`` dans ``qualification_provenance.csv``) n'est
jamais relue comme preuve primaire. ``restore_organisation_sector_applications``
réinitialise les items concernés avant toute nouvelle collecte, exactement
comme :func:`cyberwatch.sector_registry.restore_registry_applications`.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

from . import (
    company_subject_evidence,
    config,
    context_sector,
    org_enrichment,
    sector as sector_policy,
    sector_registry,
    store,
)
from .model import Item

STATUS_CONFIRMED = "CONFIRMED"
STATUS_TENTATIVE = "TENTATIVE"
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
    "Decision_Origin", "Updated_At",
]

#: Cache du candidat LLM organisationnel (P1, cf. organisation_sector_llm.py).
#: Toujours lu hors-ligne : ce module ne déclenche jamais d'appel réseau.
LLM_CACHE_CSV = store.DATA_DIR / "organisation_sector_llm.csv"

EVIDENCE_MANUAL_REFERENCE = "manual_reference"
EVIDENCE_STRUCTURED_SOURCE = "structured_source"
EVIDENCE_SAFE_NAME = "safe_name"
EVIDENCE_OFFICIAL_SUBJECT_ACTIVITY = "official_subject_activity"
EVIDENCE_NAF_PRECISE = "naf_precise_v2"
EVIDENCE_VALIDATED_ITEM = "validated_item"
EVIDENCE_SOURCE_ACTIVITY = "source_activity"
EVIDENCE_LLM_ORGANISATION = "llm_organisation"

#: Types de preuve suffisamment sûrs pour, seuls, confirmer ou mettre en
#: conflit une organisation (§5/§9 du plan). ``structured_source`` n'y entre
#: que si son sous-canal est explicitement activé par la politique partagée
#: de :mod:`cyberwatch.sector_registry` (aucune politique parallèle créée).
STRONG_EVIDENCE_TYPES = frozenset({
    EVIDENCE_MANUAL_REFERENCE,
    EVIDENCE_SAFE_NAME,
    EVIDENCE_OFFICIAL_SUBJECT_ACTIVITY,
    EVIDENCE_NAF_PRECISE,
    EVIDENCE_VALIDATED_ITEM,
    EVIDENCE_STRUCTURED_SOURCE,
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
    "LLM_SOURCE_FALLBACK",
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

    def to_row(self, *, updated_at: str = "") -> dict:
        origin = ORIGIN_LLM if EVIDENCE_LLM_ORGANISATION in self.evidence_types else ORIGIN
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


def _display_names(items: list[Item]) -> dict[str, str]:
    counters: dict[str, Counter] = defaultdict(Counter)
    for item in items:
        if item.Organisation_Key and item.Organisation_Raw:
            counters[item.Organisation_Key][item.Organisation_Raw] += 1
    return {
        key: sorted(counter.items(), key=lambda pair: (-pair[1], pair[0]))[0][0]
        for key, counter in counters.items()
    }


# --------------------------------------------------------------------------
# Collecte des preuves (§4 du plan)
# --------------------------------------------------------------------------


def _manual_reference_evidence(reference: dict):
    for key, entry in reference.items():
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


def _structured_source_evidence(items: list[Item], source_fact_rows: list[dict], policy: dict):
    if not sector_registry.channel_enabled(EVIDENCE_STRUCTURED_SOURCE, policy):
        return
    by_id = {item.Item_ID: item for item in items if item.Item_ID}
    for row in source_fact_rows:
        if row.get("Source_ID") != "RANSOMWARE_LIVE":
            continue
        item = by_id.get((row.get("Item_ID") or "").strip())
        if item is None:
            continue
        raw = (row.get("Source_Sector_Raw") or "").strip()
        sector = sector_policy.classify_source_sector(raw)
        if sector == config.SECTOR_UNKNOWN:
            continue
        yield OrganisationSectorEvidence(
            item.Organisation_Key, item.Organisation_Raw, sector,
            EVIDENCE_STRUCTURED_SOURCE, "HIGH",
            source="ransomware.live:sector", evidence_text=raw,
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


def _naf_precise_evidence(org_cache_rows: list[dict]):
    for row in org_cache_rows:
        key = (row.get("Organisation_Key") or "").strip()
        if not key:
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
    descriptions: dict[str, set[str]] = defaultdict(set)
    for row in source_fact_rows:
        item_id = (row.get("Item_ID") or "").strip()
        description = (row.get("Activity_Description") or "").strip()
        if item_id and description:
            descriptions[item_id].add(description)
    by_id = {item.Item_ID: item for item in items if item.Item_ID}
    for item_id, texts in descriptions.items():
        item = by_id.get(item_id)
        if item is None:
            continue
        for text in sorted(texts):
            sector = context_sector.classify_explicit_activity(text)
            if sector == config.SECTOR_UNKNOWN:
                continue
            yield OrganisationSectorEvidence(
                item.Organisation_Key, item.Organisation_Raw, sector,
                EVIDENCE_SOURCE_ACTIVITY, "MEDIUM",
                source="source_facts:Activity_Description", evidence_text=text,
                item_id=item.Item_ID,
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
    policy = policy or sector_registry.load_policy()

    grouped: dict[str, list[OrganisationSectorEvidence]] = defaultdict(list)
    seen: set[tuple] = set()

    def _add(evidence: OrganisationSectorEvidence) -> None:
        marker = (
            evidence.organisation_key, evidence.sector, evidence.evidence_type,
            evidence.source, evidence.item_id, evidence.evidence_url, evidence.evidence_text,
        )
        if marker in seen:
            return
        seen.add(marker)
        grouped[evidence.organisation_key].append(evidence)

    collectors = (
        _manual_reference_evidence(reference),
        _structured_source_evidence(items, source_fact_rows, policy),
        _safe_name_evidence(items),
        _official_subject_activity_evidence(items, org_cache_rows),
        _naf_precise_evidence(org_cache_rows),
        _source_activity_evidence(items, source_fact_rows),
        _validated_item_evidence(items, previous_provenance),
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


def _build_decision(
    organisation_key: str,
    organisation: str,
    status: str,
    sector: str,
    conflicting_sectors: tuple[str, ...],
    evidence_list: list[OrganisationSectorEvidence],
    *,
    confidence: str = "",
) -> OrganisationSectorDecision:
    evidence_types = tuple(sorted({e.evidence_type for e in evidence_list}))
    evidence_strings = tuple(_evidence_string(e) for e in evidence_list)
    return OrganisationSectorDecision(
        organisation_key, organisation, sector, status, confidence,
        evidence_types, len(evidence_list), evidence_strings, conflicting_sectors,
    )


def resolve_organisation_sector(
    organisation_key: str,
    organisation: str,
    evidence_list: list[OrganisationSectorEvidence],
) -> OrganisationSectorDecision:
    """Résout un secteur pour une organisation à partir de ses preuves.

    Fonction pure, indépendante de l'ordre de ``evidence_list`` : le tri est
    effectué en interne pour que la sortie ne dépende jamais de l'ordre
    d'entrée (déterminisme requis par §9, §30).
    """
    ordered = sorted(
        evidence_list,
        key=lambda e: (e.evidence_type, e.sector, e.source, e.evidence_text, e.evidence_url, e.item_id),
    )
    strong = [e for e in ordered if e.evidence_type in STRONG_EVIDENCE_TYPES]
    llm = [e for e in ordered if e.evidence_type == EVIDENCE_LLM_ORGANISATION]
    weak = [
        e for e in ordered
        if e.evidence_type not in STRONG_EVIDENCE_TYPES and e.evidence_type != EVIDENCE_LLM_ORGANISATION
    ]
    strong_sectors = sorted({e.sector for e in strong})

    if len(strong_sectors) > 1:
        # Un conflit fort n'est jamais tranché par majorité, ordre ou LLM.
        return _build_decision(
            organisation_key, organisation, STATUS_CONFLICT, config.SECTOR_UNKNOWN,
            tuple(strong_sectors), ordered,
        )

    if len(strong_sectors) == 1:
        # Une preuve forte confirme, seule ou convergente ; un candidat LLM
        # contradictoire est journalisé mais ne peut jamais l'emporter.
        confirmed = strong_sectors[0]
        annotated = ordered
        if llm and any(e.sector != confirmed for e in llm):
            annotated = ordered + [
                OrganisationSectorEvidence(
                    organisation_key, organisation, confirmed,
                    "LLM_CONFLICT_WITH_CONFIRMED", "",
                    evidence_text=f"LLM proposait {sorted({e.sector for e in llm})}",
                )
            ]
        return _build_decision(
            organisation_key, organisation, STATUS_CONFIRMED, confirmed, (), annotated,
            confidence="HIGH",
        )

    # Aucune preuve forte indépendante : le LLM ne peut jamais suffire seul.
    candidate_sectors = sorted({e.sector for e in llm} | {e.sector for e in weak})
    if len(candidate_sectors) == 1:
        if not llm:
            # Signal faible seul, sans LLM : §9 Cas 4 -> Inconnu à ce stade.
            return _build_decision(
                organisation_key, organisation, STATUS_UNKNOWN, config.SECTOR_UNKNOWN, (), ordered,
            )
        return _build_decision(
            organisation_key, organisation, STATUS_TENTATIVE, candidate_sectors[0], (), ordered,
            confidence="LOW",
        )
    if len(candidate_sectors) > 1:
        return _build_decision(
            organisation_key, organisation, STATUS_CONFLICT, config.SECTOR_UNKNOWN,
            tuple(candidate_sectors), ordered,
        )
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
    policy: dict | None = None,
) -> dict[str, OrganisationSectorDecision]:
    evidence_by_org = collect_organisation_evidence(
        items,
        reference=reference,
        source_fact_rows=source_fact_rows,
        org_cache_rows=org_cache_rows,
        previous_provenance=previous_provenance,
        llm_cache_rows=llm_cache_rows,
        policy=policy,
    )
    display = _display_names(items)
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
    """Applique uniquement les décisions ``CONFIRMED`` aux items ``Inconnu``.

    Un secteur canonique déjà connu n'est jamais écrasé par un signal plus
    faible ; seuls les items encore ``Inconnu`` sont mutés.
    """
    changed = 0
    provenance: list[dict] = []
    for item in items:
        decision = decisions.get(item.Organisation_Key)
        if decision is None or decision.status != STATUS_CONFIRMED:
            continue
        if item.Sector != config.SECTOR_UNKNOWN:
            continue
        previous = item.Sector
        item.Sector = decision.sector
        changed += 1
        origin = ORIGIN_LLM if EVIDENCE_LLM_ORGANISATION in decision.evidence_types else ORIGIN
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


def tentative_provenance(
    items: list[Item],
    decisions: dict[str, OrganisationSectorDecision],
) -> list[dict]:
    """Journalise les candidats ``TENTATIVE`` pour le mécanisme existant
    ``sector_tentative`` (§21/§37) : réutilise la même liste blanche de
    ``Decision`` que :func:`cyberwatch.site_legacy._qualification_provenance_by_incident`,
    sans ajouter de seconde mécanique d'affichage.
    """
    rows: list[dict] = []
    for item in items:
        decision = decisions.get(item.Organisation_Key)
        if decision is None or decision.status != STATUS_TENTATIVE or item.Sector != config.SECTOR_UNKNOWN:
            continue
        rows.append({
            "Item_ID": item.Item_ID,
            "Source_ID": item.Source_ID,
            "Field": "Sector",
            "Previous_Value": item.Sector,
            "Candidate_Value": decision.sector,
            "Final_Value": "",
            "Origin": ORIGIN_LLM,
            "Confidence": decision.confidence,
            "Evidence": " | ".join(decision.evidence)[:2000],
            "Match_Strategy": "organisation_key_exact+organisation_sector_resolver",
            "Decision": "REJECTED_NO_STRONG_EVIDENCE",
        })
    rows.sort(key=lambda row: (row["Item_ID"], row["Field"], row["Decision"]))
    return rows


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
    counts = Counter(decision.status for decision in decisions.values())
    return {
        "organisation_sector_total": len(decisions),
        "organisation_sector_confirmed": counts.get(STATUS_CONFIRMED, 0),
        "organisation_sector_tentative": counts.get(STATUS_TENTATIVE, 0),
        "organisation_sector_conflict": counts.get(STATUS_CONFLICT, 0),
        "organisation_sector_unknown": counts.get(STATUS_UNKNOWN, 0),
    }
