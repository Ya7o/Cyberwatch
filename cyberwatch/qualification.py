"""Phase canonique, offline et idempotente de qualification d'un snapshot."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from . import config, enrichment, identity, sector as sector_policy, source_llm_fallback, store
from .dedup import build_incidents_with_registry
from .model import Incident, Item
from .sector_fallback_migration import restore_legacy_sector_fallbacks


# Politique Threat minimale de stabilisation. Elle reste ici, au point de
# convergence CREATE/MAJ/REPLAY, pour éviter des exceptions dispersées dans les
# collecteurs et garantir qu'un REPLAY reconstruit exactement la même vérité
# canonique qu'une collecte.
_AUTHORITATIVE_NATIVE_THREAT_SOURCES = frozenset({"VEILLE_LLM"})
_AUTHORITATIVE_DEFAULT_THREATS = {
    "RANSOMWARE_LIVE": config.THREAT_RANSOMWARE,
}
_SOURCE_SCOPE_THREATS = {
    "FRENCHBREACHES": config.THREAT_LEAK,
    "BONJOURLAFUITE": config.THREAT_LEAK,
}
_STRONG_SOURCE_SCOPE_OVERRIDES = frozenset({
    config.THREAT_RANSOMWARE,
    config.THREAT_DDOS,
    config.THREAT_MALWARE,
    config.THREAT_ACCOUNT,
    config.THREAT_LEAK,
    config.THREAT_PHISHING,
    config.THREAT_THIRD_PARTY,
})

# Audit 2 / politique v7 : les preuves Sector challengers restent calculées et
# journalisées mais ne sont plus autorisées à modifier la vérité canonique.
# Même après plusieurs gardes (identité, site officiel, activité principale),
# une page de victime peut attribuer une activité à un fournisseur/partenaire.
# Sans résolution du sujet grammatical de la preuve, la précision >=95 % n'est
# pas démontrée ; ``Inconnu`` est donc préférable à une qualification forcée.
_SECTOR_FALLBACK_AUTO_APPLY = False


@dataclass(frozen=True)
class QualificationReport:
    items: list[Item]
    incidents: list[Incident]
    changes: dict[str, int]
    provenance: list[dict[str, str]]
    incident_id_registry: list[dict[str, str]]
    items_hash: str
    incidents_hash: str


def stabilize_threats(items: list[Item]) -> int:
    """Applique la confiance source sans créer de nouvelle heuristique.

    - VEILLE_LLM fournit une menace analytique structurée : sa valeur native,
      y compris ``Inconnu``, fait foi lorsqu'elle appartient à la taxonomie.
    - ransomware.live a un contrat de source univoque : Ransomware fait foi.
    - FrenchBreaches / BonjourLaFuite décrivent par construction des fuites :
      ce contexte de source reste le défaut et un simple signal générique
      (Intrusion/Autre/Inconnu) ne peut pas l'écraser. Seul un signal spécifique
      déjà reconnu par le classifieur déterministe peut le faire.
    """
    changed = 0
    for item in items:
        before = item.Threat

        if item.Source_ID in _AUTHORITATIVE_NATIVE_THREAT_SOURCES:
            native = (item.Threat_Raw or "").strip()
            if native in config.THREATS:
                item.Threat = native

        elif item.Source_ID in _AUTHORITATIVE_DEFAULT_THREATS:
            item.Threat = _AUTHORITATIVE_DEFAULT_THREATS[item.Source_ID]

        elif item.Source_ID in _SOURCE_SCOPE_THREATS:
            scoped = _SOURCE_SCOPE_THREATS[item.Source_ID]
            if item.Threat not in _STRONG_SOURCE_SCOPE_OVERRIDES:
                item.Threat = scoped

        if item.Threat != before:
            changed += 1

    return changed


def backfill_structured_source_sectors(
    items: list[Item], source_fact_rows: list[dict[str, str]] | None = None
) -> int:
    """Réapplique les secteurs structurés déjà archivés dans ``source_facts``.

    Sprint Sector A : les anciens items ransomware.live ne repassent pas par le
    collecteur lors d'un simple ``backfill-unknowns``. Leur champ source
    ``activity/sector/industry`` est pourtant conservé dans ``Source_Sector_Raw``.
    On peut donc profiter d'un mapping taxonomique amélioré sans réseau et sans
    texte libre.

    Garde-fous : source RANSOMWARE_LIVE uniquement, secteur courant Inconnu,
    une seule valeur brute non vide par Item_ID, et mapping fermé vers la
    taxonomie Cyberwatch. Toute ambiguïté reste Inconnu.
    """
    rows = (
        source_fact_rows
        if source_fact_rows is not None
        else store.read_csv(store.SOURCE_FACTS_CSV)
    )
    raw_by_item: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        if row.get("Source_ID") != "RANSOMWARE_LIVE":
            continue
        raw = (row.get("Source_Sector_Raw") or "").strip()
        item_id = (row.get("Item_ID") or "").strip()
        if item_id and raw:
            raw_by_item[item_id].add(raw)

    changed = 0
    for item in items:
        if item.Source_ID != "RANSOMWARE_LIVE" or item.Sector != config.SECTOR_UNKNOWN:
            continue
        raw_values = raw_by_item.get(item.Item_ID, set())
        if len(raw_values) != 1:
            continue
        candidate = sector_policy.classify_source_sector(next(iter(raw_values)))
        if candidate == config.SECTOR_UNKNOWN:
            continue
        item.Sector = candidate
        changed += 1
    return changed


def neutralize_sector_fallback(
    items: list[Item],
    changes: dict[str, int],
    provenance: list[dict[str, str]],
) -> int:
    """Convertit toute application Sector challenger en décision diagnostique.

    ``source_llm_fallback`` continue d'exécuter ses gardes afin de mesurer les
    candidats qui auraient été admissibles et de conserver leurs preuves dans
    la provenance. La phase canonique annule ensuite uniquement les lignes
    Sector réellement ``APPLIED`` : la valeur précédente est restaurée et la
    décision devient ``REJECTED_POLICY_DISABLED``.

    La fonction est déterministe et ne touche ni Location ni Threat.
    """
    if _SECTOR_FALLBACK_AUTO_APPLY:
        return 0

    by_id = {item.Item_ID: item for item in items if item.Item_ID}
    neutralized = 0
    for row in provenance:
        if row.get("Field") != "Sector" or row.get("Decision") != "APPLIED":
            continue
        item = by_id.get(row.get("Item_ID", ""))
        if item is None:
            continue

        previous = row.get("Previous_Value", config.SECTOR_UNKNOWN)
        applied = row.get("Final_Value", "")
        # Ne neutralise que la mutation dont la provenance décrit exactement
        # l'état courant ; une modification extérieure inattendue est protégée.
        if not applied or item.Sector != applied:
            continue

        item.Sector = previous or config.SECTOR_UNKNOWN
        row["Final_Value"] = item.Sector
        row["Confidence"] = ""
        row["Decision"] = "REJECTED_POLICY_DISABLED"
        neutralized += 1

    if neutralized:
        changes["llm_sector_fallback"] = max(
            0, changes.get("llm_sector_fallback", 0) - neutralized
        )
        changes["llm_sector_rejected"] = (
            changes.get("llm_sector_rejected", 0) + neutralized
        )
    changes["llm_sector_policy_rejected"] = neutralized
    provenance.sort(key=lambda row: (row["Item_ID"], row["Field"], row["Decision"]))
    return neutralized


def qualify(items: list[Item]) -> QualificationReport:
    """Applique la qualification canonique puis les challengers source gardés.

    Les secteurs historiquement injectés par l'ancien fallback sont d'abord
    restaurés à ``Inconnu`` à partir de leur provenance, mais uniquement si la
    valeur courante est encore exactement celle qui avait été injectée. Une
    correction ultérieure différente reste donc protégée.

    Les secteurs structurés ransomware.live archivés dans ``source_facts`` sont
    ensuite rejoués avec la table taxonomique courante. Localisation conserve
    son fallback mesuré comme fiable. Threat reste strictement protégé. Sector
    challenger reste diagnostique uniquement : toute mutation ``APPLIED`` est
    annulée avant construction des incidents et hachage du snapshot.

    Le pipeline canonique ne contient aucune correction manuelle par ``Item_ID``.
    """
    ordered = identity.sort_items(items)

    restored = restore_legacy_sector_fallbacks(
        ordered,
        store.load_qualification_provenance(),
    )

    reference = enrichment.load_reference()
    changes = enrichment.enrich_items(ordered, reference)
    changes["llm_sector_restored"] = restored
    changes.update(enrichment.backfill_unknowns(ordered, reference))
    changes["sector_structured_source_backfill"] = backfill_structured_source_sectors(ordered)
    changes["threat_stabilized"] = stabilize_threats(ordered)

    llm_changes, provenance = source_llm_fallback.apply_source_llm_fallback(ordered)
    changes.update(llm_changes)
    neutralize_sector_fallback(ordered, changes, provenance)

    incidents, incident_id_registry = build_incidents_with_registry(
        ordered, store.load_incident_id_registry()
    )
    return QualificationReport(
        items=ordered,
        incidents=incidents,
        changes=changes,
        provenance=provenance,
        incident_id_registry=incident_id_registry,
        items_hash=identity.items_hash(ordered),
        incidents_hash=identity.incidents_hash(incidents),
    )
