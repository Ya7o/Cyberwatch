"""Phase canonique, offline et idempotente de qualification d'un snapshot."""

from __future__ import annotations

from dataclasses import dataclass

from . import config, enrichment, identity, source_llm_fallback, store
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


def qualify(items: list[Item]) -> QualificationReport:
    """Applique la qualification canonique puis les fallbacks source gardés.

    Les secteurs historiquement injectés par l'ancien fallback sont d'abord
    restaurés à ``Inconnu`` à partir de leur provenance, mais uniquement si la
    valeur courante est encore exactement celle qui avait été injectée. Ils
    repassent ensuite dans les enrichissements canoniques et le garde Sector
    courant. Une correction ultérieure différente reste donc protégée.

    Le pipeline canonique ne contient aucune correction manuelle par ``Item_ID``.
    La couche challenger peut uniquement compléter des valeurs encore ``Inconnu``
    et les exports LLM ne peuvent jamais modifier ``Threat``.
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
    changes["threat_stabilized"] = stabilize_threats(ordered)

    llm_changes, provenance = source_llm_fallback.apply_source_llm_fallback(ordered)
    changes.update(llm_changes)

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
