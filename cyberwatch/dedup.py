"""Déduplication déterministe, explicable et conservatrice."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass

from . import config
from .identity import incident_id, sort_incidents, sort_items
from .incident_identity import assign_incident_ids, component_identity_key
from .model import Incident, Item
from .normalize import _base_organisation_key, date_or_empty, searchable
from .org_identity import effective_organisation_key


MERGE = "MERGE"
KEEP_SEPARATE = "KEEP_SEPARATE"
NO_DECISION = "NO_DECISION"
PREFERRED_QUALIFICATION_SOURCE = "VEILLE_LLM"

# Un veto explicite ne doit jamais être contourné par l'item d'ancrage d'une
# composante. Les simples écarts de dates ne sont pas des vetos forts : ils
# restent gérés par la décision ancre -> nouvel item afin de ne pas casser les
# corroborations légitimes déjà établies.
STRONG_KEEP_REASON_CODES = frozenset({
    "INCIDENT_KEEP_CONFLICTING_SOURCE_ITEM_ID",
    "INCIDENT_KEEP_CONFLICTING_EVENT_DATE",
    "INCIDENT_KEEP_RECURRENCE_MARKER",
})

# Une URL n'est un identifiant fort que pour une source dont le contrat indique
# qu'elle pointe vers une page/item unique. La règle est volontairement fermée :
# toute nouvelle source doit être ajoutée explicitement après vérification.
UNIQUE_ITEM_URL_SOURCES = frozenset({
    "BONJOURLAFUITE",
    "CYBERATTAQUE_ORG",
    "FRENCHBREACHES",
})

RECURRENCE_MARKERS = (
    "nouvelle cyberattaque", "nouvelle attaque", "nouvelle fuite", "a nouveau",
    "de nouveau", "une nouvelle fois", "frappe une nouvelle fois",
    "deuxieme cyberattaque", "deuxieme attaque", "deuxieme fuite",
    "2eme cyberattaque", "2e cyberattaque", "2eme attaque", "2e attaque",
    "2eme fuite", "2e fuite", "second incident", "new attack", "attacked again",
    "breached again", "another breach", "second attack", "new breach",
)


@dataclass(frozen=True)
class DedupDecision:
    action: str
    reason_code: str
    signals: tuple[str, ...] = ()


def _effective_key(item: Item) -> str:
    """Identité de dédup sans réécrire la clé/Item_ID historique de l'item."""
    return effective_organisation_key(item.Organisation_Raw, item.Organisation_Key)


def _recurrence(item: Item) -> bool:
    blob = searchable(f"{item.Title} {item.Threat_Raw}")
    return any(marker in blob for marker in RECURRENCE_MARKERS)


def _recurrence_boundary(left: Item, right: Item) -> bool:
    """Vrai seulement si l'item le plus récent annonce explicitement une récidive.

    Un marqueur de récidive décrit la relation avec un épisode antérieur ; il
    ne doit pas empêcher deux sources datées du même jour de corroborer ce
    nouvel épisode. La règle reste symétrique : l'ordre des arguments ne change
    pas la décision, seul l'item chronologiquement le plus récent peut ouvrir
    une frontière.
    """
    left_date = date_or_empty(left.best_date)
    right_date = date_or_empty(right.best_date)
    if not left_date or not right_date or left_date == right_date:
        return False
    later = right if right_date > left_date else left
    return _recurrence(later)


def _same_unique_url(left: Item, right: Item) -> bool:
    """Vrai seulement si l'URL est un identifiant d'item pour cette source."""
    return bool(
        left.URL
        and left.URL == right.URL
        and left.Source_ID == right.Source_ID
        and left.Source_ID in UNIQUE_ITEM_URL_SOURCES
    )


def decide_merge(left: Item, right: Item) -> DedupDecision:
    """Décide une fusion paire à paire, sans similarité probabiliste."""
    if left.Source_ID == right.Source_ID and left.Source_Item_ID and right.Source_Item_ID:
        if left.Source_Item_ID == right.Source_Item_ID:
            return DedupDecision(MERGE, "INCIDENT_MERGE_SOURCE_ITEM_ID")
        return DedupDecision(KEEP_SEPARATE, "INCIDENT_KEEP_CONFLICTING_SOURCE_ITEM_ID")

    # Une récidive ouvre une frontière avec un épisode antérieur, mais deux
    # publications du même jour peuvent décrire ce même nouvel épisode.
    if _recurrence_boundary(left, right):
        return DedupDecision(KEEP_SEPARATE, "INCIDENT_KEEP_RECURRENCE_MARKER")

    left_key, right_key = _effective_key(left), _effective_key(right)
    if not left_key or left_key != right_key:
        return DedupDecision(NO_DECISION, "INCIDENT_NO_DECISION")

    # Deux dates d'événement explicites et différentes décrivent deux épisodes
    # distincts. Ce veto est volontairement évalué avant la proximité de date de
    # publication : une publication rapprochée ne doit jamais effacer une
    # contradiction événementielle déjà structurée.
    if left.Event_Date and right.Event_Date and left.Event_Date != right.Event_Date:
        return DedupDecision(
            KEEP_SEPARATE,
            "INCIDENT_KEEP_CONFLICTING_EVENT_DATE",
            (f"left={left.Event_Date}", f"right={right.Event_Date}"),
        )

    left_date, right_date = date_or_empty(left.best_date), date_or_empty(right.best_date)
    if not left_date or not right_date:
        return DedupDecision(NO_DECISION, "INCIDENT_NO_DECISION")

    days = abs((left_date - right_date).days)
    if left.Event_Date and left.Event_Date == right.Event_Date and left.Source_ID != right.Source_ID:
        return DedupDecision(MERGE, "INCIDENT_MERGE_EVENT_DATE", ("event_date",))

    if days <= 3:
        alias_used = (
            _base_organisation_key(left.Organisation_Raw) != left_key
            or _base_organisation_key(right.Organisation_Raw) != right_key
            or left.Organisation_Key != left_key
            or right.Organisation_Key != right_key
        )
        return DedupDecision(
            MERGE,
            "INCIDENT_MERGE_ALIAS" if alias_used else "INCIDENT_MERGE_CANONICAL_NAME",
            (f"days={days}",),
        )

    if days <= config.INCIDENT_GAP_DAYS and _same_unique_url(left, right):
        return DedupDecision(MERGE, "INCIDENT_MERGE_UNIQUE_URL", (f"days={days}",))

    return DedupDecision(KEEP_SEPARATE, "INCIDENT_KEEP_TIME_GAP", (f"days={days}",))


def _has_strong_component_veto(current: list[Item], incoming: Item) -> bool:
    """Détecte un conflit explicite avec n'importe quel membre de la composante.

    L'algorithme reste ancré pour la décision positive de fusion, mais un veto
    fort est évalué paire à paire contre tous les membres. Cela empêche qu'un
    item tiers serve de pont entre deux identifiants natifs incompatibles ou
    entre deux dates d'événement explicitement distinctes.
    """
    for member in current:
        decision = decide_merge(member, incoming)
        if (
            decision.action == KEEP_SEPARATE
            and decision.reason_code in STRONG_KEEP_REASON_CODES
        ):
            return True
    return False


def group_components(items: list[Item]) -> list[list[Item]]:
    """Construit des composantes ancrées sans chaînage ni contournement de veto."""
    by_org: dict[str, list[Item]] = defaultdict(list)
    for item in items:
        key = _effective_key(item)
        if key:
            by_org[key].append(item)

    components: list[list[Item]] = []
    for org_key in sorted(by_org):
        group = sorted(
            by_org[org_key],
            key=lambda item: (item.best_date, item.Source_ID, item.URL, item.Item_ID),
        )
        current: list[Item] = []
        anchor: Item | None = None
        for item in group:
            if not current:
                current, anchor = [item], item
                continue
            decision = decide_merge(anchor, item)
            if decision.action == MERGE and not _has_strong_component_veto(current, item):
                current.append(item)
            else:
                components.append(current)
                current, anchor = [item], item
        if current:
            components.append(current)
    return components


def _component_dates(component: list[Item]) -> tuple[str, str]:
    event_dates = sorted(item.Event_Date for item in component if item.Event_Date)
    if event_dates:
        return event_dates[0], config.DATE_BASIS_EVENT
    published_dates = sorted(item.Published_Date for item in component if item.Published_Date)
    return (
        (published_dates[0], config.DATE_BASIS_PUBLICATION)
        if published_dates
        else ("", config.DATE_BASIS_PUBLICATION)
    )


def _majority(values: list[str], fallback: str) -> str:
    meaningful = [value for value in values if value and value != fallback]
    if not meaningful:
        return fallback
    counts = Counter(meaningful)
    top = max(counts.values())
    return min(value for value, count in counts.items() if count == top)


def _strict_majority(values: list[str], fallback: str) -> str:
    """Majorité sans tie-break arbitraire : une égalité conserve Inconnu."""
    meaningful = [value for value in values if value and value != fallback]
    if not meaningful:
        return fallback
    counts = Counter(meaningful)
    top = max(counts.values())
    winners = sorted(value for value, count in counts.items() if count == top)
    return winners[0] if len(winners) == 1 else fallback


def _preferred_qualification(ordered: list[Item], field_name: str, fallback: str) -> str:
    """Préfère VEILLE_LLM pour les champs qu'elle qualifie plus précisément.

    La priorité ne s'applique que si VEILLE_LLM fournit une valeur connue.
    Sinon, la majorité historique reste inchangée, sauf pour Sector où une
    égalité conserve désormais Inconnu plutôt qu'un choix alphabétique.
    """
    preferred = [
        getattr(item, field_name)
        for item in ordered
        if item.Source_ID == PREFERRED_QUALIFICATION_SOURCE
        and getattr(item, field_name)
        and getattr(item, field_name) != fallback
    ]
    if preferred:
        return _majority(preferred, fallback)
    values = [getattr(item, field_name) for item in ordered]
    if field_name == "Sector":
        return _strict_majority(values, fallback)
    return _majority(values, fallback)


# Priorité métier dédiée à l'agrégation Incident. Elle ne réutilise pas l'ordre
# historique de config.THREATS : une preuve spécifique de fuite ou de
# compromission de compte doit battre un simple signal générique d'intrusion.
_INCIDENT_THREAT_PRIORITY = (
    config.THREAT_RANSOMWARE,
    config.THREAT_DDOS,
    config.THREAT_MALWARE,
    config.THREAT_ACCOUNT,
    config.THREAT_LEAK,
    config.THREAT_PHISHING,
    config.THREAT_THIRD_PARTY,
    config.THREAT_INTRUSION,
    config.THREAT_OTHER,
    config.THREAT_UNKNOWN,
)


def _priority_threat(values: list[str]) -> str:
    known = {value for value in values if value and value in config.THREATS}
    for threat in _INCIDENT_THREAT_PRIORITY:
        if threat in known:
            return threat
    return config.THREAT_UNKNOWN


def _incident_evidence_items(ordered: list[Item]) -> list[Item]:
    """Écarte les apports analytiques du compteur de corroboration.

    Si un incident n'existe que dans une source analytique, celle-ci reste
    affichée comme source unique afin de ne jamais créer un incident sans source.
    """
    from . import sources

    evidence = []
    for item in ordered:
        spec = sources.by_id(item.Source_ID)
        if not (spec and spec.params.get("non_evidence_source")):
            evidence.append(item)
    return evidence or ordered


def _incident_from_component(component: list[Item], stable_id: str = "") -> Incident:
    ordered = sort_items(component)
    evidence = _incident_evidence_items(ordered)
    date, basis = _component_dates(ordered)
    incident_key = component_identity_key(ordered)
    return Incident(
        Incident_ID=stable_id or incident_id(incident_key, ordered[0].Item_ID),
        Date=date,
        Date_Basis=basis,
        Organisation=_majority(
            [item.Organisation_Raw for item in ordered],
            ordered[0].Organisation_Raw or "",
        ),
        Secteur=_preferred_qualification(ordered, "Sector", config.SECTOR_UNKNOWN),
        Menace=_priority_threat([item.Threat for item in ordered]),
        Localisation=_preferred_qualification(ordered, "Location", config.LOC_INCONNU),
        Sources=" | ".join(sorted({item.Source_ID for item in evidence if item.Source_ID})),
        Source_URLs=" | ".join(sorted({item.URL for item in evidence if item.URL})),
        Items_Count=len(ordered),
        First_seen=min(
            (item.Collected_As_Of for item in ordered if item.Collected_As_Of),
            default="",
        ),
        Last_seen=max(
            (item.Collected_As_Of for item in ordered if item.Collected_As_Of),
            default="",
        ),
    )


def build_incidents_with_registry(
    items: list[Item], registry_rows: list[dict] | None = None,
) -> tuple[list[Incident], list[dict[str, str]]]:
    """Construit INCIDENTS en conservant les ancres historiques persistées."""
    components = group_components(items)
    assigned, updated_registry = assign_incident_ids(components, registry_rows)
    incidents = [
        _incident_from_component(component, stable_id)
        for component, stable_id in zip(components, assigned)
    ]
    return sort_incidents(incidents), updated_registry


def build_incidents(items: list[Item]) -> list[Incident]:
    """Construction pure sans état, utilisée par les tests de règles de dédup."""
    return sort_incidents([
        _incident_from_component(component)
        for component in group_components(items)
    ])


def merge_items(existing: list[Item], incoming: list[Item]) -> tuple[list[Item], int]:
    by_id = {item.Item_ID: item for item in existing}
    new_count = 0
    for item in incoming:
        if not item.Item_ID:
            continue
        if item.Item_ID not in by_id:
            new_count += 1
        else:
            item.Collected_As_Of = by_id[item.Item_ID].Collected_As_Of or item.Collected_As_Of
        by_id[item.Item_ID] = item
    return sort_items(list(by_id.values())), new_count
