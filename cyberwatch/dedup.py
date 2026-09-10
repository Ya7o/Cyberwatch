"""Déduplication déterministe, explicable et conservatrice."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
import datetime as dt

from . import config
from .identity import incident_id, sort_incidents, sort_items
from .incident_identity import assign_incident_ids, component_identity_key
from .incident_dedup import DIFFERENT as INCIDENT_DIFFERENT
from .incident_dedup import SAME as INCIDENT_SAME
from .incident_dedup import decision_map as incident_decision_map
from .incident_dedup import pair_key as incident_pair_key
from .model import Incident, Item
from .sector_resolution import component_sector
from .normalize import _base_organisation_key, date_or_empty, organisation_key, searchable
from .org_identity import effective_organisation_key
from . import threat_resolution


MERGE = "MERGE"
KEEP_SEPARATE = "KEEP_SEPARATE"
NO_DECISION = "NO_DECISION"
PREFERRED_ENRICHMENT_SOURCE = "VEILLE_LLM"

STRONG_KEEP_REASON_CODES = frozenset({
    "INCIDENT_KEEP_CONFLICTING_SOURCE_ITEM_ID",
    "INCIDENT_KEEP_CONFLICTING_EVENT_DATE",
    "INCIDENT_KEEP_RECURRENCE_MARKER",
    "INCIDENT_KEEP_LLM_DIFFERENT",
    "INCIDENT_KEEP_LLM_TIME_GAP",
})

UNIQUE_ITEM_URL_SOURCES = frozenset({
    "BONJOURLAFUITE",
    "CYBERATTAQUE_ORG",
    "FRENCHBREACHES",
})

RANSOMWARE_CORROBORATION_SOURCES = frozenset({
    "RANSOMWARE_LIVE",
    "CYBERATTAQUE_ORG",
    "FRENCHBREACHES",
})
RANSOMWARE_CORROBORATION_SOURCE_PAIRS = frozenset({
    frozenset({"RANSOMWARE_LIVE", "CYBERATTAQUE_ORG"}),
    frozenset({"RANSOMWARE_LIVE", "FRENCHBREACHES"}),
    frozenset({"CYBERATTAQUE_ORG", "FRENCHBREACHES"}),
})
RANSOMWARE_CORROBORATION_DAYS = 14

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
    return effective_organisation_key(item.Organisation_Raw, item.Organisation_Key)


def _recurrence(item: Item) -> bool:
    blob = searchable(f"{item.Title} {item.Threat_Raw}")
    return any(marker in blob for marker in RECURRENCE_MARKERS)


def _temporal_pair(left: Item, right: Item) -> tuple[dt.date, dt.date, str] | None:
    """Retourne deux dates comparables et leur base sémantique.

    Deux dates d'événement sont comparées entre elles. Si l'une manque, on
    compare les dates de publication des deux items : une date d'événement ne
    doit jamais être comparée directement à une date de publication.
    """
    left_event = date_or_empty(left.Event_Date)
    right_event = date_or_empty(right.Event_Date)
    if left_event and right_event:
        return left_event, right_event, "event"
    left_published = date_or_empty(left.Published_Date)
    right_published = date_or_empty(right.Published_Date)
    if left_published and right_published:
        return left_published, right_published, "publication"
    return None


def _recurrence_boundary(left: Item, right: Item) -> bool:
    temporal = _temporal_pair(left, right)
    if temporal is None:
        return False
    left_date, right_date, _ = temporal
    if left_date == right_date:
        return False
    later = right if right_date > left_date else left
    return _recurrence(later)


def _same_unique_url(left: Item, right: Item) -> bool:
    return bool(
        left.URL
        and left.URL == right.URL
        and left.Source_ID == right.Source_ID
        and left.Source_ID in UNIQUE_ITEM_URL_SOURCES
    )


def _ransomware_corroboration(left: Item, right: Item, days: int) -> bool:
    if days > RANSOMWARE_CORROBORATION_DAYS:
        return False
    sources = frozenset({left.Source_ID, right.Source_ID})
    if (
        not sources <= RANSOMWARE_CORROBORATION_SOURCES
        or sources not in RANSOMWARE_CORROBORATION_SOURCE_PAIRS
    ):
        return False
    if left.Threat != config.THREAT_RANSOMWARE or right.Threat != config.THREAT_RANSOMWARE:
        return False

    temporal = _temporal_pair(left, right)
    if temporal is None:
        return False
    left_date, right_date, _ = temporal
    return abs((right_date - left_date).days) <= RANSOMWARE_CORROBORATION_DAYS


def decide_merge(
    left: Item,
    right: Item,
    incident_decisions: Mapping[str, str] | None = None,
) -> DedupDecision:
    """Décide une fusion paire à paire, sans similarité probabiliste."""
    if left.Source_ID == right.Source_ID and left.Source_Item_ID and right.Source_Item_ID:
        if left.Source_Item_ID == right.Source_Item_ID:
            return DedupDecision(MERGE, "INCIDENT_MERGE_SOURCE_ITEM_ID")
        # FrenchBreaches peut republier la même alerte sous un slug légèrement
        # différent tout en conservant son identifiant opaque final. Ce suffixe
        # est plus stable que l'URL complète et évite le doublon Vontes/INICEA.
        if left.Source_ID == "FRENCHBREACHES":
            left_suffix = left.Source_Item_ID.rstrip("/").rsplit("-", 1)[-1]
            right_suffix = right.Source_Item_ID.rstrip("/").rsplit("-", 1)[-1]
            if len(left_suffix) >= 12 and left_suffix == right_suffix:
                return DedupDecision(MERGE, "INCIDENT_MERGE_SOURCE_ALERT_ID")
        return DedupDecision(KEEP_SEPARATE, "INCIDENT_KEEP_CONFLICTING_SOURCE_ITEM_ID")

    if _recurrence_boundary(left, right):
        return DedupDecision(KEEP_SEPARATE, "INCIDENT_KEEP_RECURRENCE_MARKER")

    left_key, right_key = _effective_key(left), _effective_key(right)
    if not left_key or left_key != right_key:
        return DedupDecision(NO_DECISION, "INCIDENT_NO_DECISION")

    if left.Event_Date and right.Event_Date and left.Event_Date != right.Event_Date:
        return DedupDecision(
            KEEP_SEPARATE,
            "INCIDENT_KEEP_CONFLICTING_EVENT_DATE",
            (f"left={left.Event_Date}", f"right={right.Event_Date}"),
        )

    llm_decision = (incident_decisions or {}).get(
        incident_pair_key(left.Item_ID, right.Item_ID), ""
    )
    if llm_decision == INCIDENT_DIFFERENT:
        return DedupDecision(
            KEEP_SEPARATE,
            "INCIDENT_KEEP_LLM_DIFFERENT",
            ("llm_same_incident=DIFFERENT",),
        )
    if llm_decision == INCIDENT_SAME:
        temporal = _temporal_pair(left, right)
        if temporal is not None:
            left_date, right_date, basis = temporal
            days = abs((left_date - right_date).days)
            if days > config.INCIDENT_GAP_DAYS:
                return DedupDecision(
                    KEEP_SEPARATE,
                    "INCIDENT_KEEP_LLM_TIME_GAP",
                    (f"days={days}", f"basis={basis}"),
                )
        return DedupDecision(
            MERGE,
            "INCIDENT_MERGE_LLM_CONFIRMED",
            ("llm_same_incident=SAME",),
        )

    temporal = _temporal_pair(left, right)
    if temporal is None:
        return DedupDecision(NO_DECISION, "INCIDENT_NO_DECISION")
    left_date, right_date, _ = temporal

    days = abs((left_date - right_date).days)
    if (
        left.Event_Date and right.Event_Date
        and left.Event_Date == right.Event_Date
        and left.Source_ID != right.Source_ID
    ):
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

    if _ransomware_corroboration(left, right, days):
        claim_source = left.Source_ID if left.Source_ID == "RANSOMWARE_LIVE" else right.Source_ID
        report_source = right.Source_ID if claim_source == left.Source_ID else left.Source_ID
        return DedupDecision(
            MERGE,
            "INCIDENT_MERGE_RANSOMWARE_CORROBORATION",
            (f"days={days}", f"claim={claim_source}", f"report={report_source}"),
        )

    if days <= config.INCIDENT_GAP_DAYS and _same_unique_url(left, right):
        return DedupDecision(MERGE, "INCIDENT_MERGE_UNIQUE_URL", (f"days={days}",))

    return DedupDecision(KEEP_SEPARATE, "INCIDENT_KEEP_TIME_GAP", (f"days={days}",))


def _pair_cache_key(left: Item, right: Item) -> tuple[str, str]:
    return tuple(sorted((left.Item_ID, right.Item_ID)))


def _cached_decision(
    left: Item,
    right: Item,
    incident_decisions: Mapping[str, str] | None,
    cache: dict[tuple[str, str], DedupDecision],
) -> DedupDecision:
    key = _pair_cache_key(left, right)
    if key not in cache:
        cache[key] = decide_merge(left, right, incident_decisions)
    return cache[key]


def _component_block_reason(
    left: list[Item],
    right: list[Item],
    incident_decisions: Mapping[str, str] | None,
    cache: dict[tuple[str, str], DedupDecision],
) -> str:
    """Retourne le premier invariant qui interdit la réunion de deux groupes."""
    for first in left:
        for second in right:
            decision = _cached_decision(first, second, incident_decisions, cache)
            if (
                decision.action == KEEP_SEPARATE
                and decision.reason_code in STRONG_KEEP_REASON_CODES
            ):
                return decision.reason_code
            temporal = _temporal_pair(first, second)
            if temporal is None:
                return "INCIDENT_KEEP_INCOMPARABLE_DATES"
            if abs((temporal[0] - temporal[1]).days) > config.INCIDENT_GAP_DAYS:
                return "INCIDENT_KEEP_COMPONENT_TIME_SPAN"
    return ""


def group_components(
    items: list[Item],
    incident_decisions: Mapping[str, str] | None = None,
) -> list[list[Item]]:
    """Réunit des composantes compatibles, dans un ordre déterministe.

    Les liens d'identité native sont appliqués d'abord, puis les règles
    déterministes ordinaires, et enfin les verdicts SAME persistés. Toute réunion autre
    qu'une identité native exacte est contrôlée contre chaque paire des deux
    composantes : aucun veto fort ni dépassement de la fenêtre de 14 jours ne
    peut ainsi être contourné par transitivité.
    """
    eligible = [item for item in items if _effective_key(item)]
    ordered = sorted(
        eligible,
        key=lambda item: (
            _effective_key(item), item.best_date, item.Source_ID, item.URL, item.Item_ID
        ),
    )
    by_org: dict[str, list[Item]] = defaultdict(list)
    by_native: dict[tuple[str, str], list[Item]] = defaultdict(list)
    for item in eligible:
        key = _effective_key(item)
        if key:
            by_org[key].append(item)
        if item.Source_ID and item.Source_Item_ID:
            by_native[(item.Source_ID, item.Source_Item_ID)].append(item)

    local = {item.Item_ID: [item] for item in ordered}
    owner = {item.Item_ID: item.Item_ID for item in ordered}
    decision_cache: dict[tuple[str, str], DedupDecision] = {}
    edges_by_pair: dict[tuple[str, str], tuple[int, int, str, str]] = {}

    for native_group in by_native.values():
        native_ordered = sorted(native_group, key=lambda item: item.Item_ID)
        for right in native_ordered[1:]:
            pair = _pair_cache_key(native_ordered[0], right)
            edges_by_pair[pair] = (0, 0, pair[0], pair[1])

    for org_key in sorted(by_org):
        group = sorted(
            by_org[org_key],
            key=lambda item: (item.best_date, item.Source_ID, item.URL, item.Item_ID),
        )
        for index, left in enumerate(group):
            for right in group[index + 1:]:
                decision = _cached_decision(left, right, incident_decisions, decision_cache)
                if decision.action != MERGE:
                    continue
                priority = (
                    0 if decision.reason_code == "INCIDENT_MERGE_SOURCE_ITEM_ID"
                    else 2 if decision.reason_code == "INCIDENT_MERGE_LLM_CONFIRMED"
                    else 1
                )
                pair = _pair_cache_key(left, right)
                temporal = _temporal_pair(left, right)
                distance = (
                    abs((temporal[0] - temporal[1]).days)
                    if temporal is not None else config.INCIDENT_GAP_DAYS + 1
                )
                edge = (priority, distance, pair[0], pair[1])
                if pair not in edges_by_pair or edge < edges_by_pair[pair]:
                    edges_by_pair[pair] = edge

    for priority, _distance, left_id, right_id in sorted(edges_by_pair.values()):
        left_owner, right_owner = owner[left_id], owner[right_id]
        if left_owner == right_owner:
            continue
        left_component, right_component = local[left_owner], local[right_owner]
        if priority != 0 and _component_block_reason(
            left_component, right_component, incident_decisions, decision_cache
        ):
            continue
        survivor, absorbed = sorted((left_owner, right_owner))
        local[survivor] = sorted(
            local[survivor] + local[absorbed],
            key=lambda item: (item.best_date, item.Source_ID, item.URL, item.Item_ID),
        )
        for item in local[absorbed]:
            owner[item.Item_ID] = survivor
        del local[absorbed]

    return sorted(
        local.values(),
        key=lambda component: (
            _effective_key(component[0]),
            component[0].best_date,
            component[0].Source_ID,
            component[0].URL,
            component[0].Item_ID,
        ),
    )


def separation_reason(
    items: list[Item],
    left_item_id: str,
    right_item_id: str,
    incident_decisions: Mapping[str, str] | None = None,
) -> str:
    """Explique pourquoi une paire validée reste dans deux composantes."""
    components = group_components(items, incident_decisions)
    left_component = next((c for c in components if any(i.Item_ID == left_item_id for i in c)), [])
    right_component = next((c for c in components if any(i.Item_ID == right_item_id for i in c)), [])
    if not left_component or not right_component:
        return "INCIDENT_KEEP_ITEM_MISSING"
    if left_component is right_component:
        return ""
    cache: dict[tuple[str, str], DedupDecision] = {}
    return _component_block_reason(
        left_component, right_component, incident_decisions, cache
    ) or "INCIDENT_KEEP_NO_COMPATIBLE_COMPONENT"


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


def _canonical_organisation_label(ordered: list[Item]) -> str:
    """Libellé publié d'une composante fusionnée : celui que les sources emploient le plus.

    Décompte plein, contrairement à `_majority` qui écarte le `fallback` du
    sien et fait donc gagner le libellé minoritaire dès qu'il n'y a que deux
    membres. À égalité, le premier dans l'ordre alphabétique tranche : le
    résultat ne dépend ni de l'ordre de collecte, ni du sens conventionnel
    alias -> canonique choisi par le registre d'identité.
    """
    labels = [item.Organisation_Raw for item in ordered if item.Organisation_Raw]
    if not labels:
        return ""
    counts = Counter(labels)
    top = max(counts.values())
    return min(label for label, count in counts.items() if count == top)


def _strict_majority(values: list[str], fallback: str) -> str:
    meaningful = [value for value in values if value and value != fallback]
    if not meaningful:
        return fallback
    counts = Counter(meaningful)
    top = max(counts.values())
    winners = sorted(value for value, count in counts.items() if count == top)
    return winners[0] if len(winners) == 1 else fallback


def _preferred_enrichment(ordered: list[Item], field_name: str, fallback: str) -> str:
    preferred = [
        getattr(item, field_name)
        for item in ordered
        if item.Source_ID == PREFERRED_ENRICHMENT_SOURCE
        and getattr(item, field_name)
        and getattr(item, field_name) != fallback
    ]
    if preferred:
        return _majority(preferred, fallback)
    values = [getattr(item, field_name) for item in ordered]
    if field_name in {"Sector", "Location"}:
        return _strict_majority(values, fallback)
    return _majority(values, fallback)


def _incident_evidence_items(ordered: list[Item]) -> list[Item]:
    from . import sources

    evidence = []
    for item in ordered:
        spec = sources.by_id(item.Source_ID)
        if not (spec and spec.params.get("non_evidence_source")):
            evidence.append(item)
    return evidence or ordered


def _incident_from_component(
    component: list[Item],
    stable_id: str = "",
    facts_by_item: Mapping[str, list[dict]] | None = None,
) -> Incident:
    ordered = sort_items(component)
    evidence = _incident_evidence_items(ordered)
    date, basis = _component_dates(ordered)
    incident_key = component_identity_key(ordered)
    return Incident(
        Incident_ID=stable_id or incident_id(incident_key, ordered[0].Item_ID),
        Date=date,
        Date_Basis=basis,
        Organisation=_canonical_organisation_label(ordered),
        Secteur=component_sector(ordered),
        Menace=threat_resolution.resolve_component(ordered, facts_by_item).value,
        Localisation=_preferred_enrichment(ordered, "Location", config.LOC_INCONNU),
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
    items: list[Item],
    registry_rows: list[dict] | None = None,
    incident_decision_rows: list[dict] | None = None,
    source_facts_rows: list[dict] | None = None,
) -> tuple[list[Incident], list[dict[str, str]]]:
    decisions = incident_decision_map(incident_decision_rows or [])
    components = group_components(items, decisions)
    assigned, updated_registry = assign_incident_ids(components, registry_rows)
    facts_by_item = threat_resolution.index_source_facts(source_facts_rows)
    incidents = [
        _incident_from_component(component, stable_id, facts_by_item)
        for component, stable_id in zip(components, assigned)
    ]
    return sort_incidents(incidents), updated_registry


def build_incidents(items: list[Item], source_facts_rows: list[dict] | None = None) -> list[Incident]:
    facts_by_item = threat_resolution.index_source_facts(source_facts_rows)
    return sort_incidents([
        _incident_from_component(component, facts_by_item=facts_by_item)
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
