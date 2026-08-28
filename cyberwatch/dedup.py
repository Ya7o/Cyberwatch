"""Déduplication déterministe, explicable et conservatrice."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Mapping
from dataclasses import dataclass

from . import config
from .identity import incident_id, sort_incidents, sort_items
from .incident_identity import assign_incident_ids, component_identity_key
from .incident_dedup import DIFFERENT as INCIDENT_DIFFERENT
from .incident_dedup import SAME as INCIDENT_SAME
from .incident_dedup import decision_map as incident_decision_map
from .incident_dedup import pair_key as incident_pair_key
from .model import Incident, Item
from .normalize import _base_organisation_key, date_or_empty, searchable
from .org_identity import effective_organisation_key


MERGE = "MERGE"
KEEP_SEPARATE = "KEEP_SEPARATE"
NO_DECISION = "NO_DECISION"
PREFERRED_QUALIFICATION_SOURCE = "VEILLE_LLM"

STRONG_KEEP_REASON_CODES = frozenset({
    "INCIDENT_KEEP_CONFLICTING_SOURCE_ITEM_ID",
    "INCIDENT_KEEP_CONFLICTING_EVENT_DATE",
    "INCIDENT_KEEP_RECURRENCE_MARKER",
    "INCIDENT_KEEP_LLM_DIFFERENT",
})

UNIQUE_ITEM_URL_SOURCES = frozenset({
    "BONJOURLAFUITE",
    "CYBERATTAQUE_ORG",
    "FRENCHBREACHES",
})

RANSOMWARE_CORROBORATION_SOURCES = frozenset({
    "RANSOMWARE_LIVE",
    "CYBERATTAQUE_ORG",
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


def _recurrence_boundary(left: Item, right: Item) -> bool:
    left_date = date_or_empty(left.best_date)
    right_date = date_or_empty(right.best_date)
    if not left_date or not right_date or left_date == right_date:
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
    sources = {left.Source_ID, right.Source_ID}
    if "RANSOMWARE_LIVE" not in sources and sources != {"CYBERATTAQUE_ORG", "FRENCHBREACHES"}:
        return False
    if left.Threat != config.THREAT_RANSOMWARE or right.Threat != config.THREAT_RANSOMWARE:
        return False

    claim = left if left.Source_ID == "RANSOMWARE_LIVE" else right
    report = right if claim is left else left
    claim_date = date_or_empty(claim.best_date)
    report_date = date_or_empty(report.best_date)
    return bool(
        claim_date
        and report_date
        and abs((report_date - claim_date).days) <= RANSOMWARE_CORROBORATION_DAYS
    )


def decide_merge(
    left: Item,
    right: Item,
    incident_decisions: Mapping[str, str] | None = None,
) -> DedupDecision:
    """Décide une fusion paire à paire, sans similarité probabiliste."""
    if left.Source_ID == right.Source_ID and left.Source_Item_ID and right.Source_Item_ID:
        if left.Source_Item_ID == right.Source_Item_ID:
            return DedupDecision(MERGE, "INCIDENT_MERGE_SOURCE_ITEM_ID")
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
        return DedupDecision(
            MERGE,
            "INCIDENT_MERGE_LLM_CONFIRMED",
            ("llm_same_incident=SAME",),
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

    if _ransomware_corroboration(left, right, days):
        return DedupDecision(
            MERGE,
            "INCIDENT_MERGE_RANSOMWARE_CORROBORATION",
            (f"days={days}", "claim=RANSOMWARE_LIVE", "report=CYBERATTAQUE_ORG"),
        )

    if days <= config.INCIDENT_GAP_DAYS and _same_unique_url(left, right):
        return DedupDecision(MERGE, "INCIDENT_MERGE_UNIQUE_URL", (f"days={days}",))

    return DedupDecision(KEEP_SEPARATE, "INCIDENT_KEEP_TIME_GAP", (f"days={days}",))


def _has_strong_component_veto(
    current: list[Item],
    incoming: Item,
    incident_decisions: Mapping[str, str] | None = None,
) -> bool:
    for member in current:
        decision = decide_merge(member, incoming, incident_decisions)
        if (
            decision.action == KEEP_SEPARATE
            and decision.reason_code in STRONG_KEEP_REASON_CODES
        ):
            return True
    return False


def _can_extend_component(
    current: list[Item],
    incoming: Item,
    incident_decisions: Mapping[str, str] | None = None,
) -> bool:
    """Autorise une corroboration cross-source J+1 sans chaînage ouvert.

    L'ancre reste la règle principale. Cette extension ne sert que lorsqu'une
    source différente corrobore à J+1 un membre déjà admis. La composante reste
    bornée par INCIDENT_GAP_DAYS et tous les veto forts sont contrôlés avant
    l'appel par `group_components`.
    """
    incoming_date = date_or_empty(incoming.best_date)
    if not incoming_date or not current:
        return False
    dated = [member for member in current if date_or_empty(member.best_date)]
    if not dated:
        return False
    earliest = min(date_or_empty(member.best_date) for member in dated)
    if abs((incoming_date - earliest).days) > config.INCIDENT_GAP_DAYS:
        return False
    for member in reversed(dated):
        member_date = date_or_empty(member.best_date)
        if member.Source_ID == incoming.Source_ID:
            continue
        if abs((incoming_date - member_date).days) > 1:
            continue
        if decide_merge(member, incoming, incident_decisions).action == MERGE:
            return True
    return False


def group_components(
    items: list[Item],
    incident_decisions: Mapping[str, str] | None = None,
) -> list[list[Item]]:
    """Construit des composantes ancrées avec extension cross-source bornée."""
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
            decision = decide_merge(anchor, item, incident_decisions)
            veto = _has_strong_component_veto(current, item, incident_decisions)
            if not veto and (
                decision.action == MERGE
                or _can_extend_component(current, item, incident_decisions)
            ):
                current.append(item)
            else:
                components.append(current)
                current, anchor = [item], item
        if current:
            components.append(current)

    # Une publication éditoriale peut précéder de plusieurs jours la fiche
    # ransomware qui la corrobore. La construction ancrée ci-dessus ne voit
    # pas toujours cette paire si une troisième source a créé entre-temps une
    # composante distincte ; réunir alors seulement les composantes dont une
    # paire satisfait déjà la règle de corroboration stricte.
    #
    # `_ransomware_corroboration` ne vérifie que la fenêtre de jours et la
    # combinaison de sources : sans le contrôle `_effective_key` ci-dessous,
    # une chaîne d'articles ransomware sur des victimes distinctes mais
    # publiés à moins de 14 jours d'écart se recolle transitivement en un
    # seul incident (cas réel constaté : 11 organisations distinctes
    # fusionnées sous "ALIZE"). La paire qui déclenche la réunion doit donc
    # être la même organisation, exactement comme le cas visé par le
    # commentaire ci-dessus (un article et une revendication sur la même
    # victime, coupés en deux composantes par la construction ancrée).
    merged = True
    while merged:
        merged = False
        for index, left in enumerate(components):
            match = next((
                other for other in range(index + 1, len(components))
                if any(
                    _effective_key(a) == _effective_key(b)
                    and _ransomware_corroboration(
                        a, b,
                        abs((date_or_empty(a.best_date) - date_or_empty(b.best_date)).days),
                    )
                    for a in left for b in components[other]
                    if date_or_empty(a.best_date) and date_or_empty(b.best_date)
                ) and not any(
                    decide_merge(a, b, incident_decisions).reason_code in STRONG_KEEP_REASON_CODES
                    for a in left for b in components[other]
                )
            ), None)
            if match is None:
                continue
            components[index] = left + components.pop(match)
            merged = True
            break
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
    meaningful = [value for value in values if value and value != fallback]
    if not meaningful:
        return fallback
    counts = Counter(meaningful)
    top = max(counts.values())
    winners = sorted(value for value, count in counts.items() if count == top)
    return winners[0] if len(winners) == 1 else fallback


def _preferred_qualification(ordered: list[Item], field_name: str, fallback: str) -> str:
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
    items: list[Item],
    registry_rows: list[dict] | None = None,
    incident_decision_rows: list[dict] | None = None,
) -> tuple[list[Incident], list[dict[str, str]]]:
    decisions = incident_decision_map(incident_decision_rows or [])
    components = group_components(items, decisions)
    assigned, updated_registry = assign_incident_ids(components, registry_rows)
    incidents = [
        _incident_from_component(component, stable_id)
        for component, stable_id in zip(components, assigned)
    ]
    return sort_incidents(incidents), updated_registry


def build_incidents(items: list[Item]) -> list[Incident]:
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
