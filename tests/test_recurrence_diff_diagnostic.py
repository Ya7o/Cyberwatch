"""Diagnostic temporaire : comparer l'ancien et le nouveau découpage de récidive."""

from collections import defaultdict

from cyberwatch import config, store
from cyberwatch.dedup import (
    KEEP_SEPARATE,
    MERGE,
    NO_DECISION,
    DedupDecision,
    UNIQUE_ITEM_URL_SOURCES,
    group_components,
)
from cyberwatch.normalize import _base_organisation_key, date_or_empty, organisation_key, searchable


OLD_RECURRENCE_MARKERS = (
    "nouvelle cyberattaque", "nouvelle attaque", "nouvelle fuite", "a nouveau",
    "de nouveau", "une nouvelle fois", "frappe une nouvelle fois",
    "deuxieme attaque", "second incident", "new attack", "attacked again",
    "breached again", "another breach", "second attack", "new breach",
)


def _key(item):
    return organisation_key(item.Organisation_Raw) or item.Organisation_Key


def _old_recurrence(item):
    blob = searchable(f"{item.Title} {item.Threat_Raw}")
    return any(marker in blob for marker in OLD_RECURRENCE_MARKERS)


def _same_unique_url(left, right):
    return bool(
        left.URL and left.URL == right.URL and left.Source_ID == right.Source_ID
        and left.Source_ID in UNIQUE_ITEM_URL_SOURCES
    )


def _old_decide(left, right):
    if left.Source_ID == right.Source_ID and left.Source_Item_ID and right.Source_Item_ID:
        if left.Source_Item_ID == right.Source_Item_ID:
            return DedupDecision(MERGE, "SOURCE_ITEM")
        return DedupDecision(KEEP_SEPARATE, "CONFLICT")
    if _old_recurrence(left) or _old_recurrence(right):
        return DedupDecision(KEEP_SEPARATE, "RECURRENCE")
    if _key(left) != _key(right):
        return DedupDecision(NO_DECISION, "NO")
    left_date, right_date = date_or_empty(left.best_date), date_or_empty(right.best_date)
    if not left_date or not right_date:
        return DedupDecision(NO_DECISION, "NO")
    days = abs((left_date - right_date).days)
    if left.Event_Date and left.Event_Date == right.Event_Date and left.Source_ID != right.Source_ID:
        return DedupDecision(MERGE, "EVENT")
    if days <= 3:
        return DedupDecision(MERGE, "DATE")
    if days <= config.INCIDENT_GAP_DAYS and _same_unique_url(left, right):
        return DedupDecision(MERGE, "URL")
    return DedupDecision(KEEP_SEPARATE, "GAP")


def _old_components(items):
    by_org = defaultdict(list)
    for item in items:
        if _key(item):
            by_org[_key(item)].append(item)
    out = []
    for org_key in sorted(by_org):
        group = sorted(
            by_org[org_key],
            key=lambda item: (item.best_date, item.Source_ID, item.URL, item.Item_ID),
        )
        current, anchor = [], None
        for item in group:
            if not current:
                current, anchor = [item], item
                continue
            if _old_decide(anchor, item).action == MERGE:
                current.append(item)
            else:
                out.append(current)
                current, anchor = [item], item
        if current:
            out.append(current)
    return out


def _summarize(components):
    by_org = defaultdict(list)
    for component in components:
        key = _key(component[0])
        by_org[key].append([
            f"{item.best_date}|{item.Source_ID}|{item.Organisation_Raw}|{item.Title}"
            for item in component
        ])
    return by_org


def test_diagnostic_recurrence_deltas():
    items = store.load_items()
    old = _summarize(_old_components(items))
    new = _summarize(group_components(items))
    deltas = {
        key: {"old": old[key], "new": new[key]}
        for key in sorted(set(old) | set(new))
        if old[key] != new[key]
    }
    raise AssertionError(f"RECURRENCE_DELTAS={deltas!r}")
