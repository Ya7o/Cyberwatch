"""Traitement borné des entrées collectées avant fusion du snapshot."""

from __future__ import annotations

from collections.abc import Callable

from . import config
from .collectors.base import CollectResult, RawEntry, SourceSpec
from .collectors.cyberattaque_org import is_negated_incident, is_obvious_multi
from .model import Item
from .normalize import looks_cyber


def process_entries(
    result: CollectResult,
    spec: SourceSpec,
    as_of: str,
    known_orgs: dict[str, str],
    entity_index: dict,
    territories: dict[str, str] | None,
    reference: dict | None,
    fact_rows: list[dict] | None,
    *,
    convert: Callable[..., Item | None],
    extract_fact: Callable[[Item, RawEntry, SourceSpec], dict | None],
) -> tuple[list[Item], dict[str, int]]:
    """Convertit les entrées et renvoie les compteurs de rejet éditoriaux."""
    items: list[Item] = []
    requires_victim = bool(spec.params.get("require_victim"))
    metrics = {
        "articles_cyber": 0,
        "articles_rejected_no_victim": 0,
        "cyberattaque_rejected_negated": 0,
        "cyberattaque_rejected_multi": 0,
        "cyberattaque_rejected_no_victim": 0,
    }
    for entry in result.entries:
        if requires_victim and looks_cyber(entry.title, entry.summary, entry.content):
            metrics["articles_cyber"] += 1
        if spec.source_id == "CYBERATTAQUE_ORG" and is_negated_incident(
            entry.title, entry.summary, entry.content
        ):
            metrics["cyberattaque_rejected_negated"] += 1
            continue
        if spec.source_id == "CYBERATTAQUE_ORG" and is_obvious_multi(
            entry.title, entry.summary, entry.content
        ):
            metrics["cyberattaque_rejected_multi"] += 1
            continue
        item = convert(
            entry, spec, as_of, known_orgs, entity_index, territories, reference
        )
        if item is None:
            key = (
                "articles_rejected_no_victim"
                if requires_victim
                else "cyberattaque_rejected_no_victim"
            )
            metrics[key] += 1
            continue
        items.append(item)
        if (
            item.Location == config.LOC_INCONNU
            and spec.location_rule in config.LOCATIONS
            and spec.location_rule != config.LOC_INCONNU
        ):
            item.Location = spec.location_rule
        if fact_rows is not None:
            fact = extract_fact(item, entry, spec)
            if fact is not None:
                fact_rows.append(fact)
    return items, metrics
