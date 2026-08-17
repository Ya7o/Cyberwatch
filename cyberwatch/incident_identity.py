"""Stabilité des Incident_ID par ancre historique persistée.

Le moteur de déduplication reste entièrement déterministe. La seule mémoire
persistée ici est l'item qui a créé l'identifiant d'un incident. Une nouvelle
source corroborante ne peut donc plus renommer un incident existant simplement
parce qu'elle se trie avant l'ancienne ancre.

Lorsqu'une fusion réunit plusieurs incidents déjà connus, l'identifiant dont
l'ancre a été collectée le plus tôt survit et les autres deviennent des
redirections. Lorsqu'un incident est scindé, seule la composante qui contient
son ancre historique conserve l'ancien identifiant.
"""

from __future__ import annotations

from collections import defaultdict

from .identity import incident_id, sort_items
from .model import Incident, Item
from .org_identity import effective_organisation_key


REGISTRY_COLUMNS = [
    "Incident_ID",
    "Anchor_Item_ID",
    "Organisation_Key",
    "Redirect_To",
]


def component_identity_key(component: list[Item]) -> str:
    """Clé utilisée pour créer un nouvel Incident_ID, sans renommer l'historique."""
    ordered = sort_items(component)
    if not ordered:
        return ""
    effective = effective_organisation_key(
        ordered[0].Organisation_Raw,
        ordered[0].Organisation_Key,
    )
    # Compatibilité avec la règle historique : un singleton garde sa clé stockée
    # afin qu'une amélioration future du resolver ne le renomme pas à elle seule.
    if len(ordered) == 1:
        return ordered[0].Organisation_Key or effective
    return effective


def _normalise_registry(rows: list[dict]) -> list[dict[str, str]]:
    normalised: list[dict[str, str]] = []
    for row in rows:
        normalised.append({column: str(row.get(column, "") or "") for column in REGISTRY_COLUMNS})
    return normalised


def _survivor_key(row: dict[str, str], items_by_id: dict[str, Item]) -> tuple[str, str, str]:
    anchor = items_by_id.get(row["Anchor_Item_ID"])
    if anchor is None:
        return ("9999-99-99T99:99:99", "9999-99-99", row["Incident_ID"])
    return (
        anchor.Collected_As_Of or "9999-99-99T99:99:99",
        anchor.Published_Date or "9999-99-99",
        row["Incident_ID"],
    )


def _new_incident_id(org_key: str, anchor_item_id: str, occupied: set[str]) -> str:
    """Crée un ID déterministe et évite une collision avec un ID historique."""
    candidate = incident_id(org_key, anchor_item_id)
    if candidate not in occupied:
        return candidate
    sequence = 2
    while True:
        candidate = incident_id(org_key, f"{anchor_item_id}#{sequence}")
        if candidate not in occupied:
            return candidate
        sequence += 1


def assign_incident_ids(
    components: list[list[Item]],
    registry_rows: list[dict] | None = None,
) -> tuple[list[str], list[dict[str, str]]]:
    """Attribue un ID stable à chaque composante et renvoie le registre mis à jour."""
    rows = _normalise_registry(registry_rows or [])
    records: dict[str, dict[str, str]] = {}
    for row in rows:
        incident = row["Incident_ID"]
        if incident and incident not in records:
            records[incident] = dict(row)

    items_by_id = {
        item.Item_ID: item
        for component in components
        for item in component
        if item.Item_ID
    }
    active_by_anchor: dict[str, dict[str, str]] = {}
    for row in records.values():
        if row["Anchor_Item_ID"] and not row["Redirect_To"]:
            active_by_anchor[row["Anchor_Item_ID"]] = row

    occupied = set(records)
    assigned: list[str] = []

    for component in components:
        member_ids = {item.Item_ID for item in component if item.Item_ID}
        inherited = [
            active_by_anchor[item_id]
            for item_id in sorted(member_ids)
            if item_id in active_by_anchor
        ]

        if inherited:
            survivor = min(inherited, key=lambda row: _survivor_key(row, items_by_id))
            chosen = survivor["Incident_ID"]
            for row in inherited:
                if row["Incident_ID"] != chosen:
                    row["Redirect_To"] = chosen
                    active_by_anchor.pop(row["Anchor_Item_ID"], None)
        else:
            ordered = sort_items(component)
            anchor = ordered[0]
            org_key = component_identity_key(component)
            chosen = _new_incident_id(org_key, anchor.Item_ID, occupied)
            record = {
                "Incident_ID": chosen,
                "Anchor_Item_ID": anchor.Item_ID,
                "Organisation_Key": org_key,
                "Redirect_To": "",
            }
            records[chosen] = record
            active_by_anchor[anchor.Item_ID] = record
            occupied.add(chosen)

        assigned.append(chosen)

    # Aplatit d'éventuelles chaînes de redirection anciennes.
    for row in records.values():
        target = row["Redirect_To"]
        seen = {row["Incident_ID"]}
        while target and target in records and target not in seen:
            seen.add(target)
            next_target = records[target]["Redirect_To"]
            if not next_target:
                break
            target = next_target
        if target and target not in seen:
            row["Redirect_To"] = target

    return assigned, sorted(records.values(), key=lambda row: row["Incident_ID"])


def bootstrap_registry(items: list[Item], incidents: list[Incident]) -> list[dict[str, str]]:
    """Récupère sans heuristique l'ancre de chaque Incident_ID déjà publié.

    La migration n'est acceptée que si chaque identifiant publié correspond à
    exactement un couple (clé d'organisation, Item_ID) selon la formule
    historique. Toute absence ou ambiguïté fait échouer la migration.
    """
    candidates: dict[str, list[tuple[Item, str]]] = defaultdict(list)
    for item in items:
        effective = effective_organisation_key(item.Organisation_Raw, item.Organisation_Key)
        keys: list[str] = []
        for key in (item.Organisation_Key, effective):
            if key and key not in keys:
                keys.append(key)
        for key in keys:
            candidates[incident_id(key, item.Item_ID)].append((item, key))

    rows: list[dict[str, str]] = []
    failures: list[str] = []
    for incident in incidents:
        matches = candidates.get(incident.Incident_ID, [])
        if len(matches) != 1:
            failures.append(f"{incident.Incident_ID}: matches={len(matches)}")
            continue
        item, key = matches[0]
        rows.append({
            "Incident_ID": incident.Incident_ID,
            "Anchor_Item_ID": item.Item_ID,
            "Organisation_Key": key,
            "Redirect_To": "",
        })
    if failures:
        raise ValueError("Migration Incident_ID ambiguë: " + "; ".join(failures[:20]))
    return sorted(rows, key=lambda row: row["Incident_ID"])


def validate_registry(
    rows: list[dict],
    items: list[Item],
    incidents: list[Incident] | None = None,
) -> list[str]:
    """Contrôles structurels du registre d'identité d'incident."""
    normalised = _normalise_registry(rows)
    problems: list[str] = []
    by_id: dict[str, dict[str, str]] = {}
    active_anchors: dict[str, str] = {}
    item_ids = {item.Item_ID for item in items if item.Item_ID}

    for row in normalised:
        incident = row["Incident_ID"]
        anchor = row["Anchor_Item_ID"]
        redirect = row["Redirect_To"]
        if not incident or not anchor:
            problems.append("Registre Incident_ID : ligne sans Incident_ID ou Anchor_Item_ID")
            continue
        if incident in by_id:
            problems.append(f"Registre Incident_ID : Incident_ID dupliqué {incident}")
        by_id[incident] = row
        if anchor not in item_ids:
            problems.append(f"Registre Incident_ID : ancre absente des ITEMS {anchor}")
        if not redirect:
            previous = active_anchors.get(anchor)
            if previous and previous != incident:
                problems.append(f"Registre Incident_ID : ancre active dupliquée {anchor}")
            active_anchors[anchor] = incident

    for row in normalised:
        redirect = row["Redirect_To"]
        if not redirect:
            continue
        if redirect == row["Incident_ID"]:
            problems.append(f"Registre Incident_ID : auto-redirection {redirect}")
        elif redirect not in by_id:
            problems.append(f"Registre Incident_ID : cible de redirection absente {redirect}")
        elif by_id[redirect]["Redirect_To"]:
            problems.append(
                f"Registre Incident_ID : chaîne de redirection non aplatie {row['Incident_ID']}"
            )

    if incidents is not None:
        current = {incident.Incident_ID for incident in incidents}
        active = {row["Incident_ID"] for row in normalised if not row["Redirect_To"]}
        missing = sorted(current - active)
        stale = sorted(active - current)
        if missing:
            problems.append(
                "Registre Incident_ID : incident(s) courant(s) sans ancre active "
                + ", ".join(missing[:10])
            )
        if stale:
            problems.append(
                "Registre Incident_ID : ancre(s) active(s) sans incident courant "
                + ", ".join(stale[:10])
            )

    return problems
