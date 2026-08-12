"""Identifiants déterministes, tri canonique et empreintes (§7, §28).

Ce module est le garant de la reproductibilité : à `ITEMS` identique, il doit
produire exactement les mêmes identifiants, le même ordre et les mêmes hashes,
quel que soit l'ordre d'arrivée des données (§27).
"""

from __future__ import annotations

import hashlib

from .model import INCIDENT_COLUMNS, ITEM_COLUMNS, Incident, Item

#: Séparateur des composants de hachage. Choisi hors des valeurs attendues afin
#: que deux découpages différents ne puissent pas produire la même chaîne.
SEP = "|"


def _sha256(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def item_id(source_id: str, published_date: str, organisation_key: str, url: str) -> str:
    """`ITM-` + 16 premiers caractères hexadécimaux du SHA256 (§7)."""
    payload = SEP.join([
        source_id or "",
        published_date or "",
        organisation_key or "",
        url or "",
    ])
    return "ITM-" + _sha256(payload)[:16]


def incident_id(organisation_key: str, component_start_date: str) -> str:
    """`INC-` + 12 premiers caractères hexadécimaux en majuscules du SHA256 (§7)."""
    payload = SEP.join([organisation_key or "", component_start_date or ""])
    return "INC-" + _sha256(payload)[:12].upper()


# --------------------------------------------------------------------------
# Tri canonique (§28)
# --------------------------------------------------------------------------


def item_sort_key(item: Item) -> tuple:
    """Source_ID, Published_Date, Organisation_Key, URL, Item_ID."""
    return (
        item.Source_ID or "",
        item.Published_Date or "",
        item.Organisation_Key or "",
        item.URL or "",
        item.Item_ID or "",
    )


def sort_items(items: list[Item]) -> list[Item]:
    return sorted(items, key=item_sort_key)


def _date_ordinal(date: str) -> int:
    """`AAAA-MM-JJ` converti en entier comparable ; 0 si la date est absente."""
    digits = "".join(ch for ch in (date or "") if ch.isdigit())
    return int(digits) if digits else 0


def incident_sort_key(incident: Incident) -> tuple:
    """Date décroissante, puis Organisation normalisée, puis Incident_ID.

    La décroissance passe par l'opposé de la date convertie en entier : une
    seule clé de tri croissante suffit alors, sans mélanger `reverse=True` avec
    des composantes qui, elles, doivent rester croissantes. Les incidents sans
    date se retrouvent en fin de liste.
    """
    return (
        -_date_ordinal(incident.Date),
        (incident.Organisation or "").lower(),
        incident.Incident_ID or "",
    )


def sort_incidents(incidents: list[Incident]) -> list[Incident]:
    return sorted(incidents, key=incident_sort_key)


# --------------------------------------------------------------------------
# Empreintes (§24, §26, §27)
# --------------------------------------------------------------------------


def items_hash(items: list[Item]) -> str:
    """Empreinte SHA256 de `ITEMS`, calculée sur les données triées.

    Seules les colonnes canoniques entrent dans le calcul : deux exécutions du
    même jeu de données donnent la même empreinte même si l'ordre d'arrivée ou
    l'horodatage de collecte diffèrent.
    """
    lines = []
    for item in sort_items(items):
        row = item.to_row()
        lines.append(SEP.join(row[col] for col in ITEM_COLUMNS if col != "Collected_As_Of"))
    return _sha256("\n".join(lines))


def incidents_hash(incidents: list[Incident]) -> str:
    """Empreinte SHA256 de `INCIDENTS`, calculée sur les données triées.

    `First_seen` et `Last_seen` sont exclus : ils dépendent de l'historique des
    runs et non du contenu, alors que l'empreinte doit qualifier la
    transformation `ITEMS -> INCIDENTS` seule (§26).
    """
    excluded = {"First_seen", "Last_seen"}
    lines = []
    for incident in sort_incidents(incidents):
        row = incident.to_row()
        lines.append(SEP.join(row[col] for col in INCIDENT_COLUMNS if col not in excluded))
    return _sha256("\n".join(lines))
