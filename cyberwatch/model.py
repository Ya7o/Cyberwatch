"""Structures de données et ordre canonique des colonnes.

Les cinq feuilles du §4 de la méthodologie deviennent cinq fichiers CSV ;
l'architecture de la base est inchangée, seul le contenant l'est. Un sixième
jeu, `ENTITY_WATCH`, est ajouté pour rendre la couverture des couches de veille
vérifiable nominativement et alimenter le focus Réunion / Mayotte du dashboard.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

# --------------------------------------------------------------------------
# ITEMS (§4.1) — une ligne = un item brut réellement lu
# --------------------------------------------------------------------------

ITEM_COLUMNS = [
    "Item_ID",
    "Source_ID",
    "Published_Date",
    "Event_Date",
    "Organisation_Raw",
    "Organisation_Key",
    "Threat_Raw",
    "Threat",
    "Sector",
    "Location",
    "Title",
    "URL",
    "Collected_As_Of",
]


@dataclass
class Item:
    """Item brut de collecte. Aucune déduplication à ce stade (§4.1)."""

    Item_ID: str = ""
    Source_ID: str = ""
    Published_Date: str = ""
    Event_Date: str = ""
    Organisation_Raw: str = ""
    Organisation_Key: str = ""
    Threat_Raw: str = ""
    Threat: str = ""
    Sector: str = ""
    Location: str = ""
    Title: str = ""
    URL: str = ""
    Collected_As_Of: str = ""

    def to_row(self) -> dict[str, str]:
        data = asdict(self)
        return {col: str(data.get(col, "") or "") for col in ITEM_COLUMNS}

    @classmethod
    def from_row(cls, row: dict[str, str]) -> "Item":
        return cls(**{col: (row.get(col) or "") for col in ITEM_COLUMNS})

    @property
    def best_date(self) -> str:
        """Date retenue pour le regroupement : l'événement prime (§12)."""
        return self.Event_Date or self.Published_Date


# --------------------------------------------------------------------------
# INCIDENTS (§4.2) — une ligne = un incident dédupliqué
# --------------------------------------------------------------------------

INCIDENT_COLUMNS = [
    "Incident_ID",
    "Date",
    "Date_Basis",
    "Organisation",
    "Secteur",
    "Menace",
    "Localisation",
    "Sources",
    "Source_URLs",
    "Items_Count",
    "First_seen",
    "Last_seen",
]


@dataclass
class Incident:
    """Incident dédupliqué. Cette feuille alimente le dashboard."""

    Incident_ID: str = ""
    Date: str = ""
    Date_Basis: str = ""
    Organisation: str = ""
    Secteur: str = ""
    Menace: str = ""
    Localisation: str = ""
    Sources: str = ""
    Source_URLs: str = ""
    Items_Count: int = 0
    First_seen: str = ""
    Last_seen: str = ""

    def to_row(self) -> dict[str, str]:
        data = asdict(self)
        return {col: str(data.get(col, "") or "") for col in INCIDENT_COLUMNS}

    @classmethod
    def from_row(cls, row: dict[str, str]) -> "Incident":
        values = {col: (row.get(col) or "") for col in INCIDENT_COLUMNS}
        try:
            values["Items_Count"] = int(values["Items_Count"] or 0)
        except (TypeError, ValueError):
            values["Items_Count"] = 0
        return cls(**values)


# --------------------------------------------------------------------------
# SOURCES (§4.3) — une ligne = une source ou un protocole
# --------------------------------------------------------------------------

SOURCE_COLUMNS = [
    "Source_ID",
    "Active",
    "Layer",
    "Zone",
    "Start_URL",
    "Method",
    "Protocol",
    "Success_test",
    "Default_threat",
    "Location_rule",
    "Notes",
]

# --------------------------------------------------------------------------
# RUN_SOURCES (§4.4) — une ligne = résultat d'une source pendant un run
# Le statut suit le modèle refondu : Status + Coverage + Reason.
# --------------------------------------------------------------------------

RUN_SOURCE_COLUMNS = [
    "Run_ID",
    "As_Of",
    "Source_ID",
    "Layer",
    "Status",
    "Coverage",
    "Reason_Code",
    "Reason",
    "Calls",
    "Units_Done",
    "Units_Expected",
    "Items_seen",
    "Items_collected",
    "New_items",
    "Latest_item_date",
    "Access_Method",
    "Duration_s",
    "Comment",
]

# --------------------------------------------------------------------------
# RUN_LOG (§4.5) — une ligne = synthèse globale du run
# --------------------------------------------------------------------------

RUN_LOG_COLUMNS = [
    "Run_ID",
    "As_Of",
    "Mode",
    "Method_ID",
    "Target_Start",
    "Target_End",
    "Layers",
    "Items_Count",
    "Incidents_Count",
    "New_Items",
    "New_Incidents",
    "Sources_OK",
    "Sources_PARTIAL",
    "Sources_FAIL",
    "Sources_SKIPPED",
    "Health_Score",
    "Items_Hash",
    "Incidents_Hash",
    "Overall_Status",
    "Duration_s",
    "Requests",
    "Notes",
]

# --------------------------------------------------------------------------
# ENTITY_WATCH — état de veille nominatif (ajout par rapport à la méthode)
# --------------------------------------------------------------------------

ENTITY_WATCH_COLUMNS = [
    "Entity",
    "Entity_Key",
    "Territory",
    "Type",
    "Sector_Hint",
    "Last_Queried",
    "Query_Status",
    "Items_Found",
    "Last_Incident_Date",
    "Last_Incident_ID",
]


@dataclass
class WatchedEntity:
    """Entité placée sous surveillance nominative (couches `ENTITY_WATCH`)."""

    name: str
    territory: str
    kind: str = "critique"  # « commune » ou « critique »
    sector_hint: str = ""
    aliases: list[str] = field(default_factory=list)
