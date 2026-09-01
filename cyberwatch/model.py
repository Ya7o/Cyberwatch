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
    "Source_Item_ID",
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
    Source_Item_ID: str = ""
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
    "Items_in_window",
    "Items_collected",
    "New_items",
    "Latest_item_date",
    "Latest_Item_Org",
    "Access_Method",
    "Duration_s",
    "Comment",
    # Couverture historique (§stabilisation pré-release) : additives, en fin
    # de liste pour rester rétro-compatibles (store.read_csv tolère les
    # anciennes lignes sans ces colonnes via row.get(col, "")).
    "History_Status",
    "Oldest_Available_Date",
    "Collect_Duration_s",
    "Processing_Duration_s",
    "SourceFacts_LLM_Duration_s",
    "SourceFacts_LLM_Calls",
    "SourceFacts_LLM_Cost_USD",
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
    "Source_Status",
    "Items_seen",
    "Items_in_window",
    "Sources_OK",
    "Sources_PARTIAL",
    "Sources_FAIL",
    "Sources_SKIPPED",
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


# --------------------------------------------------------------------------
# DEDUP_AI_DAILY_USAGE — une ligne de synthèse par run du filet quotidien de
# déduplication (§Lot 14). Colonnes définies ici (et non dans dedup_ai.py)
# pour garder le format CSV indépendant de l'implémentation du filet.
# --------------------------------------------------------------------------

DEDUP_AI_DAILY_USAGE_COLUMNS = [
    "Run_ID",
    "As_Of",
    "Mode",
    "Status",
    "Model",
    "Prompt_Version",
    "Candidates_Generated",
    "Candidates_Selected",
    "Candidates_Not_Reviewed_Capacity",
    "LLM_Calls",
    "LLM_Calls_Succeeded",
    "LLM_Calls_Failed",
    "LLM_Cache_Hits",
    "LLM_Same_Organisation",
    "LLM_Same_Incident",
    "LLM_Different",
    "LLM_Unknown",
    "Org_Aliases_Applied",
    "Incident_Decisions_Applied",
    "Review_Required",
    "LLM_Input_Tokens",
    "LLM_Output_Tokens",
    "LLM_Cost_USD",
    "LLM_Duration_Seconds",
]

# --------------------------------------------------------------------------
# SOURCE_FACTS — faits supplémentaires publiés par une source pour un item.
# Jeu auxiliaire : décrit ce qu'une source publie, jamais une connaissance
# canonique sur l'organisation (Threat/Sector/Location n'en dépendent pas).
# --------------------------------------------------------------------------

SOURCE_FACT_COLUMNS = [
    "Item_ID",
    "Source_ID",
    "Claim_Status",
    "Claim_Status_Raw",
    "Threat_Actor",
    "Third_Party",
    "Fine_Location",
    "Source_Sector_Raw",
    "Activity_Description",
    # Proposition issue de la même extraction de faits ; elle ne remplace pas
    # le secteur déterministe de l'incident.
    "Activity_Sector_Match",
    "Affected_Count",
    "Affected_Unit",
    "Affected_Count_Raw",
    "Data_Volume_Raw",
    "File_Count",
    "Data_Types_JSON",
    "Vulnerabilities_JSON",
    "CVSS_Raw",
    "Attack_Date",
    "Discovered_Date",
    "Victim_Website",
    "Cyberattack_Score",
    "Initial_Access",
    "Attack_Flow_JSON",
    "Impact",
    "Summary",
    "Evolution",
    "Evidence_URLs_JSON",
    "Evidence_JSON",
    "Source_Metadata_JSON",
    "Extraction_Method",
    "Extraction_Version",
]
