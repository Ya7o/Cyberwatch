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
    # Profil de performance par source. Les temps externes sont inclus dans
    # Processing_Duration_s mais ventilés ici pour expliquer le coût réel.
    "Collect_Duration_s",
    "Processing_Duration_s",
    "Org_Registry_Duration_s",
    "Org_Registry_Calls",
    "Org_Official_Site_Duration_s",
    "Org_Official_Site_Calls",
    "Qualification_LLM_Duration_s",
    "Qualification_LLM_Calls",
    "Qualification_LLM_Cost_USD",
    "SourceFacts_LLM_Duration_s",
    "SourceFacts_LLM_Calls",
    "SourceFacts_LLM_Cost_USD",
    "Other_Processing_Duration_s",
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
# AI_QUALIFICATIONS — cache/provenance du filet de rattrapage LLM
# --------------------------------------------------------------------------

AI_QUALIFICATIONS_COLUMNS = [
    "Item_ID",
    "Source_ID",
    "Input_Hash",
    "Model",
    "Prompt_Version",
    "Threat",
    "Threat_Confidence",
    "Threat_Evidence",
    "Sector",
    "Sector_Confidence",
    "Sector_Evidence",
    "Location",
    "Location_Confidence",
    "Location_Evidence",
    "Input_Tokens",
    "Cached_Input_Tokens",
    "Output_Tokens",
    "Total_Tokens",
    "Estimated_Cost_USD",
]

# --------------------------------------------------------------------------
# AI_USAGE — une ligne de synthèse par run concernant l'usage LLM
# --------------------------------------------------------------------------

AI_USAGE_COLUMNS = [
    "Run_ID",
    "As_Of",
    "Mode",
    "Model",
    "Prompt_Version",
    "Candidates",
    "Cache_Hits",
    "Calls_Attempted",
    "Calls_Succeeded",
    "Calls_Failed",
    "Calls_Budget_Blocked",
    "Threat_Unknown_Before",
    "Threat_Qualified",
    "Sector_Unknown_Before",
    "Sector_Qualified",
    "Location_Unknown_Before",
    "Location_Qualified",
    "Still_Unknown",
    "Input_Tokens",
    "Cached_Input_Tokens",
    "Output_Tokens",
    "Reasoning_Tokens",
    "Total_Tokens",
    "Estimated_Cost_USD",
    "Duration_s",
    "Status",
    # Pipeline Secteur (§12 METHODOLOGY.md) : additives, en fin de liste pour
    # rester rétro-compatibles avec les anciennes lignes (store.read_csv
    # tolère les colonnes absentes via row.get(col, "")).
    "Sector_Initial_Unknown",
    "Sector_Resolved_Reference",
    "Sector_Resolved_Deterministic",
    "Sector_Resolved_Source_LLM",
    "Sector_Evidence_Rejected",
    "Sector_Enrichment_Cache_Hit",
    "Sector_Enrichment_Http_Attempted",
    "Sector_Enrichment_Http_Matched",
    "Sector_Enrichment_Http_Ambiguous",
    "Sector_Enrichment_Http_Not_Found",
    "Sector_Enrichment_Http_Error",
    "Sector_Resolved_Enriched_Deterministic",
    "Sector_Resolved_Enriched_LLM",
    "Sector_Remaining_Unknown",
    "Org_Enrichment_Calls",
    "Org_Enrichment_Duration_s",
    "Org_Enrichment_Cache_Hit_Rate",
    # §Sector (fiabilité) : additives, mêmes garanties de rétrocompatibilité
    # que le bloc ci-dessus.
    "Sector_Resolved_Native",
    "Sector_LLM_Skipped_No_Evidence",
]

# --------------------------------------------------------------------------
# ORG_ENRICHMENT_CACHE — cache d'enrichissement gratuit d'entreprise (Sector)
# --------------------------------------------------------------------------

ORG_ENRICHMENT_CACHE_COLUMNS = [
    "Organisation_Key",
    "Query_Name",
    "Matched_Name",
    "Company_ID",
    "Activity_Code",
    "Activity_Label",
    "Headquarters_Department",
    "Evidence_Source",
    "Evidence_URL",
    "Match_Status",
    "Fetched_At",
    "Validated_Sector",
    "Validated_Via",
    # §Sector (fiabilité) : version de la logique de matching/mapping ayant
    # produit cette ligne — permet d'invalider ciblément un résultat négatif
    # ancien (org_enrichment.ORG_ENRICHMENT_CACHE_VERSION) sans TTL ni infra
    # supplémentaire. Additive, rétrocompatible (row.get(col, "")).
    "Cache_Version",
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
