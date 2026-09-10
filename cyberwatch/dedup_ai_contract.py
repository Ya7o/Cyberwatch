"""Vocabulaire partagé du challenger LLM de déduplication.

Ce module ne contient que des constantes et le verdict figé : il est importé
aussi bien par la couche de préparation des charges utiles que par la couche
de validation, sans jamais dépendre d'elles. C'est ce qui permet de découper
`dedup_ai` sans introduire de cycle d'import.
"""

from __future__ import annotations

from dataclasses import dataclass

SAME = "SAME"
DIFFERENT = "DIFFERENT"
UNKNOWN = "UNKNOWN"

STATUS_OK = "OK"
STATUS_CACHE_HIT = "CACHE_HIT"
STATUS_SKIPPED = "SKIPPED"
STATUS_DISABLED = "DISABLED"
STATUS_BUDGET_BLOCKED = "BUDGET_BLOCKED"
STATUS_ERROR = "ERROR"
#: Candidat écarté uniquement par manque de capacité du batch quotidien
#: (nombre ou taille), à distinguer explicitement d'une absence de candidat
#: ou d'un filet désactivé (§Lot 15) : ce n'est jamais une absence de doublon.
STATUS_NOT_REVIEWED_CAPACITY = "NOT_REVIEWED_CAPACITY"
#: Paire dont la seule charge utile dépasse déjà le budget du batch. Elle est
#: différée telle quelle : tronquer son JSON produirait un objet incomplet que
#: le modèle jugerait sur des faits amputés, sans que rien ne le signale.
STATUS_NOT_REVIEWED_PAIR_TOO_LARGE = "NOT_REVIEWED_PAIR_TOO_LARGE"

#: Batch quotidien (§Lot 3) : version de prompt et de schéma distinctes du
#: challenger paire-à-paire historique, afin qu'un changement de forme de
#: batch n'invalide jamais silencieusement le cache pair-à-pair existant, et
#: réciproquement.
DAILY_BATCH_SCHEMA_NAME = "cyberwatch_dedup_batch_audit"
DAILY_BATCH_PROMPT_VERSION = "2026-09-11.1"
DAILY_BATCH_SCHEMA_VERSION = "2"

#: Seuil de confiance requis pour qu'une décision LLM soit proposée aux
#: registres d'identité organisationnelle ou d'incident (§Lot 5).
#:
#: Abaissé de 0.95 à 0.85 sur cas réel mesuré (reset 2026-08-25) : la paire
#: "Banque Alimentaire de la Croix-Rouge à Strasbourg" / "Banque Alimentaire
#: de Strasbourg" a bien été jugée SAME/SAME par le filet, avec 5 faits
#: concordants (Organisation_Key, Date, Affected_Count, Impact, Summary),
#: mais à 0.90 de confiance — donc rejetée, registre jamais écrit, doublon
#: publié. Une confiance de 0.90 sur un faisceau aussi net n'est pas un
#: doute réel ; 0.95 exigeait une quasi-certitude que le modèle n'exprime
#: quasiment jamais, rendant ce canal d'application inopérant en pratique.
ORG_IDENTITY_CONFIDENCE_THRESHOLD = 0.85
# Une décision négative devient un veto persistant. Elle demande donc une
# certitude supérieure à une fusion, qui pourra encore être bloquée par les
# garde-fous déterministes. Le seuil évite qu'un DIFFERENT à 0,85 fige un
# doublon avéré comme Aveyron / OnRecrute.
DIFFERENT_CONFIDENCE_THRESHOLD = 0.95

CACHE_COLUMNS = [
    "Pair_Key",
    "Left_Item_ID",
    "Right_Item_ID",
    "Input_Hash",
    "Model",
    "Prompt_Version",
    "Same_Organisation",
    "Same_Incident",
    "Confidence",
    "Evidence",
    "Reason",
    "Matched_Facts_JSON",
    "Conflicting_Facts_JSON",
    "Input_Tokens",
    "Cached_Input_Tokens",
    "Output_Tokens",
    "Total_Tokens",
    "Estimated_Cost_USD",
]

#: Champs SourceFacts transmis au modèle pour chaque item d'une paire.
FACT_FIELDS = (
    "Claim_Status",
    "Threat_Actor",
    "Third_Party",
    "Attack_Date",
    "Discovered_Date",
    "Victim_Website",
    "Affected_Count",
    "Affected_Unit",
    "Affected_Count_Raw",
    "File_Count",
    "Data_Types_JSON",
    "Impact",
    "Summary",
    "Evolution",
    "Evidence_URLs_JSON",
)


@dataclass(frozen=True)
class DedupAiDecision:
    status: str
    same_organisation: str = UNKNOWN
    same_incident: str = UNKNOWN
    confidence: float = 0.0
    evidence: str = ""
    reason: str = ""
    cache_hit: bool = False
    matched_facts: tuple[str, ...] = ()
    conflicting_facts: tuple[str, ...] = ()
