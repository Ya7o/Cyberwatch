from __future__ import annotations

import json

from cyberwatch import source_facts, source_facts_ai as sfa


def test_deterministic_impact_rejects_conditionnel_et_remediation():
    assert sfa._deterministic_impact("L'attaque aurait entraîné une indisponibilité des systèmes.") is None
    assert sfa._deterministic_impact("Scalingo a mis le service hors ligne puis appliqué un correctif de sécurité.") is None
    assert sfa._deterministic_impact("Une interruption des services a duré plusieurs heures.") is not None


def test_initial_access_deterministe_strict():
    explicit = "Une intrusion sur l'intranet a été réalisée à partir du compte compromis d'un membre."
    result = sfa._deterministic_initial_access(explicit)
    assert result and result["value"] == "compromised_credentials"
    assert sfa._deterministic_initial_access("Il s'agirait d'une campagne de phishing ayant permis l'accès à certains comptes.") is None
    assert sfa._deterministic_initial_access("Le point d'entrée reste inconnu. Un phishing est possible.") is None


def test_initial_access_ignore_la_phrase_pedagogique_generique():
    """Régression Le Tampon : un article expliquant ce qu'une attaque « peut »
    entraîner en général énumérait des vecteurs sans en imputer aucun à la
    victime, et le vecteur en ressortait pourtant « confirmé »."""
    generique = (
        "La compromission d’un compte, l’exploitation d’une vulnérabilité ou "
        "l’infection d’un serveur peut ainsi conduire les équipes à isoler "
        "préventivement plusieurs systèmes afin d’empêcher l’attaque de se propager."
    )
    assert sfa._deterministic_initial_access(generique) is None
    # Une preuve réellement imputée à la victime reste retenue.
    impute = "L'attaquant a exploité une faille IDOR qui a permis l'accès aux dossiers."
    assert sfa._deterministic_initial_access(impute)["value"] == "vulnerability_exploitation"


def test_summary_derivee_depuis_faits_valides():
    fact = {
        "Summary": "",
        "Initial_Access": "compromised_credentials",
        "Impact": "Interruption du service",
    }
    evidence = {"Initial_Access": "preuve accès", "Impact": "preuve impact"}
    source_facts._derive_summary(fact, evidence)
    assert fact["Summary"]
    assert len(fact["Summary"]) <= sfa.MAX_SUMMARY_CHARS
    assert evidence["Summary"]


def test_merge_source_facts_preserve_legacy_and_refreshable_on_empty_refresh():
    existing = [{
        "Item_ID": "ITM-1", "Source_ID": "FRENCHBREACHES", "Threat_Actor": "ZeroBytes",
        "Summary": "old-summary", "Impact": "old-impact",
        "Evidence_JSON": json.dumps({"Threat_Actor": "proof actor", "Summary": "old proof", "Impact": "old impact"}),
    }]
    incoming = [{
        "Item_ID": "ITM-1", "Source_ID": "FRENCHBREACHES", "Threat_Actor": "",
        "Summary": "", "Impact": "", "Evidence_JSON": "",
    }]
    merged = source_facts.merge_source_facts(existing, incoming)[0]
    assert merged["Threat_Actor"] == "ZeroBytes"
    assert merged["Summary"] == "old-summary"
    assert merged["Impact"] == "old-impact"
    evidence = json.loads(merged["Evidence_JSON"])
    assert evidence["Threat_Actor"] == "proof actor"
    assert evidence["Summary"] == "old proof"
    assert evidence["Impact"] == "old impact"



def test_summary_fallback_depuis_faits_structures_sans_appel_ai():
    fact = {
        "Summary": "",
        "Initial_Access": "",
        "Impact": "",
        "Affected_Count_Raw": "",
        "Affected_Unit": "",
        "File_Count": "39000",
        "Data_Types_JSON": json.dumps(["adresses e-mail", "données bancaires"]),
    }
    evidence = {
        "File_Count": "39 000 fichiers",
        "Data_Types_JSON": {
            "adresses e-mail": "adresses e-mail",
            "données bancaires": "données bancaires",
        },
    }
    source_facts._derive_summary(fact, evidence)
    assert fact["Summary"] == (
        "Éléments documentés : 39 000 fichiers ; "
        "données concernées : adresses e-mail et données bancaires."
    )
    assert evidence["Summary"]


def test_summary_fallback_ne_duplique_pas_un_compteur_de_fichiers():
    fact = {
        "Summary": "",
        "Initial_Access": "",
        "Impact": "",
        "Affected_Count_Raw": "49 168 fichiers",
        "Affected_Unit": "files",
        "File_Count": "49168",
        "Data_Types_JSON": "",
    }
    evidence = {"Affected_Count_Raw": "49 168 fichiers"}
    source_facts._derive_summary(fact, evidence)
    assert fact["Summary"] == "Éléments documentés : 49 168 fichiers."


def test_summary_fallback_s_abstient_sur_un_seul_type_isole():
    fact = {
        "Summary": "",
        "Initial_Access": "",
        "Attack_Flow_JSON": "",
        "Impact": "",
        "Data_Volume_Raw": "",
        "Affected_Count_Raw": "",
        "Affected_Unit": "",
        "File_Count": "",
        "Data_Types_JSON": json.dumps(["mots de passe"]),
    }
    evidence = {"Data_Types_JSON": {"mots de passe": "mots de passe"}}
    source_facts._derive_summary(fact, evidence)
    assert fact["Summary"] == ""
