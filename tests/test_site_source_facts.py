"""Contrat de publication des faits source dans le dashboard.

La couche reste auxiliaire : provenance par Item_ID, aucune fusion arbitraire
entre sources et aucune mutation des champs canoniques de l'incident.
"""

from cyberwatch import identity, site
from cyberwatch.model import Incident, Item


def _item(item_id: str, source_id: str, date: str = "2026-08-10") -> Item:
    return Item(
        Item_ID=item_id,
        Source_ID=source_id,
        Published_Date=date,
        Organisation_Raw="Exemple SA",
        Organisation_Key="exemple sa",
        Threat="Fuite de données",
        Sector="Commerce / Distribution",
        Location="France métropolitaine",
        Title="Fuite chez Exemple SA",
        URL=f"https://example.test/{item_id}",
    )


def _incident(incident_id: str) -> Incident:
    return Incident(
        Incident_ID=incident_id,
        Date="2026-08-10",
        Date_Basis="PUBLICATION",
        Organisation="Exemple SA",
        Secteur="Commerce / Distribution",
        Menace="Fuite de données",
        Localisation="France métropolitaine",
        Sources="FRENCHBREACHES",
        Source_URLs="https://example.test/ITM-a",
        Items_Count=1,
        First_seen="2026-08-10T00:00:00Z",
        Last_seen="2026-08-10T00:00:00Z",
    )


def test_source_fact_payload_omet_les_champs_vides_et_parse_les_listes():
    payload = site._source_fact_payload({
        "Item_ID": "ITM-a",
        "Source_ID": "FRENCHBREACHES",
        "Threat_Actor": "ShinyHunters",
        "Third_Party": "",
        "Affected_Count": "2800000",
        "Affected_Unit": "records",
        "Affected_Count_Raw": "2,8 millions d'enregistrements",
        "Data_Types_JSON": '["emails","noms"]',
        "Vulnerabilities_JSON": '["CVE-2026-12345"]',
        "Initial_Access": "vulnerability_exploitation",
        "Attack_Flow_JSON": '[{"action":"Exploitation CVE","evidence":"CVE exploitée"},{"action":"Exfiltration","evidence":"données exfiltrées"}]',
        "Evidence_URLs_JSON": '["https://example.test/preuve"]',
        "Extraction_Method": "FRENCHBREACHES",
        "Evidence_JSON": '{"debug":true}',
    })

    assert payload == {
        "source": "FRENCHBREACHES",
        "item_id": "ITM-a",
        "threat_actor": "ShinyHunters",
        "affected_count": 2800000,
        "affected_unit": "records",
        "affected_count_raw": "2,8 millions d'enregistrements",
        "initial_access": "vulnerability_exploitation",
        "data_types": ["emails", "noms"],
        "vulnerabilities": ["CVE-2026-12345"],
        "evidence_urls": ["https://example.test/preuve"],
        "attack_flow": [
            {"action": "Exploitation CVE", "evidence": "CVE exploitée"},
            {"action": "Exfiltration", "evidence": "données exfiltrées"},
        ],
    }
    assert "third_party" not in payload
    assert "Evidence_JSON" not in payload
    assert "Extraction_Method" not in payload


def test_attack_flow_invalide_est_ignore_sans_casser_le_payload():
    payload = site._source_fact_payload({
        "Item_ID": "ITM-a",
        "Source_ID": "FRENCHBREACHES",
        "Summary": "Synthèse utile",
        "Attack_Flow_JSON": '[{"action":"Sans preuve"},{"evidence":"sans action"},"invalide"]',
    })
    assert payload["summary"] == "Synthèse utile"
    assert "attack_flow" not in payload


def test_veille_llm_reste_sur_son_renderer_historique():
    assert site._source_fact_payload({
        "Item_ID": "ITM-local",
        "Source_ID": "VEILLE_LLM",
        "Cyberattack_Score": "100",
        "Summary": "Synthèse",
    }) is None


def test_fait_sans_donnee_publiable_est_ignore():
    assert site._source_fact_payload({
        "Item_ID": "ITM-a",
        "Source_ID": "FRENCHBREACHES",
        "Source_Sector_Raw": "Retail",
        "Activity_Description": "commerce spécialisé",
        "Evidence_JSON": "{}",
    }) is None


def test_jointure_par_item_id_conserve_les_sources_separees():
    items = [
        _item("ITM-a", "FRENCHBREACHES"),
        _item("ITM-b", "RANSOMWARE_LIVE"),
    ]
    rows = [
        {"Item_ID": "ITM-a", "Source_ID": "FRENCHBREACHES", "Threat_Actor": "ShinyHunters"},
        {"Item_ID": "ITM-b", "Source_ID": "RANSOMWARE_LIVE", "Threat_Actor": "LockBit"},
        {"Item_ID": "ITM-orphan", "Source_ID": "FRENCHBREACHES", "Threat_Actor": "Orphelin"},
    ]

    facts = site._source_facts_by_incident(items, rows)
    assert len(facts) == 1
    incident_facts = next(iter(facts.values()))
    assert [(fact["source"], fact["threat_actor"]) for fact in incident_facts] == [
        ("FRENCHBREACHES", "ShinyHunters"),
        ("RANSOMWARE_LIVE", "LockBit"),
    ]
    assert all(fact["threat_actor"] != "Orphelin" for fact in incident_facts)


def test_best_summary_prend_la_source_la_plus_riche_sans_fusion_llm():
    facts = [
        {
            "source": "CYBERATTAQUE_ORG", "item_id": "ITM-a",
            "summary": "Synthèse pauvre.", "impact": "Impact",
        },
        {
            "source": "FRENCHBREACHES", "item_id": "ITM-b",
            "summary": "Synthèse documentée.",
            "initial_access": "compromised_credentials",
            "attack_flow": [{"action": "Intrusion", "evidence": "preuve"}],
            "impact": "Impact", "threat_actor": "Groupe X",
        },
    ]
    assert site._best_source_summary(facts) == "Synthèse documentée."


def test_best_summary_est_stable_en_cas_degalite():
    facts = [
        {"source": "CYBERATTAQUE_ORG", "item_id": "ITM-a", "summary": "A", "impact": "x"},
        {"source": "FRENCHBREACHES", "item_id": "ITM-b", "summary": "B", "impact": "x"},
    ]
    first = site._best_source_summary(facts)
    second = site._best_source_summary(list(reversed(facts)))
    assert first == second


def test_incident_sans_faits_garde_exactement_le_payload_compact():
    item = _item("ITM-a", "FRENCHBREACHES")
    incident_id = identity.incident_id(item.Organisation_Key, item.Item_ID)
    row = site.incidents_payload([_incident(incident_id)])[0]
    assert "facts" not in row
    assert "summary" not in row


def test_incident_avec_faits_ne_modifie_aucun_champ_canonique_et_expose_summary():
    item = _item("ITM-a", "FRENCHBREACHES")
    incident_id = identity.incident_id(item.Organisation_Key, item.Item_ID)
    incident = _incident(incident_id)
    source_facts = {
        incident_id: [{
            "source": "FRENCHBREACHES",
            "item_id": "ITM-a",
            "threat_actor": "ShinyHunters",
            "summary": "Intrusion documentée ayant exposé des données clients.",
        }]
    }

    row = site.incidents_payload([incident], source_facts=source_facts)[0]
    assert row["org"] == "Exemple SA"
    assert row["sector"] == "Commerce / Distribution"
    assert row["threat"] == "Fuite de données"
    assert row["location"] == "France métropolitaine"
    assert row["date"] == "2026-08-10"
    assert row["facts"] == source_facts[incident_id]
    assert row["summary"] == "Intrusion documentée ayant exposé des données clients."


def test_build_charge_explicitement_source_facts():
    source = open("cyberwatch/site.py", encoding="utf-8").read()
    assert "store.load_source_facts()" in source


def test_renderer_ui_est_conditionnel_et_sans_nouvelles_colonnes():
    """La table `#incidents-table` a été retirée (masquée par CSS, jamais
    affichée) : la fiche riche vit maintenant uniquement dans le dialogue
    partagé des trois vues. Seule cette destination est encore un contrat."""
    js = open("assets/dashboard.js", encoding="utf-8").read()

    assert "function factHtml(fact, incidentSummary" in js
    assert "function factsSectionHtml(incident, facts)" in js
    assert "const rendered = (facts || []).map((fact) => factHtml(fact, incident.summary))" in js
    assert "attackFlowLabel" in js
    assert "renderDataTypes(fact.data_types)" in js


def test_renderer_ui_ne_duplique_pas_affected_files_et_file_count():
    js = open("assets/dashboard.js", encoding="utf-8").read()
    assert "function duplicatesDedicatedFileCount(fact)" in js
    assert 'String(fact.affected_unit || "").trim().toLowerCase() !== "files"' in js
    assert 'factRow("Données touchées", duplicatesDedicatedFileCount(fact) ? "" : affectedLabel(fact))' in js
    assert 'factRow("Fichiers", fact.file_count != null ? formatNumber(fact.file_count) : "")' in js
