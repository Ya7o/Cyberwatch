from cyberwatch import fact_resolution as fr


def fact(source, **values):
    return {"source": source, "item_id": f"ITM-{source}", **values}


def test_priorite_source_et_fallback_scalaire():
    facts = [
        fact("FRENCHBREACHES", threat_actor="acteur secondaire"),
        fact("RANSOMWARE_LIVE", threat_actor="acteur prioritaire"),
    ]
    resolved = fr.resolve_incident_facts(facts)
    assert resolved["fields"]["threat_actor"]["value"] == "acteur prioritaire"
    assert resolved["fields"]["threat_actor"]["source"] == "RANSOMWARE_LIVE"

    fallback = fr.resolve_incident_facts([
        fact("RANSOMWARE_LIVE", threat_actor=""),
        fact("CYBERATTAQUE_ORG", threat_actor="acteur documenté"),
    ])
    assert fallback["fields"]["threat_actor"]["value"] == "acteur documenté"


def test_valeur_identique_agrege_les_sources():
    resolved = fr.resolve_incident_facts([
        fact("RANSOMWARE_LIVE", third_party="Prestataire X"),
        fact("CYBERATTAQUE_ORG", third_party="Prestataire X"),
    ])
    field = resolved["fields"]["third_party"]
    assert field["source"] == "RANSOMWARE_LIVE"
    assert field["sources"] == ["RANSOMWARE_LIVE", "CYBERATTAQUE_ORG"]


def test_listes_complementaires_sont_fusionnees_sans_doublons():
    resolved = fr.resolve_incident_facts([
        fact("CYBERATTAQUE_ORG", data_types=["Nom", "Téléphone"]),
        fact("FRENCHBREACHES", data_types=["nom", "Date de naissance"]),
    ])
    values = [entry["value"] for entry in resolved["data_types"]]
    assert values == ["Nom", "Téléphone", "Date de naissance"]
    assert resolved["data_types"][0]["sources"] == ["CYBERATTAQUE_ORG", "FRENCHBREACHES"]


def test_records_total_et_uniques_ne_sont_pas_ecrases():
    resolved = fr.resolve_incident_facts([
        fact("RANSOMWARE_LIVE", rich_facts={"affected_counts": [
            {"value": 10_279_819, "unit": "records", "scope": "total", "status": "claimed"},
            {"value": 5_169_727, "unit": "records", "scope": "unique après déduplication", "status": "claimed"},
        ]}),
        fact("CYBERATTAQUE_ORG", rich_facts={"affected_counts": [
            {"value": 5_160_000, "unit": "clients", "scope": "clients concernés", "status": "reported"},
        ]}),
    ])
    semantics = {(row["unit"], row["semantic"]): row["value"] for row in resolved["affected"]}
    assert semantics[("records", "total")] == 10_279_819
    assert semantics[("records", "unique")] == 5_169_727
    assert semantics[("clients", "clients concernes")] == 5_160_000


def test_conflit_meme_semantique_garde_source_prioritaire():
    resolved = fr.resolve_incident_facts([
        fact("RANSOMWARE_LIVE", rich_facts={"affected_counts": [
            {"value": 1000, "unit": "records", "scope": "total", "status": "claimed"},
        ]}),
        fact("CYBERATTAQUE_ORG", rich_facts={"affected_counts": [
            {"value": 900, "unit": "records", "scope": "total", "status": "reported"},
        ]}),
    ])
    assert len(resolved["affected"]) == 1
    assert resolved["affected"][0]["value"] == 1000
    assert resolved["affected"][0]["source"] == "RANSOMWARE_LIVE"


def test_statut_revendique_est_conserve_et_resume_deterministe():
    resolved = fr.resolve_incident_facts([
        fact("RANSOMWARE_LIVE", rich_facts={"affected_counts": [
            {"value": 10_279_819, "unit": "records", "scope": "total", "status": "claimed"},
        ]}, data_types=["emails", "téléphones"]),
    ])
    assert resolved["affected"][0]["status"] == "claimed"
    assert "revendiqué" in resolved["display_summary"]
    assert "Données exposées" in resolved["display_summary"]


def test_source_inconnue_passe_apres_sources_connues():
    assert fr.source_rank("RANSOMWARE_LIVE") < fr.source_rank("SOURCE_EXTERNE")


def test_resultat_est_deterministe_independamment_de_l_ordre_entree():
    facts = [
        fact("FRENCHBREACHES", threat_actor="B", data_types=["Nom"]),
        fact("CYBERATTAQUE_ORG", threat_actor="A", data_types=["Email"]),
    ]
    assert fr.resolve_incident_facts(facts) == fr.resolve_incident_facts(list(reversed(facts)))
