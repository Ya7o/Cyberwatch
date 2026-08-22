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


def test_rich_et_legacy_complementaires_survivent_ensemble():
    resolved = fr.resolve_incident_facts([
        fact("RANSOMWARE_LIVE", rich_facts={"affected_counts": [
            {"value": 10_279_819, "unit": "records", "scope": "total", "status": "claimed"},
        ]}),
        fact("CYBERATTAQUE_ORG", affected_count=525_000, affected_unit="people", claim_status="reported"),
    ])
    values = {(row["unit"], row["semantic"]): row["value"] for row in resolved["affected"]}
    assert values[("records", "total")] == 10_279_819
    assert values[("people", "unspecified")] == 525_000


def test_legacy_identique_au_rich_ne_cree_pas_de_doublon():
    resolved = fr.resolve_incident_facts([
        fact("RANSOMWARE_LIVE", rich_facts={"affected_counts": [
            {"value": 10_000, "unit": "records", "scope": "total", "status": "claimed"},
        ]}, affected_count=10_000, affected_unit="records", claim_status="claimed"),
    ])
    assert len(resolved["affected"]) == 1
    assert resolved["affected"][0]["semantic"] == "total"


def test_conflit_cross_format_meme_unite_garde_source_prioritaire_si_semantique_non_ambigue():
    resolved = fr.resolve_incident_facts([
        fact("RANSOMWARE_LIVE", affected_count=10_000, affected_unit="records", claim_status="claimed"),
        fact("CYBERATTAQUE_ORG", rich_facts={"affected_counts": [
            {"value": 9_000, "unit": "records", "scope": "total", "status": "reported"},
        ]}),
    ])
    assert len(resolved["affected"]) == 1
    assert resolved["affected"][0]["value"] == 10_000
    assert resolved["affected"][0]["source"] == "RANSOMWARE_LIVE"


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


def test_beauty_success_conserve_les_trois_concepts_distincts():
    resolved = fr.resolve_incident_facts([
        fact("RANSOMWARE_LIVE", rich_facts={"affected_counts": [
            {"value": 10_279_819, "unit": "records", "scope": "total", "status": "claimed"},
            {"value": 5_169_727, "unit": "records", "scope": "unique", "status": "claimed"},
        ]}),
        fact("CYBERATTAQUE_ORG", affected_count=5_160_000, affected_unit="clients", claim_status="reported"),
    ])
    assert {(r["unit"], r["semantic"]) for r in resolved["affected"]} == {
        ("records", "total"), ("records", "unique"), ("clients", "unspecified")
    }
    assert resolved["display_summary"].startswith("5 160 000 clients")


def test_protection_civile_fusionne_volume_et_types_de_donnees():
    resolved = fr.resolve_incident_facts([
        fact("CYBERATTAQUE_ORG", affected_count=525_000, affected_unit="people", claim_status="reported", data_types=["Noms", "Prénoms", "Téléphones"]),
        fact("FRENCHBREACHES", data_types=["noms", "Dates de naissance"]),
    ])
    assert resolved["affected"][0]["value"] == 525_000
    assert [entry["value"] for entry in resolved["data_types"]] == ["Noms", "Prénoms", "Téléphones", "Dates de naissance"]


def test_statut_revendique_est_conserve_et_resume_deterministe():
    resolved = fr.resolve_incident_facts([
        fact("RANSOMWARE_LIVE", rich_facts={"affected_counts": [
            {"value": 10_279_819, "unit": "records", "scope": "total", "status": "claimed"},
        ]}, data_types=["emails", "téléphones"]),
    ])
    assert resolved["affected"][0]["status"] == "claimed"
    assert "revendiqué" in resolved["display_summary"]
    assert "Données exposées" in resolved["display_summary"]


def test_legacy_sans_unite_est_ignore():
    resolved = fr.resolve_incident_facts([fact("CYBERATTAQUE_ORG", affected_count=42, affected_unit="")])
    assert resolved["affected"] == []


def test_source_inconnue_passe_apres_sources_connues():
    assert fr.source_rank("RANSOMWARE_LIVE") < fr.source_rank("SOURCE_EXTERNE")


def test_resultat_est_deterministe_independamment_de_l_ordre_entree():
    facts = [
        fact("FRENCHBREACHES", threat_actor="B", data_types=["Nom"], affected_count=100, affected_unit="people"),
        fact("CYBERATTAQUE_ORG", threat_actor="A", data_types=["Email"], rich_facts={"affected_counts": [
            {"value": 200, "unit": "records", "scope": "total", "status": "reported"},
        ]}),
    ]
    assert fr.resolve_incident_facts(facts) == fr.resolve_incident_facts(list(reversed(facts)))
