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


def test_nom_organisation_n_est_jamais_une_synthese_publiable():
    assert not fr.is_publishable_summary("Exemple SA", organisation="Exemple SA")
    assert fr.best_publishable_summary([
        fact("CYBERATTAQUE_ORG", summary="Exemple SA"),
        fact("FRENCHBREACHES", summary="Exemple SA subit une fuite de données clients."),
    ], organisation="Exemple SA") == "Exemple SA subit une fuite de données clients."


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


def test_conflit_cross_format_meme_unite_conserve_les_mesures_distinctes():
    resolved = fr.resolve_incident_facts([
        fact("RANSOMWARE_LIVE", affected_count=10_000, affected_unit="records", claim_status="claimed"),
        fact("CYBERATTAQUE_ORG", rich_facts={"affected_counts": [
            {"value": 9_000, "unit": "records", "scope": "total", "status": "reported"},
        ]}),
    ])
    assert {row["value"] for row in resolved["affected"]} == {9_000, 10_000}


def test_conflit_meme_semantique_conserve_les_valeurs_sourcees():
    resolved = fr.resolve_incident_facts([
        fact("RANSOMWARE_LIVE", rich_facts={"affected_counts": [
            {"value": 1000, "unit": "records", "scope": "total", "status": "claimed"},
        ]}),
        fact("CYBERATTAQUE_ORG", rich_facts={"affected_counts": [
            {"value": 900, "unit": "records", "scope": "total", "status": "reported"},
        ]}),
    ])
    assert {row["value"] for row in resolved["affected"]} == {900, 1000}


def test_claims_timeline_et_systemes_semantiques_sont_publies():
    resolved = fr.resolve_incident_facts([fact("CYBERATTAQUE_ORG", rich_facts={
        "claims": [{"type": "actor", "value": "ZeroBytes", "status": "claimed", "evidence": "ZeroBytes revendique l'accès."}, {"type": "system", "value": "Pilot", "status": "reported", "evidence": "Le système Pilot est concerné."}],
        "timeline": [{"date": "2026-08-19", "event": "Publication de la revendication", "status": "reported", "evidence": "L'article est publié le 19 août."}],
    })])
    assert resolved["claims"][0]["status"] == "claimed"
    assert resolved["systems"][0]["value"] == "Pilot"
    assert resolved["timeline"][0]["event"] == "Publication de la revendication"


def test_type_de_donnee_numerique_ou_trop_long_est_rejete():
    resolved = fr.resolve_incident_facts([fact("CYBERATTAQUE_ORG", data_types=["779750", "x" * 121, "IBAN"])])
    assert [entry["value"] for entry in resolved["data_types"]] == ["IBAN"]


def test_claim_legacy_sans_type_et_relation_sont_repares_prudemment():
    resolved = fr.resolve_incident_facts([fact("CYBERATTAQUE_ORG", rich_facts={
        "claims": [{"value": "ZeroBytes", "status": "claimed", "evidence": "ZeroBytes revendique l'accès à Pilot."}],
        "relations": [{"subject": "Sport 2000", "relation": "claimed_by", "object": "ZeroBytes", "status": "claimed", "evidence": "ZeroBytes revendique l'accès à Pilot."}],
    })])
    assert any(row["type"] == "actor" and row["value"] == "ZeroBytes" for row in resolved["claims"])


def test_reparation_legacy_ne_transforme_pas_un_libelle_technique_en_acteur():
    resolved = fr.resolve_incident_facts([fact("CYBERATTAQUE_ORG", rich_facts={
        "claims": [{"value": "publication des données", "status": "claimed", "evidence": "La publication des données est revendiquée."}],
    })])
    assert resolved["claims"][0]["type"] != "actor"


def test_organisation_victime_ne_peut_pas_etre_affichee_comme_acteur():
    resolved = fr.resolve_incident_facts([fact("CYBERATTAQUE_ORG", rich_facts={
        "claims": [{"type": "actor", "value": "SUEZ Eau France", "status": "confirmed", "evidence": "SUEZ Eau France confirme l'incident."}],
    })], organisation="SUEZ")
    assert resolved["claims"] == []


def test_claim_acteur_type_alimente_le_champ_detail_sans_ecraser_un_scalaire():
    resolved = fr.resolve_incident_facts([fact("CYBERATTAQUE_ORG", rich_facts={
        "claims": [{"type": "actor", "value": "ZeroBytes", "status": "claimed", "evidence": "ZeroBytes revendique l'accès."}],
    })])
    assert resolved["fields"]["threat_actor"]["value"] == "ZeroBytes"


def test_prestataire_nomme_dans_la_preuve_alimente_un_tiers_sans_identite_inventee():
    resolved = fr.resolve_incident_facts([fact("CYBERATTAQUE_ORG", rich_facts={
        "claims": [{"status": "confirmed", "evidence": "L'incident a touché un prestataire technique de la victime."}],
    })])
    assert resolved["fields"]["third_party"]["value"] == "prestataire technique"


def test_acteur_cite_sans_preuve_n_est_pas_choisi_comme_acteur_principal():
    resolved = fr.resolve_incident_facts([fact("CYBERATTAQUE_ORG", rich_facts={
        "claims": [
            {"type": "actor", "value": "ZeroBytes", "status": "claimed", "evidence": "Des éléments plus précis sur l'exfiltration."},
            {"type": "actor", "value": "misere", "status": "claimed", "evidence": "Le hacker misere revendique la fuite."},
        ],
    })])
    assert resolved["fields"]["threat_actor"]["value"] == "misere"


def test_tiers_ne_devient_pas_systeme_concerne():
    resolved = fr.resolve_incident_facts([fact("CYBERATTAQUE_ORG", rich_facts={
        "affected_systems": [{"value": "prestataire technique de la victime", "status": "confirmed"}],
    })])
    assert resolved["systems"] == []


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
    assert resolved["display_summary"] == ""


def test_protection_civile_fusionne_volume_et_types_de_donnees():
    resolved = fr.resolve_incident_facts([
        fact("CYBERATTAQUE_ORG", affected_count=525_000, affected_unit="people", claim_status="reported", data_types=["Noms", "Prénoms", "Téléphones"]),
        fact("FRENCHBREACHES", data_types=["noms", "Dates de naissance"]),
    ])
    assert resolved["affected"][0]["value"] == 525_000
    assert [entry["value"] for entry in resolved["data_types"]] == ["Noms", "Prénoms", "Téléphones", "Dates de naissance"]


def test_data_types_rich_et_legacy_sont_fusionnes_sans_doublon():
    resolved = fr.resolve_incident_facts([
        fact("CYBERATTAQUE_ORG", rich_facts={"data_types": [
            {"value": "Adresses e-mail", "status": "confirmed"},
            {"value": "Numéros de téléphone", "status": "reported"},
        ]}),
        fact("FRENCHBREACHES", data_types=["adresses e-mail", "Dates de naissance"]),
    ])
    values = [entry["value"] for entry in resolved["data_types"]]
    assert values == ["Adresses e-mail", "Numéros de téléphone", "Dates de naissance"]


def test_data_type_rich_negated_is_not_published_as_exposed():
    resolved = fr.resolve_incident_facts([
        fact("CYBERATTAQUE_ORG", rich_facts={"data_types": [
            {"value": "IBAN / RIB", "status": "negated"},
            {"value": "Adresses e-mail", "status": "reported"},
        ]}),
    ])
    assert [entry["value"] for entry in resolved["data_types"]] == ["Adresses e-mail"]


def test_statut_revendique_est_conserve_et_resume_deterministe():
    resolved = fr.resolve_incident_facts([
        fact("RANSOMWARE_LIVE", rich_facts={"affected_counts": [
            {"value": 10_279_819, "unit": "records", "scope": "total", "status": "claimed"},
        ]}, data_types=["emails", "téléphones"]),
    ])
    assert resolved["affected"][0]["status"] == "claimed"
    assert resolved["display_summary"] == ""


def test_legacy_sans_unite_est_ignore():
    resolved = fr.resolve_incident_facts([fact("CYBERATTAQUE_ORG", affected_count=42, affected_unit="")])
    assert resolved["affected"] == []


def test_dinum_impact_narratif_prime_sur_metrique_seule():
    """Point 3 : un article riche ne doit pas se réduire à « X lignes (documenté). »
    quand un impact narratif validé est disponible."""
    resolved = fr.resolve_incident_facts([
        fact(
            "CYBERATTAQUE_ORG", affected_count=31_544, affected_unit="records", claim_status="unknown",
            impact="Les services numériques de la DINUM ont été rendus indisponibles pendant plusieurs jours.",
        ),
    ], fallback_summary="31 544 enregistrements (documenté).")
    assert resolved["display_summary"] == ""


def test_made_in_bebe_fallback_narratif_prime_sur_metrique_seule_multi_source():
    """Point 4 : une fusion multi-source sans impact narratif propre ne doit
    pas écraser un fallback riche par la seule métrique agrégée."""
    fallback = (
        "Made in Bébé confirme une fuite de données clients après une intrusion "
        "sur son site marchand, revendiquée par un groupe cybercriminel."
    )
    resolved = fr.resolve_incident_facts([
        fact("CYBERATTAQUE_ORG", affected_count=960_106, affected_unit="people", claim_status="claimed"),
        fact("FRENCHBREACHES", data_types=["emails", "adresses postales"]),
    ], fallback_summary=fallback)
    assert resolved["display_summary"] == fallback


def test_claim_documente_prime_sur_metrique_et_fallback():
    """Point 3 : un claim riche est plus informatif qu'un compte seul."""
    claim = "La base mise en vente contient des informations issues du service client."
    resolved = fr.resolve_incident_facts([
        fact("CYBERATTAQUE_ORG", affected_count=960_106, affected_unit="people", claim_status="claimed",
             rich_facts={"claims": [{"type": "statement", "status": "reported", "value": "base client", "evidence": claim}]}),
    ], fallback_summary="Plus de 960 000 personnes seraient concernées par une fuite de données.")
    assert resolved["display_summary"] == "Plus de 960 000 personnes seraient concernées par une fuite de données."


def test_metrique_seule_reste_utilisee_sans_fallback_substantiel():
    """La métrique reste affichée telle quelle quand aucun fallback riche
    n'existe (pas de régression sur le comportement historique)."""
    resolved = fr.resolve_incident_facts([
        fact("CYBERATTAQUE_ORG", affected_count=31_544, affected_unit="records", claim_status="unknown"),
    ], fallback_summary="")
    assert resolved["display_summary"] == ""


def test_synthese_technique_ou_generique_est_rejetee():
    assert not fr.is_publishable_summary("Vecteur d’entrée documenté : l’exploitation d’une vulnérabilité.")
    assert not fr.is_publishable_summary("Impact documenté : les services sont perturbés.")
    assert not fr.is_publishable_summary("Déroulé documenté : accès → exfiltration.")
    assert not fr.is_publishable_summary("Données concernées : e-mails, IBAN.")
    assert not fr.is_publishable_summary("Données exposées : e-mails, IBAN.")
    assert not fr.is_publishable_summary("L'incident a entraîné une exfiltration de données.")
    assert not fr.is_publishable_summary("Groupe Géotec a confirmé une exfiltration de données suite à un incident de cybersécurité.")
    assert not fr.is_publishable_summary("43 Go — grosse amélioration de la vitesse d’apparition visuelle.")


def test_synthese_editoriale_une_phrase_est_conservee():
    headline = "Réserver aurait exposé 19 495 enregistrements après une mauvaise configuration d’API."
    assert fr.resolve_incident_facts([], fallback_summary=headline)["display_summary"] == headline


def test_headline_acceptee_d_une_source_ne_peut_pas_etre_masquee_par_un_detail_rejete():
    facts = [
        fact("CYBERATTAQUE_ORG", summary="Éléments documentés : 20 fichiers."),
        fact("FRENCHBREACHES", summary="Protection Civile signale une fuite touchant plus de 525 000 profils."),
    ]
    assert fr.best_publishable_summary(facts).startswith("Protection Civile")


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
