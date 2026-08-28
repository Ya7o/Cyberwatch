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
    # "Téléphone"/"Date de naissance" sont ramenés à leur forme canonique
    # (cf. canonical_data_type()) ; "Nom" seul ne matche aucun motif connu et
    # reste tel quel — précision plutôt qu'une fusion devinée.
    assert values == ["Nom", "numéros de téléphone", "dates de naissance"]
    assert resolved["data_types"][0]["sources"] == ["CYBERATTAQUE_ORG", "FRENCHBREACHES"]


def test_type_de_donnee_mentionne_apres_pas_de_n_est_pas_publie():
    resolved = fr.resolve_incident_facts([fact(
        "CYBERATTAQUE_ORG",
        rich_facts={"data_types": [{
            "value": "mots de passe",
            "status": "unknown",
            "evidence": "Pas de mots de passe ni de cartes bancaires concernés.",
        }]},
    )])

    assert resolved["data_types"] == []


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


def test_chiffre_demente_n_est_pas_publie():
    """Cas réel (audit 2026-08-25, Banque Alimentaire de la Croix-Rouge à
    Strasbourg) : quand la seule valeur disponible est explicitement
    démentie par l'article, elle ne doit pas s'afficher comme un fait
    ordinaire — même garde que _data_types_entries pour negated/denied,
    jusqu'ici absente côté affected[]."""
    resolved = fr.resolve_incident_facts([
        fact("CYBERATTAQUE_ORG", rich_facts={"affected_counts": [
            {"value": 10_073, "unit": "records", "scope": "total", "status": "negated"},
        ]}),
    ])
    assert resolved["affected"] == []


def test_chiffre_hypothetique_et_son_repli_legacy_ne_sont_pas_publies():
    resolved = fr.resolve_incident_facts([fact(
        "FRENCHBREACHES",
        affected_count=18_875,
        affected_unit="clients",
        claim_status="claimed",
        rich_facts={"affected_counts": [{
            "value": 18_875,
            "unit": "clients",
            "status": "hypothesis",
            "evidence": "18 875 clients potentiellement concernés.",
        }]},
    )])

    assert resolved["affected"] == []


def test_projection_unknown_du_meme_chiffre_hypothetique_est_aussi_rejetee():
    resolved = fr.resolve_incident_facts([fact("CYBERATTAQUE_ORG", rich_facts={
        "affected_counts": [
            {
                "value": 12_400,
                "unit": "clients",
                "status": "hypothesis",
                "evidence": "L'attaquant aurait pu accéder à 12 400 clients.",
            },
            {
                "value": 12_400,
                "unit": "clients",
                "status": "unknown",
                "evidence": "12 400 clients dans une chronologie non confirmée.",
            },
        ],
    })])

    assert resolved["affected"] == []


def test_chiffre_demente_ne_masque_pas_le_chiffre_confirme():
    resolved = fr.resolve_incident_facts([
        fact("CYBERATTAQUE_ORG", rich_facts={"affected_counts": [
            {"value": 1_899_454, "unit": "records", "scope": "total", "status": "claimed"},
        ]}),
        fact("FRENCHBREACHES", affected_count=42, affected_unit="people", claim_status="negated"),
    ])
    values = {(row["unit"], row["value"]) for row in resolved["affected"]}
    assert ("records", 1_899_454) in values
    assert ("people", 42) not in values


def test_chiffre_rond_et_precis_ne_produisent_qu_une_seule_entree():
    """Cas réels (audit 2026-08-25) : Groupe Bernard (330 563 vs 330 000
    fichiers), Banque Alimentaire de la Croix-Rouge à Strasbourg (10 073 vs
    10 000) — deux sources rapportant le même volume avec une précision
    différente, jusqu'ici affichées comme deux chiffres distincts."""
    resolved = fr.resolve_incident_facts([
        fact("CYBERATTAQUE_ORG", rich_facts={"affected_counts": [
            {"value": 330_563, "unit": "files", "scope": "total", "status": "claimed"},
        ]}),
        fact("FRENCHBREACHES", rich_facts={"affected_counts": [
            {"value": 330_000, "unit": "files", "scope": "total", "status": "claimed"},
        ]}),
    ])
    assert len(resolved["affected"]) == 1
    assert resolved["affected"][0]["value"] == 330_563
    assert set(resolved["affected"][0]["sources"]) == {"CYBERATTAQUE_ORG", "FRENCHBREACHES"}


def test_meme_chiffre_avec_et_sans_raw_ne_produit_qu_une_seule_entree():
    """Cas réel constaté sur données publiées (reset 2026-08-25, Groupe
    Bernard) : la fiche affichait "330 563 fichiers" deux fois. L'extraction
    amont avait rempli `scope` avec le nom de l'organisation sur une partie
    des enregistrements, ce qui leur donnait une sémantique distincte, et
    l'enregistrement survivant de ce groupe avait perdu son `raw`. Les deux
    entrées s'affichaient pourtant au texte identique (l'une depuis `raw`,
    l'autre reconstruite depuis `value`+`unit`) : c'est bien un doublon
    visuel, quelle que soit la cause amont."""
    resolved = fr.resolve_incident_facts([
        fact("CYBERATTAQUE_ORG", rich_facts={"affected_counts": [
            {"value": 330_563, "unit": "files", "raw": "330 563 fichiers", "status": "claimed"},
            {"value": 330_563, "unit": "files", "raw": "", "scope": "Groupe Bernard", "status": "reported"},
        ]}),
    ])
    assert len(resolved["affected"]) == 1
    assert resolved["affected"][0]["value"] == 330_563


def test_claims_timeline_et_systemes_semantiques_sont_publies():
    resolved = fr.resolve_incident_facts([fact("CYBERATTAQUE_ORG", rich_facts={
        "claims": [{"type": "actor", "value": "ZeroBytes", "status": "claimed", "evidence": "ZeroBytes revendique l'accès."}, {"type": "system", "value": "Pilot", "status": "reported", "evidence": "Le système Pilot est concerné."}],
        "timeline": [{"date": "2026-08-19", "event": "Publication de la revendication", "status": "reported", "evidence": "L'article est publié le 19 août."}],
    })])
    assert resolved["claims"][0]["status"] == "claimed"
    assert resolved["systems"][0]["value"] == "Pilot"
    assert resolved["timeline"][0]["event"] == "Publication de la revendication"


def test_claim_statement_dupliquant_une_entree_timeline_est_ecarte():
    """Cas réel constaté sur SUEZ : un claim `statement` (destiné à "Faits
    sourcés") reprenait mot pour mot l'evidence d'une entrée `timeline`."""
    evidence = "L'attaque a permis à des personnes malveillantes d'accéder à certaines données et de les extraire."
    resolved = fr.resolve_incident_facts([fact("CYBERATTAQUE_ORG", rich_facts={
        "claims": [{"type": "statement", "value": "Accès et extraction de données", "status": "confirmed", "evidence": evidence}],
        "timeline": [{"date": "2026-08-20", "event": "Accès et extraction", "status": "confirmed", "evidence": evidence}],
    })])
    assert resolved["claims"] == []
    assert resolved["timeline"][0]["event"] == "Accès et extraction"


def test_markdown_brut_est_retire_de_la_chronologie():
    """Cas réel constaté sur FRENCHBREACHES (Déclic Services, Solimut) : des
    astérisques Markdown fuyaient telles quelles dans l'evidence affichée."""
    resolved = fr.resolve_incident_facts([fact("FRENCHBREACHES", rich_facts={
        "timeline": [{
            "date": "2026-08-22", "status": "claimed",
            "event": "Une publication diffusée le **22 août 2026** sur un forum revendique une compromission.",
            "evidence": "Une publication diffusée le **22 août 2026** sur un forum revendique une compromission.",
        }],
    })])
    assert "**" not in resolved["timeline"][0]["event"]
    assert "**" not in resolved["timeline"][0]["evidence"]


def test_date_en_toutes_lettres_est_normalisee_en_iso_dans_la_chronologie():
    resolved = fr.resolve_incident_facts([fact("CYBERATTAQUE_ORG", rich_facts={
        "timeline": [{"date": "10 août 2026", "status": "reported", "event": "Début de l'intrusion", "evidence": "le début de l'intrusion au 10 août 2026"}],
    })])
    assert resolved["timeline"][0]["date"] == "2026-08-10"


def test_deux_formulations_du_meme_jour_ne_gardent_que_la_plus_concise():
    """Cas réel constaté sur Déclic Services : une phrase brute et son libellé
    nettoyé décrivaient le même événement du même jour."""
    resolved = fr.resolve_incident_facts([fact("CYBERATTAQUE_ORG", rich_facts={
        "timeline": [
            {"date": "2026-08-10", "status": "unknown", "event": "Une chronologie fait remonter le début de l'intrusion au 10 août 2026.", "evidence": "une chronologie fait remonter le début de l'intrusion au 10 août 2026"},
            {"date": "2026-08-10", "status": "reported", "event": "Début de l'intrusion", "evidence": "le début de l'intrusion au 10 août 2026"},
        ],
    })])
    assert len(resolved["timeline"]) == 1
    assert resolved["timeline"][0]["event"] == "Début de l'intrusion"


def test_systeme_agrege_redondant_avec_ses_composants_est_ecarte():
    """Cas réel constaté sur Déclic Services : "WordPress", "ERP" et un 3ᵉ
    chip "WordPress, ERP, base de production" qui répète les deux premiers."""
    resolved = fr.resolve_incident_facts([fact("CYBERATTAQUE_ORG", rich_facts={
        "affected_systems": [
            {"value": "WordPress", "evidence": "le site WordPress exposé publiquement"},
            {"value": "ERP", "evidence": "un ERP accessible depuis Internet"},
            {"value": "WordPress, ERP, base de production", "evidence": "chaîne passant par WordPress, un ERP, la base de production"},
        ],
    })])
    values = {entry["value"] for entry in resolved["systems"]}
    assert values == {"WordPress", "ERP"}


def test_type_de_donnee_numerique_ou_trop_long_est_rejete():
    resolved = fr.resolve_incident_facts([fact("CYBERATTAQUE_ORG", data_types=["779750", "x" * 121, "IBAN"])])
    assert [entry["value"] for entry in resolved["data_types"]] == ["données bancaires"]


def test_triplet_relation_brut_est_filtre_des_claims():
    """Un format interne "sujet → relation → objet" n'est jamais publiable tel quel
    (cas réel constaté sur DINUM avant correction du collecteur)."""
    resolved = fr.resolve_incident_facts([fact("CYBERATTAQUE_ORG", rich_facts={
        "claims": [{
            "type": "statement", "status": "unknown",
            "value": "victime → compromised_via → elle-même",
            "evidence": "Il est donc techniquement possible qu'une partie des fichiers ait été obtenue depuis des ressources rendues accessibles par la plateforme elle-même.",
        }],
    })])
    assert resolved["claims"] == []


def test_claim_legacy_sans_type_et_relation_sont_repares_prudemment():
    resolved = fr.resolve_incident_facts([fact("CYBERATTAQUE_ORG", rich_facts={
        "claims": [{"value": "ZeroBytes", "status": "claimed", "evidence": "ZeroBytes revendique l'accès à Pilot."}],
        "relations": [{"subject": "Sport 2000", "relation": "claimed_by", "object": "ZeroBytes", "status": "claimed", "evidence": "ZeroBytes revendique l'accès à Pilot."}],
    })])
    assert any(row["type"] == "actor" and row["value"] == "ZeroBytes" for row in resolved["claims"])


def test_reparation_legacy_ne_transforme_pas_un_libelle_technique_en_acteur():
    """"Publication des données" est entièrement composé de termes génériques
    (voir _GENERIC_CLAIM_TERMS) : il est désormais filtré comme non
    informatif (point 7 de l'audit UX round 2), ce qui garantit à plus forte
    raison qu'il n'est jamais promu en acteur."""
    resolved = fr.resolve_incident_facts([fact("CYBERATTAQUE_ORG", rich_facts={
        "claims": [{"value": "publication des données", "status": "claimed", "evidence": "La publication des données est revendiquée."}],
    })])
    assert resolved["claims"] == []


def test_organisation_victime_ne_peut_pas_etre_affichee_comme_acteur():
    resolved = fr.resolve_incident_facts([fact("CYBERATTAQUE_ORG", rich_facts={
        "claims": [{"type": "actor", "value": "SUEZ Eau France", "status": "confirmed", "evidence": "SUEZ Eau France confirme l'incident."}],
    })], organisation="SUEZ")
    assert resolved["claims"] == []


def test_acteur_scalaire_victime_n_est_pas_publie():
    """Cas réel constaté (audit 2026-08-25, Emil Frey France) : le champ
    threat_actor scalaire (colonne directe, pas rich_facts.claims) peut
    valoir le nom de la victime elle-même ("L'entreprise indique...") sans
    passer par le filtre déjà existant pour claims[] — celui-ci ne portait
    que sur les claims, jamais sur fields.threat_actor."""
    resolved = fr.resolve_incident_facts(
        [fact("CYBERATTAQUE_ORG", threat_actor="L'entreprise", claim_status="confirmed")],
        organisation="L'entreprise",
    )
    assert "threat_actor" not in resolved["fields"]


def test_acteur_periphrase_generique_de_la_victime_n_est_pas_publie():
    """Cas réel constaté après le fix du prompt (reset 2026-08-25, Emil Frey
    France) : le LLM peut désigner la victime par une périphrase générique
    ("L'entreprise indique...") plutôt que par le nom exact de
    l'organisation. Le filtre par collision de nom ne suffit pas ici
    puisque "L'entreprise" != "Emil Frey France" ; il faut aussi un filtre
    par périphrase générique, indépendant du nom réel de l'organisation."""
    resolved = fr.resolve_incident_facts(
        [fact("CYBERATTAQUE_ORG", threat_actor="L'entreprise", claim_status="confirmed")],
        organisation="Emil Frey France",
    )
    assert "threat_actor" not in resolved["fields"]


def test_acteur_pronom_n_est_pas_publie():
    """Cas réel constaté (audit 2026-08-25, Groupe Bernard) : "qui indique"
    a produit threat_actor="qui" — un pronom relatif capté comme sujet
    grammatical, pas un acteur nommé."""
    resolved = fr.resolve_incident_facts(
        [fact("CYBERATTAQUE_ORG", threat_actor="qui", claim_status="claimed")],
    )
    assert "threat_actor" not in resolved["fields"]


def test_fragments_grammaticaux_ne_sont_pas_publies_comme_acteurs():
    for value in ("de", "et", "group", "groupe"):
        resolved = fr.resolve_incident_facts([
            fact("CYBERATTAQUE_ORG", threat_actor=value, claim_status="claimed")
        ])
        assert "threat_actor" not in resolved["fields"]


def test_claim_acteur_type_alimente_le_champ_detail_sans_ecraser_un_scalaire():
    resolved = fr.resolve_incident_facts([fact("CYBERATTAQUE_ORG", rich_facts={
        "claims": [{"type": "actor", "value": "ZeroBytes", "status": "claimed", "evidence": "ZeroBytes revendique l'accès."}],
    })])
    assert resolved["fields"]["threat_actor"]["value"] == "ZeroBytes"


def test_champ_scalaire_republie_le_statut_du_claim_gagnant():
    """Le statut est republié sur le champ résolu (via claims ou via colonne
    CSV directe) pour que le frontend puisse afficher le badge une seule
    fois, sur le champ lui-même, plutôt que de le répéter dans "Faits
    sourcés"."""
    via_claim = fr.resolve_incident_facts([fact("CYBERATTAQUE_ORG", rich_facts={
        "claims": [{"type": "actor", "value": "ZeroBytes", "status": "claimed", "evidence": "ZeroBytes revendique l'accès."}],
    })])
    assert via_claim["fields"]["threat_actor"]["status"] == "claimed"

    via_colonne = fr.resolve_incident_facts([fact("FRENCHBREACHES", threat_actor="misere", claim_status="confirmed")])
    assert via_colonne["fields"]["threat_actor"]["status"] == "confirmed"


def test_claim_vulnerability_alimente_la_liste_publique():
    """Cas réel constaté sur DINUM : une faille zero-day documentée par un
    claim `type:"vulnerability"` n'atteignait jamais `vulnerabilities[]`."""
    resolved = fr.resolve_incident_facts([fact("CYBERATTAQUE_ORG", rich_facts={
        "claims": [{
            "type": "vulnerability", "status": "reported",
            "value": "faille zero-day critique de type injection SQL",
            "evidence": "une faille zero-day critique de type injection SQL avait été activement exploitée.",
        }],
    })])
    assert resolved["vulnerabilities"][0]["value"] == "faille zero-day critique de type injection SQL"


def test_claim_initial_access_sans_vocabulaire_de_compromission_est_rejete():
    """Cas réel constaté sur Solimut : un claim étiqueté `initial_access` mais
    décrivant en réalité la mise en vente des données (pas un vecteur d'entrée)
    ne doit pas être promu tel quel."""
    resolved = fr.resolve_incident_facts([fact("FRENCHBREACHES", rich_facts={
        "claims": [{
            "type": "initial_access", "status": "claimed",
            "value": "plusieurs bases de données",
            "evidence": "revendique la mise en vente de plusieurs bases de données attribuées à Solimut Mutuelle de France.",
        }],
    })])
    assert "initial_access" not in resolved["fields"]


def test_claim_initial_access_avec_vocabulaire_de_compromission_est_promu():
    resolved = fr.resolve_incident_facts([fact("CYBERATTAQUE_ORG", rich_facts={
        "claims": [{
            "type": "initial_access", "status": "reported",
            "value": "compromission d'un compte administrateur via hameçonnage",
            "evidence": "Elle évoque la compromission des identifiants d'un compte administrateur à la suite d'une campagne d'hameçonnage.",
        }],
    })])
    assert resolved["fields"]["initial_access"]["value"] == "compromission d'un compte administrateur via hameçonnage"


def test_claim_reduit_a_un_mot_generique_est_filtre():
    """Cas réel constaté sur Déclic Services : "Autres éléments documentés"
    affichait `Action documentée: "compromission"` — une valeur qui ne dit
    rien de propre à cet incident précis. Un claim similaire mais avec un
    contenu spécifique reste conservé."""
    resolved = fr.resolve_incident_facts([fact("CYBERATTAQUE_ORG", rich_facts={
        "claims": [
            {"type": "attack_action", "status": "claimed", "value": "compromission", "evidence": "ZeroBytes revendique la compromission du site."},
            {"type": "attack_action", "status": "claimed", "value": "compromission du serveur WordPress via un plugin vulnérable", "evidence": "ZeroBytes détaille la compromission du serveur WordPress via un plugin vulnérable."},
        ],
    })])
    values = [claim["value"] for claim in resolved["claims"]]
    assert "compromission" not in values
    assert "compromission du serveur WordPress via un plugin vulnérable" in values


def test_prestataire_nomme_dans_la_preuve_alimente_un_tiers_sans_identite_inventee():
    resolved = fr.resolve_incident_facts([fact("CYBERATTAQUE_ORG", rich_facts={
        "claims": [{"status": "confirmed", "evidence": "L'incident a touché un prestataire technique de la victime."}],
    })])
    assert resolved["fields"]["third_party"]["value"] == "prestataire technique"


def test_tiers_hypothetique_ne_devient_pas_un_tiers_implique():
    resolved = fr.resolve_incident_facts([fact("CYBERATTAQUE_ORG", rich_facts={
        "claims": [{
            "type": "third_party",
            "value": "fournisseur",
            "status": "hypothesis",
            "evidence": "Ces données pourraient alimenter une fraude au faux fournisseur.",
        }],
    })])

    assert "third_party" not in resolved["fields"]


def test_vulnerabilite_de_contexte_ne_devient_pas_vecteur_initial():
    resolved = fr.resolve_incident_facts([fact(
        "CYBERATTAQUE_ORG",
        initial_access="vulnerability_exploitation",
        initial_access_evidence=(
            "Le contexte actuel est particulier : une vulnérabilité critique "
            "de Metabase a récemment été corrigée."
        ),
    )])

    assert "initial_access" not in resolved["fields"]


def test_statut_confirme_global_ne_confirme_pas_les_types_seulement_revendiques():
    evidence = (
        "TeleCoop confirme certains accès à des données personnelles, tandis "
        "que le hacker revendique des données bancaires et des pièces d'identité."
    )
    resolved = fr.resolve_incident_facts([fact(
        "CYBERATTAQUE_ORG",
        claim_status="confirmed",
        data_types=["données personnelles", "données bancaires"],
        rich_facts={"data_types": [
            {"value": "données personnelles", "status": "confirmed", "evidence": evidence},
            {"value": "données bancaires", "status": "confirmed", "evidence": evidence},
        ]},
    )])

    statuses = {entry["value"]: entry["status"] for entry in resolved["data_types"]}
    assert statuses == {"données personnelles": "confirmed", "données bancaires": "claimed"}


def test_statut_scalaire_suit_la_revendication_dans_sa_preuve():
    resolved = fr.resolve_incident_facts([fact(
        "CYBERATTAQUE_ORG",
        threat_actor="ZeroBytes",
        threat_actor_evidence="ZeroBytes revendique le vol de la base.",
        claim_status="confirmed",
    )])

    assert resolved["fields"]["threat_actor"]["status"] == "claimed"


def test_volume_legacy_herite_du_statut_de_sa_preuve_riche():
    resolved = fr.resolve_incident_facts([fact(
        "CYBERATTAQUE_ORG",
        data_volume="335 Mo",
        claim_status="confirmed",
        rich_facts={"data_volumes": [{
            "value": 335,
            "unit": "MO",
            "status": "claimed",
            "evidence": "Le hacker revendique 335 Mo de données.",
        }]},
    )])

    assert resolved["fields"]["data_volume"]["status"] == "claimed"


def test_decompte_specifique_remplace_la_reparation_generique_du_meme_extrait():
    evidence = (
        "Le hacker revendique 14 947 adresses e-mail uniques et "
        "6 451 IBAN uniques."
    )
    resolved = fr.resolve_incident_facts([fact("CYBERATTAQUE_ORG", rich_facts={
        "affected_counts": [{
            "value": 14_947,
            "unit": "accounts",
            "status": "claimed",
            "evidence": evidence,
        }],
        "claims": [{
            "type": "data_type",
            "value": "adresses e-mail",
            "status": "claimed",
            "evidence": evidence,
        }],
    })])

    assert [(row["value"], row["unit"]) for row in resolved["affected"]] == [
        (14_947, "adresses e-mail"),
        (6_451, "données bancaires"),
    ]


def test_impact_narratif_sans_colonne_legacy_vient_du_claim():
    """Cas réel constaté sur DINUM/SUEZ : un claim de type "impact" existe
    (texte narratif sourcé) mais aucune colonne Impact legacy n'est
    renseignée. Sans ce filet, fields.impact restait absent alors qu'un
    badge de statut aurait pu s'afficher sur le champ (voir points 3+8 de
    l'audit UX) — la même logique que threat_actor/third_party s'applique."""
    resolved = fr.resolve_incident_facts([fact("CYBERATTAQUE_ORG", rich_facts={
        "claims": [{"type": "impact", "value": "Services rendus indisponibles plusieurs jours.", "status": "confirmed", "evidence": "Les services ont été rendus indisponibles plusieurs jours."}],
    })])
    assert resolved["fields"]["impact"]["value"] == "Services rendus indisponibles plusieurs jours."
    assert resolved["fields"]["impact"]["status"] == "confirmed"


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


def test_claim_numerique_type_sans_projection_est_recupere_une_seule_fois():
    """Un affected_count typé mais absent de la collection dédiée ne doit
    plus être perdu. Il est réparé une seule fois et sans `raw` numérique qui
    court-circuiterait le formatage du frontend."""
    resolved = fr.resolve_incident_facts([fact("FRENCHBREACHES", rich_facts={
        "claims": [{
            "type": "affected_count", "status": "reported", "value": "1000000",
            "evidence": "plus d'un million d'assurés apparaîtraient dans les données.",
        }],
    })])
    assert len(resolved["affected"]) == 1
    assert resolved["affected"][0]["value"] == 1_000_000
    assert resolved["affected"][0]["unit"] == "people"
    assert resolved["affected"][0].get("raw", "") == ""


def test_claim_sans_type_reste_repare_en_volume():
    """Le filet de réparation garde son utilité réelle : un claim qui a
    effectivement perdu son `type` (export historique) doit toujours être
    promu en volume, avec une unité devinée depuis l'evidence."""
    resolved = fr.resolve_incident_facts([fact("FRENCHBREACHES", rich_facts={
        "claims": [{
            "status": "reported", "value": "50000",
            "evidence": "50 000 clients seraient concernés par cette fuite.",
        }],
    })])
    assert len(resolved["affected"]) == 1
    assert resolved["affected"][0]["unit"] == "people"
    assert resolved["affected"][0]["value"] == 50000


def test_meme_volume_affiche_deux_fois_avec_semantique_differente_ne_fait_pas_doublon():
    """Cas réel constaté sur Sport 2000 : "9 000 clients" apparaissait deux
    fois dans "Volume documenté" car deux enregistrements portaient la même
    valeur/unité affichée mais une sémantique interne différente ("total" vs
    "unspecified", invisible à l'écran)."""
    resolved = fr.resolve_incident_facts([
        fact("CYBERATTAQUE_ORG", rich_facts={"affected_counts": [
            {"value": 9_000, "unit": "people", "raw": "9 000 clients", "scope": "total", "status": "claimed"},
        ]}),
        fact("FRENCHBREACHES", rich_facts={"affected_counts": [
            {"value": 9_000, "unit": "people", "raw": "9 000 clients", "status": "reported"},
        ]}),
    ])
    assert len(resolved["affected"]) == 1
    assert resolved["affected"][0]["semantic"] == "total"
    assert set(resolved["affected"][0]["sources"]) == {"CYBERATTAQUE_ORG", "FRENCHBREACHES"}


def test_protection_civile_fusionne_volume_et_types_de_donnees():
    resolved = fr.resolve_incident_facts([
        fact("CYBERATTAQUE_ORG", affected_count=525_000, affected_unit="people", claim_status="reported", data_types=["Noms", "Prénoms", "Téléphones"]),
        fact("FRENCHBREACHES", data_types=["noms", "Dates de naissance"]),
    ])
    assert resolved["affected"][0]["value"] == 525_000
    assert [entry["value"] for entry in resolved["data_types"]] == ["Noms", "noms et prénoms", "numéros de téléphone", "dates de naissance"]


def test_data_types_rich_et_legacy_sont_fusionnes_sans_doublon():
    resolved = fr.resolve_incident_facts([
        fact("CYBERATTAQUE_ORG", rich_facts={"data_types": [
            {"value": "Adresses e-mail", "status": "confirmed"},
            {"value": "Numéros de téléphone", "status": "reported"},
        ]}),
        fact("FRENCHBREACHES", data_types=["adresses e-mail", "Dates de naissance"]),
    ])
    values = [entry["value"] for entry in resolved["data_types"]]
    assert values == ["adresses e-mail", "numéros de téléphone", "dates de naissance"]


def test_data_type_rich_negated_is_not_published_as_exposed():
    resolved = fr.resolve_incident_facts([
        fact("CYBERATTAQUE_ORG", rich_facts={"data_types": [
            {"value": "IBAN / RIB", "status": "negated"},
            {"value": "Adresses e-mail", "status": "reported"},
        ]}),
    ])
    assert [entry["value"] for entry in resolved["data_types"]] == ["adresses e-mail"]


def test_meme_type_de_donnee_formule_differemment_selon_la_source_ne_fait_pas_doublon():
    """Cas réel constaté sur SUEZ : CYBERATTAQUE_ORG écrit "adresses e-mail",
    BONJOURLAFUITE écrit "Adresse email" — même type, deux formulations."""
    resolved = fr.resolve_incident_facts([
        fact("CYBERATTAQUE_ORG", data_types=["adresses e-mail"]),
        fact("BONJOURLAFUITE", data_types=["Adresse email"]),
    ])
    assert len(resolved["data_types"]) == 1
    assert resolved["data_types"][0]["value"] == "adresses e-mail"
    assert resolved["data_types"][0]["sources"] == ["CYBERATTAQUE_ORG", "BONJOURLAFUITE"]


def test_actor_scalar_drops_narrative_prefix():
    resolved = fr.resolve_incident_facts([
        fact("CYBERATTAQUE_ORG", threat_actor="Le cybercriminel misere"),
    ])
    assert resolved["fields"]["threat_actor"]["value"] == "misere"


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


def test_decompte_de_valeurs_uniques_cite_dans_l_evidence_est_recupere():
    """Cas réel constaté sur Déclic Services : la phrase source citait
    "14 947 adresses e-mail uniques, 6 451 IBAN uniques" dans l'evidence d'un
    claim "mots de passe", mais ni l'un ni l'autre n'était extrait comme
    volume séparé."""
    evidence = (
        "Le hacker précise lui-même qu'il s'agit de données brutes non dédupliquées et "
        "revendique notamment 14 947 adresses e-mail uniques, 6 451 IBAN uniques et "
        "plusieurs centaines de hachages de mots de passe distincts."
    )
    resolved = fr.resolve_incident_facts([fact("CYBERATTAQUE_ORG", rich_facts={
        "claims": [{"type": "data_type", "value": "mots de passe", "status": "claimed", "evidence": evidence}],
    })])
    by_unit = {entry["unit"]: entry["value"] for entry in resolved["affected"]}
    assert by_unit["adresses e-mail"] == 14947
    assert by_unit["données bancaires"] == 6451


def test_decompte_de_valeur_unique_sans_type_de_donnee_reconnu_est_ignore():
    resolved = fr.resolve_incident_facts([fact("CYBERATTAQUE_ORG", rich_facts={
        "claims": [{"type": "statement", "value": "x", "status": "unknown", "evidence": "L'article cite 42 visiteurs uniques ce mois-ci."}],
    })])
    assert resolved["affected"] == []


def test_resultat_est_deterministe_independamment_de_l_ordre_entree():
    facts = [
        fact("FRENCHBREACHES", threat_actor="B", data_types=["Nom"], affected_count=100, affected_unit="people"),
        fact("CYBERATTAQUE_ORG", threat_actor="A", data_types=["Email"], rich_facts={"affected_counts": [
            {"value": 200, "unit": "records", "scope": "total", "status": "reported"},
        ]}),
    ]
    assert fr.resolve_incident_facts(facts) == fr.resolve_incident_facts(list(reversed(facts)))


def test_societe_operatrice_de_la_victime_n_est_pas_un_attaquant():
    resolved = fr.resolve_incident_facts([fact(
        "CYBERATTAQUE_ORG",
        threat_actor="Commerce",
        rich_facts={"claims": [{
            "type": "actor",
            "value": "L Commerce",
            "status": "reported",
            "evidence": (
                "L Commerce, la société derrière Allo E.Leclerc, informe ses "
                "clients qu'un prestataire a été victime d'un incident."
            ),
        }]},
    )], organisation="Allo E.Leclerc")

    assert "threat_actor" not in resolved["fields"]


def test_negation_rich_ne_laisse_pas_survivre_le_meme_type_legacy():
    resolved = fr.resolve_incident_facts([fact(
        "CYBERATTAQUE_ORG",
        data_types=["numéros de téléphone", "identifiants", "mots de passe"],
        rich_facts={"data_types": [
            {
                "value": "informations bancaires, identifiants de connexion et mots de passe",
                "status": "negated",
                "evidence": (
                    "Les informations bancaires, identifiants de connexion et "
                    "mots de passe ne sont pas concernés par cette fuite."
                ),
            },
            {
                "value": "numéros de téléphone",
                "status": "reported",
                "evidence": "Les attaquants ont pu accéder aux numéros de téléphone.",
            },
        ]},
    )])

    assert [entry["value"] for entry in resolved["data_types"]] == ["numéros de téléphone"]


def test_population_generale_n_est_pas_un_volume_affecte():
    resolved = fr.resolve_incident_facts([fact(
        "CYBERATTAQUE_ORG",
        affected_count=4_600,
        affected_unit="users",
        rich_facts={
            "affected_counts": [{
                "value": 4_600,
                "unit": "users",
                "status": "unknown",
                "evidence": (
                    "Plus de 5 millions d'euskos sont en circulation, avec "
                    "environ 4 600 utilisateurs particuliers dans son réseau."
                ),
            }],
            "claims": [{
                "type": "affected_count",
                "value": "6000",
                "status": "reported",
                "evidence": "Environ 6 000 particuliers ont été informés de l'incident.",
            }],
        },
    )])

    assert [(entry["value"], entry["unit"]) for entry in resolved["affected"]] == [(6000, "people")]


def test_vulnerabilite_hypothetique_ou_remediation_n_est_pas_dite_exploitee():
    resolved = fr.resolve_incident_facts([fact("CYBERATTAQUE_ORG", rich_facts={
        "claims": [
            {
                "type": "vulnerability",
                "value": "une faiblesse dans une API",
                "status": "hypothesis",
                "evidence": "Une faiblesse potentielle permettrait de modifier un crédit.",
            },
            {
                "type": "vulnerability",
                "value": "corrected",
                "status": "confirmed",
                "evidence": "Le groupe indique avoir corrigé la vulnérabilité.",
            },
        ],
    })])

    assert resolved["vulnerabilities"] == []


def test_systeme_explicitement_non_concerne_et_impact_data_only_sont_ecartes():
    resolved = fr.resolve_incident_facts([fact(
        "CYBERATTAQUE_ORG",
        impact="Des données personnelles ont été compromises.",
        rich_facts={"claims": [{
            "type": "system",
            "value": "systèmes d’Allo E.Leclerc",
            "status": "reported",
            "evidence": "L'incident ne concerne donc pas directement les systèmes d’Allo E.Leclerc.",
        }]},
    )])

    assert resolved["systems"] == []
    assert "impact" not in resolved["fields"]


def test_formulations_nominales_d_exposition_ne_sont_pas_un_impact():
    for impact in (
        "accès non autorisé à plusieurs données personnelles",
        "consultation ou la copie de données personnelles",
    ):
        resolved = fr.resolve_incident_facts([fact("CYBERATTAQUE_ORG", impact=impact)])
        assert "impact" not in resolved["fields"]


def test_perimetre_de_donnees_compose_reste_distinct_des_types_atomiques():
    resolved = fr.resolve_incident_facts([fact("CYBERATTAQUE_ORG", rich_facts={
        "affected_datasets": [
            {"value": "adresse e-mail", "status": "reported"},
            {
                "value": "données de livraison et de facturation de Journaux.fr",
                "status": "claimed",
            },
        ],
    })])

    assert [entry["value"] for entry in resolved["datasets"]] == [
        "données de livraison et de facturation de Journaux.fr",
    ]


def test_meme_volume_meme_preuve_conserve_le_qualificatif_sans_doublon():
    evidence = "Alduin affirme avoir récupéré environ 270 000 enregistrements."
    resolved = fr.resolve_incident_facts([fact("CYBERATTAQUE_ORG", rich_facts={
        "affected_counts": [
            {
                "value": 270_000,
                "unit": "records",
                "scope": "livraison",
                "status": "claimed",
                "evidence": "Le hacker " + evidence,
            },
            {
                "value": 270_000,
                "unit": "records",
                "scope": "données de livraison",
                "status": "unknown",
                "raw": "environ 270 000 enregistrements",
                "evidence": evidence,
            },
        ],
    })])

    assert len(resolved["affected"]) == 1
    assert resolved["affected"][0]["raw"] == "environ 270 000 enregistrements"
    assert resolved["affected"][0]["status"] == "claimed"
