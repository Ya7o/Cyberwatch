"""Normalisation : clés, taxonomie des menaces, secteurs, localisations, dates."""

import pytest

from cyberwatch import config
from cyberwatch.normalize import (
    classify_location,
    classify_sector,
    classify_threat,
    extract_activity_description,
    find_known_entity,
    looks_cyber,
    organisation_from_title,
    canonical_data_type,
    extract_unique_value_counts,
    is_recognized_data_type,
    organisation_key,
    parse_date,
)
from cyberwatch.enrichment import Enrichment, enrich_items, enrich_unknowns


class TestOrganisationKey:
    """§7 — ordre imposé : NFKD, accents, minuscules, ponctuation, formes juridiques."""

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("CHU de La Réunion", "chu de la reunion"),
            ("Mairie de Saint-André", "mairie de saint andre"),
            ("Société Générale", "societe generale"),
            ("L'Étang-Salé", "l etang sale"),
            ("  espaces   multiples  ", "espaces multiples"),
            ("", ""),
        ],
    )
    def test_normalisation(self, raw, expected):
        assert organisation_key(raw) == expected

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("ACME SAS", "acme"),
            ("ACME SARL", "acme"),
            ("ACME SA", "acme"),
            ("ACME EURL", "acme"),
        ],
    )
    def test_formes_juridiques_retirees(self, raw, expected):
        assert organisation_key(raw) == expected

    def test_forme_juridique_non_isolee_conservee(self):
        """« Sanofi » contient « sa » mais n'est pas une forme juridique isolée."""
        assert organisation_key("Sanofi") == "sanofi"
        assert organisation_key("Santé SA") == "sante"

    def test_pas_de_rapprochement_flou(self):
        """Deux libellés différents restent deux organisations distinctes (§11)."""
        assert organisation_key("CHU Réunion") != organisation_key("CHU de La Réunion")


class TestEnrichmentReference:
    def test_reference_completes_only_unknown_values(self):
        reference = {
            "air austral": Enrichment(
                organisation="Air Austral", sector=config.SECTOR_TRANSPORT,
                location=config.LOC_REUNION, scope="Océan Indien", reason="test", validation_url="",
            )
        }
        assert enrich_unknowns("Air Austral", config.SECTOR_UNKNOWN, config.LOC_INCONNU, reference) == (
            config.SECTOR_TRANSPORT, config.LOC_REUNION
        )

    def test_structured_source_values_are_not_replaced(self):
        reference = {
            "air austral": Enrichment(
                organisation="Air Austral", sector=config.SECTOR_TRANSPORT,
                location=config.LOC_REUNION, scope="Océan Indien", reason="test", validation_url="",
            )
        }
        assert enrich_unknowns("Air Austral", config.SECTOR_TECH, config.LOC_FRANCE, reference) == (
            config.SECTOR_TECH, config.LOC_FRANCE
        )

    def test_item_enrichment_reports_ocean_indian_changes(self, make_item):
        item = make_item(org="Air Austral", sector=config.SECTOR_UNKNOWN, location=config.LOC_INCONNU)
        reference = {"air austral": Enrichment("Air Austral", config.SECTOR_TRANSPORT, config.LOC_REUNION, "Océan Indien", "test", "")}
        assert enrich_items([item], reference) == {"sector": 1, "location": 1, "ocean_indian": 1, "france": 0}


class TestThreatTaxonomy:
    """§8 — l'ordre de priorité prime sur la position dans le texte."""

    @pytest.mark.parametrize(
        "text,expected",
        [
            ("Attaque par ransomware contre la mairie", config.THREAT_RANSOMWARE),
            ("Rançongiciel : données chiffrées", config.THREAT_RANSOMWARE),
            ("Attaque DDoS massive", config.THREAT_DDOS),
            ("Déni de service sur le portail", config.THREAT_DDOS),
            ("Un malware détecté sur le réseau", config.THREAT_MALWARE),
            ("Messagerie compromise du service", config.THREAT_INTRUSION),
            ("Intrusion dans le système d information", config.THREAT_INTRUSION),
            ("Fuite de données personnelles", config.THREAT_LEAK),
            ("Campagne de phishing", config.THREAT_PHISHING),
            ("Incident chez un prestataire", config.THREAT_THIRD_PARTY),
        ],
    )
    def test_regles(self, text, expected):
        assert classify_threat(text) == expected

    def test_priorite_ransomware_sur_fuite(self):
        """Un ransomware qui exfiltre reste un ransomware : le §8 le classe en 1er."""
        text = "Fuite de données massive après une attaque par ransomware"
        assert classify_threat(text) == config.THREAT_RANSOMWARE

    def test_groupe_ransomware_reconnu(self):
        assert classify_threat("LockBit revendique l'attaque") == config.THREAT_RANSOMWARE

    def test_texte_non_cyber_reste_inconnu(self):
        assert classify_threat("Le conseil municipal vote le budget") == config.THREAT_UNKNOWN

    def test_valeur_par_defaut_de_la_source(self):
        assert classify_threat("texte neutre", default=config.THREAT_LEAK) == config.THREAT_LEAK

    def test_toutes_les_valeurs_sont_dans_la_taxonomie(self):
        for text in ["ransomware", "ddos", "phishing", "rien du tout"]:
            assert classify_threat(text) in config.THREATS


class TestSectorTaxonomy:
    """Les marqueurs de secteur restent discriminants."""

    @pytest.mark.parametrize(
        "organisation,expected",
        [
            ("Fédération Hospitalière de France", config.SECTOR_UNKNOWN),
            ("Fédération Française des Sapeurs-Pompiers", config.SECTOR_ADMIN),
            ("Fédération Française de Tennis", config.SECTOR_SPORT),
            ("Fédération Française d’Athlétisme", config.SECTOR_SPORT),
            ("Fédération Française d’ULM", config.SECTOR_SPORT),
            ("On Air Fitness", config.SECTOR_SPORT),
            ("Air Austral", config.SECTOR_TRANSPORT),
        ],
    )
    def test_marqueurs_federation_et_air(self, organisation, expected):
        assert classify_sector(organisation) == expected


class TestLooksCyber:
    """Garde-fou d'ingestion : un contenu non cyber n'entre pas dans la base."""

    @pytest.mark.parametrize(
        "text",
        [
            "Cyberattaque contre l'hôpital",
            "Fuite de données chez l'opérateur",
            "Le CHU victime d'un ransomware",
            "Campagne de phishing en cours",
            "La mairie piratée ce week-end",
            "Incident informatique à la préfecture",
            "Attaque DDoS sur le portail",
            "Données exposées par un prestataire",
        ],
    )
    def test_contenu_cyber(self, text):
        assert looks_cyber(text)

    @pytest.mark.parametrize(
        "text",
        [
            "Inauguration du nouveau stade municipal",
            # Régression : le marqueur « si » laissait passer tout texte français.
            "Le conseil municipal vote si le budget passe",
            "Si la pluie continue, la route sera fermée",
            # Régression : « numérique » et « données » sont trop généraux pour
            # qualifier un contenu cyber — la rubrique Numérique d'un média
            # local déversait sinon tous ses articles dans la base.
            "Inauguration de la médiathèque numérique",
            "Les données du recensement sont publiées",
            "Formation aux outils informatiques pour les seniors",
            "Le nouveau site internet de la mairie est en ligne",
        ],
    )
    def test_contenu_hors_perimetre(self, text):
        assert not looks_cyber(text)

    def test_racine_de_mot_reconnue(self):
        """« cyber » doit attraper « cyberattaque », « pirat » « piratage »."""
        assert looks_cyber("cyberattaque")
        assert looks_cyber("cybersécurité")
        assert looks_cyber("piratage")
        assert looks_cyber("piratée")


class TestSector:
    """§9 — secteur donné par la source, sinon règle fixe, sinon Inconnu."""

    @pytest.mark.parametrize(
        "org,expected",
        [
            ("Mairie de Saint-Paul", config.SECTOR_ADMIN),
            ("CHU de La Réunion", config.SECTOR_HEALTH),
            ("Université de La Réunion", config.SECTOR_EDUCATION),
            ("Bank of Mauritius", config.SECTOR_FINANCE),
            ("Air Austral", config.SECTOR_TRANSPORT),
            ("CCI Réunion", config.SECTOR_RETAIL),
            ("Orange Réunion", config.SECTOR_TECH),
            ("EDF Réunion", config.SECTOR_ENERGY),
            ("Boulangerie Durand", config.SECTOR_UNKNOWN),
        ],
    )
    def test_regles(self, org, expected):
        assert classify_sector(org) == expected

    def test_secteur_fourni_prioritaire(self):
        assert classify_sector("Mairie de Saint-Paul", given=config.SECTOR_HEALTH) == (
            config.SECTOR_HEALTH
        )

    def test_toutes_les_valeurs_sont_dans_la_liste(self):
        assert classify_sector("n importe quoi") in config.SECTORS


class TestSectorRulesResserrees:
    """§Sector fiabilité : mots isolés retirés car omniprésents dans tout
    récit d'incident cyber, jamais une preuve d'activité de la victime."""

    @pytest.mark.parametrize(
        "text",
        [
            "à ce stade, aucune donnée n'a fuité",
            "les enquêteurs ignorent à ce stade l'ampleur de la fuite",
        ],
    )
    def test_stade_marqueur_de_discours_najamais_sport(self, text):
        assert classify_sector("", text) != config.SECTOR_SPORT

    @pytest.mark.parametrize(
        "text",
        [
            "le site web de l'entreprise a été piraté",
            "des données publiées sur internet",
            "une transformation digitale en cours",
            "les systèmes ont été compromis",
        ],
    )
    def test_vocabulaire_incident_najamais_tech(self, text):
        assert classify_sector("", text) != config.SECTOR_TECH

    def test_association_syndicat_najamais_services(self):
        assert classify_sector("", "un syndicat de police a réagi à l'incident") != config.SECTOR_SERVICES
        assert classify_sector("", "une association de victimes s'est constituée") != config.SECTOR_SERVICES

    def test_mutuelle_reste_reconnue_via_finance(self):
        # Le doublon mort dans SECTOR_SERVICES a été retiré, pas la règle
        # elle-même (déjà couverte par SECTOR_FINANCE, testée en premier).
        assert classify_sector("", "la mutuelle rembourse ses adhérents") == config.SECTOR_FINANCE


class TestExtractActivityDescription:
    """§Sector fiabilité : formulation métier explicite uniquement, jamais
    le récit de l'incident — partagée entre `runner.py` et `source_facts.py`."""

    def test_specialisee_dans(self):
        text = "Bureau Vallée est une enseigne spécialisée dans la vente de fournitures de bureau."
        assert "vente de fournitures de bureau" in extract_activity_description(text)

    def test_editeur_de(self):
        text = "La société est éditeur de logiciels de comptabilité."
        assert "logiciels de comptabilité" in extract_activity_description(text)

    def test_club_de_football(self):
        text = "Le club de football professionnel a confirmé la fuite."
        assert "football" in extract_activity_description(text)

    def test_etablissement_de_sante(self):
        text = "L'établissement de santé a été visé par un rançongiciel."
        assert extract_activity_description(text) != ""

    def test_texte_de_revendication_ransomware_renvoie_vide(self):
        assert extract_activity_description("Groupe : LockBit") == ""
        assert extract_activity_description("X revendiqué par LockBit") == ""

    def test_absence_de_declencheur_renvoie_vide(self):
        assert extract_activity_description("à ce stade, aucune donnée n'a fuité") == ""

    def test_plusieurs_textes_premier_match_gagne(self):
        result = extract_activity_description("", "acteur de la distribution automobile")
        assert "distribution automobile" in result


class TestLocation:
    """§10 — priorité : structurée par la source, puis règle fixe, puis indice."""

    def test_localisation_structuree_prioritaire(self):
        assert classify_location("un texte parlant de Maurice", given="La Réunion") == (
            config.LOC_REUNION
        )

    def test_regle_fixe_prime_sur_indice_textuel(self):
        """Un article national mentionnant Maurice ne devient pas mauricien."""
        assert classify_location(
            "incident évoquant Maurice", default=config.LOC_FRANCE
        ) == config.LOC_FRANCE

    def test_indice_textuel_en_dernier_recours(self):
        assert classify_location("incident à Mamoudzou") == config.LOC_MAYOTTE

    def test_inconnu_par_defaut(self):
        assert classify_location("texte sans géographie") == config.LOC_INCONNU


class TestDates:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("2026-08-12", "2026-08-12"),
            ("12/08/2026", "2026-08-12"),
            ("2026-08-12T10:30:00+04:00", "2026-08-12"),
            ("Tue, 12 Aug 2026 10:00:00 +0000", "2026-08-12"),
            ("12 août 2026", "2026-08-12"),
            ("12 August 2026", "2026-08-12"),
            ("pas une date", ""),
            ("", ""),
            (None, ""),
        ],
    )
    def test_parse(self, raw, expected):
        assert parse_date(raw) == expected


class TestOrganisationExtraction:
    def test_titre_avec_deux_points(self):
        assert organisation_from_title("Mairie de Saint-Leu : données exposées") == (
            "Mairie de Saint-Leu"
        )

    def test_prefixe_redactionnel_ignore(self):
        """« Cyberattaque : ... » ne désigne pas une organisation."""
        assert organisation_from_title("Cyberattaque : un hôpital touché") == ""

    def test_sans_deux_points(self):
        assert organisation_from_title("Un hôpital victime d'une attaque") == ""

    def test_entite_connue_trouvee(self):
        index = {"chu de la reunion": "CHU de La Réunion"}
        assert find_known_entity("Le CHU de La Réunion est touché", index) == (
            "CHU de La Réunion"
        )

    def test_entite_la_plus_longue_gagne(self):
        index = {
            "saint denis": "Saint-Denis",
            "mairie de saint denis": "Mairie de Saint-Denis",
        }
        assert find_known_entity("La Mairie de Saint-Denis piratée", index) == (
            "Mairie de Saint-Denis"
        )


class TestCleanOrganisation:
    """Nettoyage des libellés sans réécriture du nom (§7)."""

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("🟢\xa0LaSanté.net", "LaSanté.net"),
            ("www.ville-dunkerque.fr", "ville-dunkerque.fr"),
            ("AXYON  (EDF, Eiffage, Bouygues)", "AXYON"),
            ('OFII / ANEF (Portail "Étrangers en France")', "OFII / ANEF"),
            ("Trescal", "Trescal"),
            ("", ""),
        ],
    )
    def test_nettoyage(self, raw, expected):
        from cyberwatch.normalize import clean_organisation

        assert clean_organisation(raw) == expected

    def test_le_nom_n_est_jamais_reecrit(self):
        """Aucun rapprochement : hartford.fr ne devient pas « Hartford »."""
        from cyberwatch.normalize import clean_organisation

        assert clean_organisation("hartford.fr") == "hartford.fr"


class TestOrganisationFromTitle:
    """Règle « Organisation : ... », tronquée au récit de l'incident."""

    @pytest.mark.parametrize(
        "title,expected",
        [
            ("Enseignement catholique : une fuite expose 1,5 M", "Enseignement catholique"),
            ("Crous : 770 000 étudiants touchés", "Crous"),
            # Régression : le titre entier était pris pour une organisation.
            ("Son-Video.com frappé une nouvelle fois par une cyberattaque : détails",
             "Son-Video.com"),
            ("Impact Centre Chrétien frappé par Qilin : ce que l'on sait",
             "Impact Centre Chrétien"),
            ("Cyberattaque : un hôpital touché", ""),
            ("Un hôpital victime d'une attaque", ""),
        ],
    )
    def test_extraction(self, title, expected):
        assert organisation_from_title(title) == expected


class TestOrganisationFromEntryTitle:
    """Sources dont chaque entrée est nommée d'après l'organisation."""

    @pytest.mark.parametrize(
        "title,expected",
        [
            ("Trescal", "Trescal"),
            ("AgroParisTech", "AgroParisTech"),
            ("🟢\xa0Intermarché", "Intermarché"),
            ("Chambre de Commerce et de l'Industrie Nice Côte d'Azur",
             "Chambre de Commerce et de l'Industrie Nice Côte d'Azur"),
            ("AXYON  (EDF, Eiffage, Bouygues, Engie, Renault)", "AXYON"),
        ],
    )
    def test_extraction(self, title, expected):
        from cyberwatch.normalize import organisation_from_entry_title

        assert organisation_from_entry_title(title) == expected

    def test_phrase_trop_longue_rejetee(self):
        from cyberwatch.normalize import organisation_from_entry_title

        long_title = " ".join(["mot"] * 20)
        assert organisation_from_entry_title(long_title) == ""


class TestIntrusionPhysiqueOuCyber:
    """« Intrusion » vaut pour le cambriolage comme pour l'informatique."""

    @pytest.mark.parametrize(
        "text",
        [
            "Intrusion nocturne chez un commerçant de Dzoumogné",
            "Matériel disparu après un cambriolage à Kaweni",
            "Tentative d'effraction en pleine nuit",
            "Cambriolage nocturne au Douka Bé de Longoni",
        ],
    )
    def test_effraction_physique_ecartee(self, text):
        assert not looks_cyber(text)

    @pytest.mark.parametrize(
        "text",
        [
            "Intrusion dans le système d'information de la mairie",
            "Intrusion informatique chez un opérateur",
            "Une intrusion a permis l'exfiltration de données",
            # Marqueur physique présent, mais terme cyber sans équivoque.
            "Ransomware après une intrusion nocturne sur le SI",
        ],
    )
    def test_intrusion_cyber_conservee(self, text):
        assert looks_cyber(text)


class TestSecteurPrecedence:
    """Le secteur est celui de la victime, pas du récit de l'article."""

    def test_organisation_prime_sur_le_texte(self):
        """Régression : un article citant « fédération » classait Trescal en Sport."""
        assert classify_sector(
            "Trescal", "Fuite touchant plusieurs fédérations françaises"
        ) == config.SECTOR_UNKNOWN

    def test_victime_sportive_bien_classee(self):
        assert classify_sector(
            "Fédération Française de Squash", "fuite de données"
        ) == config.SECTOR_SPORT

    def test_texte_utilise_si_organisation_inconnue(self):
        assert classify_sector(
            "", "Cyberattaque contre une fédération sportive"
        ) == config.SECTOR_SPORT

    @pytest.mark.parametrize(
        "activity,expected",
        [
            ("Manufacturing", config.SECTOR_INDUSTRY),
            ("Construction", config.SECTOR_CONSTRUCTION),
            ("Business Services", config.SECTOR_SERVICES),
            ("Healthcare", config.SECTOR_HEALTH),
            ("Government", config.SECTOR_ADMIN),
        ],
    )
    def test_activite_ransomware_live_traduite(self, activity, expected):
        assert classify_sector("", given=activity) == expected


class TestCanonicalDataType:
    """Une même catégorie de donnée peut être écrite différemment selon la
    source (Cyberattaque.org, FrenchBreaches, BonjourLaFuite) : ces deux
    fonctions ramènent chaque libellé à une forme canonique partagée."""

    def test_deux_formulations_convergent(self):
        assert canonical_data_type("adresses e-mail") == canonical_data_type("Adresse email")

    def test_libelle_inconnu_reste_inchange(self):
        assert canonical_data_type("fiches individuelles") == "fiches individuelles"

    def test_is_recognized_reste_vrai_meme_deja_canonique(self):
        assert is_recognized_data_type("adresses e-mail") is True
        assert is_recognized_data_type("fiches individuelles") is False


class TestExtractUniqueValueCounts:
    """Cas réel constaté sur Déclic Services : une phrase source citait
    plusieurs comptages qualifiés qu'un décompte générique de personnes/
    comptes/enregistrements ne capte pas."""

    def test_deux_comptages_dans_la_meme_phrase(self):
        text = "revendique notamment 14 947 adresses e-mail uniques, 6 451 IBAN uniques et le reste."
        results = extract_unique_value_counts(text)
        assert (14947, "adresses e-mail", "14 947 adresses e-mail uniques") in results
        assert (6451, "données bancaires", "6 451 IBAN uniques") in results

    def test_libelle_sans_type_de_donnee_reconnu_est_ignore(self):
        assert extract_unique_value_counts("42 visiteurs uniques ce mois-ci") == []
