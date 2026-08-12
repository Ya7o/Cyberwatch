"""Normalisation : clés, taxonomie des menaces, secteurs, localisations, dates."""

import pytest

from cyberwatch import config
from cyberwatch.normalize import (
    classify_location,
    classify_sector,
    classify_threat,
    find_known_entity,
    looks_cyber,
    organisation_from_title,
    organisation_key,
    parse_date,
)


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
            ("Messagerie compromise du service", config.THREAT_ACCOUNT),
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
