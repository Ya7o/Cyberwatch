"""Contrat des headlines : un deux-points se juge sur la structure du titre."""
from __future__ import annotations

import pytest

from cyberwatch.headline import is_publishable_for_organisation, rejection_reason


@pytest.mark.parametrize("title", [
    "Brevo: 138 comptes compromis après une faille SSO",
    "Brevo: 138 comptes clients accessibles, 6 utilisés pour envoyer des e-mails de "
    "phishing et 43 ont vu leurs contacts exportés.",
    "Brevo : 138 comptes compromis, une vaste campagne de phishing frappe Trezor et CoinTracking",
    "Acme : une campagne de phishing vise ses clients",
    # Titres réels du corpus : proposition avant le deux-points, liste après.
    "GreenGo victime d’une cyberattaque : données de comptes, réservations et messages consultés",
    "Impact Centre Chrétien frappé par Qilin : passeports, permis et titres de séjour déjà exposés",
    "Duvignau40 : les données CRM, des e-mails et des documents diffusés",
    "Santé publique France : près de 80 000 personnes exposées après une faille",
    "Foo : attaque revendiquée par X",
])
def test_un_vrai_titre_editorial_est_accepte(title):
    assert rejection_reason(title) == ""


@pytest.mark.parametrize("title", [
    "Impact: fuite de données",
    "Données: emails, téléphones",
    "Acme: emails, téléphones",
    "Acme : noms, prénoms, adresses",
    "Acme: phishing",
    "Victime : Acme SA",
    "Menace : ransomware LockBit revendiqué",
    "Vecteur d'entrée : phishing ciblé des employés",
    "Acme : attaque. Données : e-mails",
])
def test_un_libelle_ou_une_enumeration_reste_un_prefixe(title):
    assert rejection_reason(title) == "list_or_prefix"


@pytest.mark.parametrize("title,reason", [
    ("Données concernées : Nom, prénom, Adresse email et Numéro de téléphone.", "structured_detail"),
    ("Impact documenté : indisponibilité des services.", "structured_detail"),
    ("Acme — amélioration de la vitesse d'apparition visuelle", "technical_fragment"),
    ("L'incident a entraîné une exfiltration de données.", "generic"),
    ("138 000", "metric_only"),
    ("Acme a subi une attaque. Les données ont fuité.", "multiple_sentences"),
    ("x" * 161, "too_long"),
])
def test_les_protections_existantes_sont_conservees(title, reason):
    assert rejection_reason(title) == reason


def test_un_nom_d_organisation_seul_n_est_pas_une_headline():
    assert not is_publishable_for_organisation("Brevo", "Brevo")
    assert is_publishable_for_organisation("Brevo: 138 comptes compromis après une faille SSO", "Brevo")
