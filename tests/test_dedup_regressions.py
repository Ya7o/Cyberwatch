"""Régressions de normalisation prouvées par l'audit multi-source."""

from cyberwatch.collectors.ransomware_live import _victim_name
from cyberwatch.normalize import organisation_key


def test_duvignau_40_has_one_deterministic_key():
    assert organisation_key("Duvignau40") == organisation_key("Duvignau 40")


def test_incident_suffix_is_not_part_of_the_victim_identity():
    assert organisation_key("AFPA piraté") == organisation_key("AFPA")


def test_ransomware_domain_is_canonicalized_before_identity():
    assert organisation_key(_victim_name("reflet2000.fr")) == organisation_key("Reflet 2000")
