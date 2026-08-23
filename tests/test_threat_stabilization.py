"""Régressions bloquantes de stabilisation de la qualification Threat."""

from cyberwatch import config
from cyberwatch.dedup import build_incidents
from cyberwatch.normalize import classify_threat
from cyberwatch.qualification import stabilize_threats


def test_specific_leak_beats_generic_cyberattack():
    assert classify_threat(
        "90 000 données volées après une cyberattaque"
    ) == config.THREAT_LEAK


def test_account_compromise_is_an_intrusion_not_a_threat_kind():
    assert classify_threat(
        "Cyberattaque avec messagerie compromise du service"
    ) == config.THREAT_INTRUSION


def test_ransomware_still_beats_exfiltration():
    assert classify_threat(
        "Attaque ransomware avec exfiltration de données"
    ) == config.THREAT_RANSOMWARE


def test_intrusion_without_specific_signal_stays_intrusion():
    assert classify_threat(
        "Accès non autorisé au système d information"
    ) == config.THREAT_INTRUSION


def test_negated_leak_does_not_override_intrusion():
    assert classify_threat(
        "Intrusion dans la messagerie, aucune fuite de données identifiée"
    ) == config.THREAT_INTRUSION


def test_negated_cyberattack_is_not_intrusion():
    assert classify_threat(
        "L'origine cyber est évoquée mais cyberattaque non démontrée"
    ) == config.THREAT_UNKNOWN


def test_source_scope_leak_beats_generic_piratage():
    assert classify_threat(
        "Piratage de l'entreprise", default=config.THREAT_LEAK
    ) == config.THREAT_LEAK


def test_source_scope_allows_explicit_ransomware_override():
    assert classify_threat(
        "Attaque ransomware LockBit", default=config.THREAT_LEAK
    ) == config.THREAT_RANSOMWARE


def test_veille_native_unknown_is_preserved(make_item):
    item = make_item(source="VEILLE_LLM", threat=config.THREAT_INTRUSION)
    item.Threat_Raw = config.THREAT_UNKNOWN
    assert stabilize_threats([item]) == 1
    assert item.Threat == config.THREAT_UNKNOWN


def test_veille_native_known_is_preserved(make_item):
    item = make_item(source="VEILLE_LLM", threat=config.THREAT_LEAK)
    item.Threat_Raw = config.THREAT_ACCOUNT
    stabilize_threats([item])
    assert item.Threat == config.THREAT_INTRUSION


def test_ransomware_live_contract_is_authoritative(make_item):
    item = make_item(source="RANSOMWARE_LIVE", threat=config.THREAT_LEAK)
    stabilize_threats([item])
    assert item.Threat == config.THREAT_RANSOMWARE


def test_frenchbreaches_generic_intrusion_falls_back_to_leak(make_item):
    item = make_item(source="FRENCHBREACHES", threat=config.THREAT_INTRUSION)
    stabilize_threats([item])
    assert item.Threat == config.THREAT_LEAK


def test_frenchbreaches_explicit_ransomware_is_kept(make_item):
    item = make_item(source="FRENCHBREACHES", threat=config.THREAT_RANSOMWARE)
    stabilize_threats([item])
    assert item.Threat == config.THREAT_RANSOMWARE


def test_incident_leak_beats_generic_intrusion(make_item):
    items = [
        make_item(source="FRENCHBREACHES", threat=config.THREAT_LEAK, url="https://a/1"),
        make_item(
            source="CYBERATTAQUE_ORG",
            threat=config.THREAT_INTRUSION,
            published="2026-03-02",
            url="https://a/2",
        ),
    ]
    assert build_incidents(items)[0].Menace == config.THREAT_LEAK


def test_incident_account_compromise_legacy_value_is_not_published(make_item):
    items = [
        make_item(source="VEILLE_LLM", threat=config.THREAT_ACCOUNT, url="https://a/1"),
        make_item(
            source="CYBERATTAQUE_ORG",
            threat=config.THREAT_INTRUSION,
            published="2026-03-02",
            url="https://a/2",
        ),
    ]
    assert build_incidents(items)[0].Menace == config.THREAT_INTRUSION


def test_incident_ransomware_beats_leak_even_when_leak_is_veille(make_item):
    items = [
        make_item(source="VEILLE_LLM", threat=config.THREAT_LEAK, url="https://a/1"),
        make_item(
            source="RANSOMWARE_LIVE",
            threat=config.THREAT_RANSOMWARE,
            published="2026-03-02",
            url="https://a/2",
        ),
    ]
    assert build_incidents(items)[0].Menace == config.THREAT_RANSOMWARE
