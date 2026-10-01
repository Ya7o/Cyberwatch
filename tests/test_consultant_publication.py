"""Régressions des qualifications et des périmètres audités côté consultant."""
from cyberwatch import config, data_sensitivity, site, site_analysis, site_evidence, threat_resolution
from cyberwatch.model import Incident


def _fact(item, summary, impact=""):
    return {"Item_ID": item.Item_ID, "Source_ID": item.Source_ID,
            "Summary": summary, "Impact": impact, "Source_Metadata_JSON": "{}"}


def test_tampon_confirmed_attack_does_not_promote_hypothetical_leak(make_item):
    item = make_item(org="Ville du Tampon", source="VEILLE_LLM", threat=config.THREAT_OTHER,
                     title="Ville du Tampon : Autre cyber")
    fact = _fact(item, "La mairie confirme une cyberattaque. La nature de l'attaque reste inconnue.",
                 "Une éventuelle fuite de données est évoquée comme hypothèse, sans confirmation publique.")
    decision = threat_resolution.resolve_component([item], {item.Item_ID: [fact]})
    assert decision.value == config.THREAT_UNKNOWN
    assert decision.reason == "THREAT_RESERVED_BY_SOURCE"


def test_joly_intrusion_with_no_established_exfiltration_is_not_a_leak(make_item):
    item = make_item(org="Lycée Jean Joly", source="VEILLE_LLM", threat=config.THREAT_INTRUSION,
                     title="Lycée Jean Joly : Intrusion")
    fact = _fact(item, "Un élève a été surpris lors d'une tentative de connexion au serveur.",
                 "Des dossiers personnels d'élèves sont stockés sur ce serveur. Aucune exfiltration de données n'est établie publiquement.")
    decision = threat_resolution.resolve_component([item], {item.Item_ID: [fact]})
    assert decision.value == config.THREAT_INTRUSION
    assert not data_sensitivity.classify({"display_summary": fact["Summary"], "fields": {
        "impact": {"value": fact["Impact"]},
    }})["high_sensitivity_data_exposed"]


def test_claimed_leak_remains_a_claim_without_victim_confirmation(make_item):
    item = make_item(org="EPF / VALGO", source="VEILLE_LLM", threat=config.THREAT_LEAK,
                     title="EPF / VALGO : Fuite de données")
    fact = _fact(item, "Fuite de données revendiquée via un tiers, sans confirmation publique retrouvée.")
    assert threat_resolution.resolve_component([item], {item.Item_ID: [fact]}).value == config.THREAT_LEAK


def test_negative_data_types_and_student_perpetrator_do_not_imply_exposure():
    detail = {"data_types": [{"value": "dossiers médicaux d'élèves", "status": "negated"}],
              "display_summary": "Un élève est soupçonné d'avoir redémarré les serveurs."}
    exposure = data_sensitivity.classify(detail)
    assert not any(exposure[field] for field in (
        "personal_data_exposed", "high_sensitivity_data_exposed", "credentials_or_secrets_exposed",
    ))


def test_denied_exposure_in_summary_does_not_flag_vulnerable_people():
    denied = {"display_summary": "Les données personnelles d’élèves n’ont pas été diffusées."}
    positive = {"display_summary": "Les données personnelles d’élèves ont été diffusées."}
    assert not data_sensitivity.classify(denied)["vulnerable_people_data_exposed"]
    assert data_sensitivity.classify(positive)["vulnerable_people_data_exposed"]


def test_evidence_separates_website_preserves_articles_and_rejects_unsafe_urls():
    row = {"source_links": [
        {"source": "RANSOMWARE_LIVE", "url": "https://victim.example/"},
        {"source": "VEILLE_LLM", "url": "https://imazpress.com/article"},
    ]}
    site_evidence.decorate(row, [{"source": "VEILLE_LLM", "victim_website": "https://victim.example",
        "evidence_urls": ["https://imazpress.com/article", "https://linfo.re/article",
                          "javascript:alert(1)", "https://user:password@example.com/article"]}])
    assert row["organisation_links"] == ["https://victim.example"]
    assert [link["label"] for link in row["source_links"]] == ["Imaz Press", "Linfo.re"]
    assert len(row["source_links"]) == 2


def test_query_identifies_distinct_publications_on_same_path():
    row = {"source_links": []}
    site_evidence.decorate(row, [{"source": "VEILLE_LLM", "evidence_urls": [
        "https://press.example/article?id=1", "https://press.example/article?id=2",
    ]}])
    assert len(row["source_links"]) == 2


def test_ransomware_source_never_uses_victim_or_other_publishers_url():
    incident = Incident(Sources="RANSOMWARE_LIVE | FRENCHBREACHES", Source_URLs=(
        "https://victim.example | https://frenchbreaches.com/alertes/incident"
    ))
    assert site._source_links(incident) == [{
        "source": "FRENCHBREACHES", "url": "https://frenchbreaches.com/alertes/incident",
    }]
    incident.Sources = "FRENCHBREACHES"
    incident.Source_URLs = "https://impostor.example/article?url=frenchbreaches.com"
    assert site._source_links(incident) == []


def test_analysis_windows_include_boundary_exclude_future_and_keep_all_undated():
    rows = [
        {"id": "edge", "date": "2026-09-01", "org": "A", "location": "La Réunion", "threat": "Intrusion"},
        {"id": "new", "date": "2026-09-30", "org": "B", "location": "La Réunion", "threat": "Intrusion"},
        {"id": "old", "date": "2026-08-31", "org": "C", "location": "La Réunion", "threat": "Intrusion"},
        {"id": "future", "date": "2026-10-01", "org": "D", "location": "La Réunion", "threat": "Intrusion"},
        {"id": "undated", "date": "", "org": "E", "location": "La Réunion", "threat": "Intrusion"},
        {"id": "metro", "date": "2026-09-30", "org": "F", "location": config.LOC_FRANCE, "threat": "Intrusion"},
    ]
    profiles = site_analysis.build(rows, "2026-09-30T17:00:00+04:00")
    assert profiles["focus"]["30"]["incidents"] == 2
    assert profiles["focus"]["30"]["threat"] == [{"label": "Intrusion", "count": 2}]
    assert profiles["metro"]["30"]["incidents"] == 1
    assert profiles["focus"]["all"]["incidents"] == 5
    assert profiles["focus"]["all"]["undated"] == 1
    assert profiles == site_analysis.build(list(reversed(rows)), "2026-09-30T17:00:00+04:00")
