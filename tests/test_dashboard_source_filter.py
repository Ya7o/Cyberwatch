"""Contrat du filtre dashboard par source."""


def test_filtre_source_est_present_et_applique_aux_deux_rendus():
    html = open("index.html", encoding="utf-8").read()
    legacy = open("assets/app-legacy.js", encoding="utf-8").read()
    audit = open("assets/dashboard-audit.js", encoding="utf-8").read()

    assert 'id="f-source"' in html
    assert '<option value="">Toutes les sources</option>' in html
    for source_id in (
        "BONJOURLAFUITE", "FRENCHBREACHES", "CYBERATTAQUE_ORG",
        "RANSOMWARE_LIVE", "VEILLE_LLM",
    ):
        assert f'value="{source_id}"' in html

    expected = 'selectedSource && !(incident.sources || []).includes(selectedSource)'
    assert expected in legacy
    assert expected in audit
    assert '$("#f-source")?.addEventListener("change"' in legacy
    assert 'cyberwatch:filters-changed' in legacy
