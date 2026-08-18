"""Contrat des filtres du dashboard unifié."""


def test_filtre_source_et_recherche_organisation_sont_appliques_par_le_runtime_unique():
    html = open("index.html", encoding="utf-8").read()
    app = open("assets/app.js", encoding="utf-8").read()

    assert 'id="f-source"' in html
    assert 'id="f-org"' in html
    assert 'id="f-reset"' in html
    assert '<option value="">Toutes les sources</option>' in html
    for source_id in (
        "BONJOURLAFUITE", "FRENCHBREACHES", "CYBERATTAQUE_ORG",
        "RANSOMWARE_LIVE", "VEILLE_LLM",
    ):
        assert f'value="{source_id}"' in html

    assert 'state.filters.source && !(i.sources || []).includes(state.filters.source)' in app
    assert 'norm(i.org).includes(q)' in app
    assert 'state.filters={ocean:false,local:false,source:"",org:""}' in app
    assert "assets/app-legacy.js" not in app
    assert "assets/dashboard-audit.js" not in app
