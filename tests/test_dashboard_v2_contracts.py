"""Contrats UX et frontière de responsabilité du dashboard v2."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_runtime_v2_est_le_seul_runtime_charge():
    html = _read("index.html")
    assert 'src="assets/dashboard-v2.js' in html
    assert 'src="assets/dashboard.js' not in html


def test_header_regroupe_sante_sources_et_date_collecte():
    js = _read("assets/dashboard-v2.js")
    html = _read("index.html")
    assert 'id="run-pill-text"' in html
    assert "`${ok}/${total} sources · ${formatDateTime(run.as_of)}`" in js
    assert 'id="freshness"' not in html


def test_reunion_mayotte_est_un_statut_30_jours_compact():
    js = _read("assets/dashboard-v2.js")
    assert "Aucun incident à La Réunion / Mayotte sur les 30 derniers jours." in js
    assert "median_gap_days" not in js
    assert "max_gap_days" not in js
    assert "multi_source" not in js


def test_recherche_supporte_plusieurs_territoires_et_les_raccourcis():
    html = _read("index.html")
    js = _read("assets/dashboard-v2.js")
    assert 'id="quick-focus"' in html
    assert 'id="quick-ocean"' in html
    assert "locations: []" in js
    assert 'params.getAll("location")' in js
    assert 'params.append("location", value)' in js
    assert "state.filters.locations.includes(incident.location)" in js


def test_recherche_reste_paginee_par_30():
    js = _read("assets/dashboard-v2.js")
    assert "const PAGE_SIZE = 30;" in js
    assert "rows.slice(start, start + PAGE_SIZE)" in js


def test_actions_et_blocs_inutiles_sont_supprimes():
    html = _read("index.html")
    for removed in (
        "Copier le lien de cette vue",
        "Comment lire ces signaux",
        "Ampleur des fuites",
        "Qualité et couverture",
        "Citer cette vue",
        "Une absence dans Cyberwatch signifie",
        "Signaux calculés sur les publications observées",
    ):
        assert removed not in html


def test_cartes_ne_rendent_pas_la_provenance_redondante_ni_inconnu():
    js = _read("assets/dashboard-v2.js")
    assert "provenanceLabel" not in js
    assert "2 sources · corroboré" not in js
    assert "[incident.threat, incident.sector].filter(known)" in js


def test_signaux_exposent_une_lecture_consultant_et_masquent_les_scores():
    js = _read("assets/dashboard-v2.js")
    assert "Pourquoi ce signal ?" in js
    assert "Hausse des incidents —" in js
    assert "confidence.score" not in js
    assert "base_rate_pct" not in js
    assert "share_pct" not in js


def test_priorite_des_sources_n_existe_plus_dans_le_runtime():
    js = _read("assets/dashboard-v2.js")
    backend = _read("cyberwatch/fact_resolution.py")
    assert "SOURCE_PRIORITY" not in js
    assert "sourceRank(" not in js
    assert "sortedFacts(" not in js
    assert "firstValue(" not in js
    assert "function resolveFacts(" not in js
    expected = '(\n    "RANSOMWARE_LIVE",\n    "CYBERATTAQUE_ORG",\n    "FRENCHBREACHES",\n    "BONJOURLAFUITE",\n    "VEILLE_LLM",\n)'
    assert expected in backend


def test_detail_consomme_le_schema_resolu_et_n_affiche_que_les_champs_presents():
    js = _read("assets/dashboard-v2.js")
    assert "detail.fields || {}" in js
    assert "detail.data_types || []" in js
    assert "detail.affected || []" in js
    assert "detail.display_summary" in js
    assert "Éléments documentés" in js
    assert "Première observation" not in js
    assert "Dernière observation" not in js
    assert "incident-fact-source" not in js


def test_site_publie_les_faits_resolus_sans_priver_analytics_des_faits_bruts():
    site = _read("cyberwatch/site.py")
    assert "raw_facts = _legacy._source_facts_by_incident" in site
    assert "resolved = fact_resolution.resolve_all(raw_facts" in site
    assert 'store.write_json(store.SITE_DATA_DIR / "facts.json", resolved)' in site
    assert "analytics.build_analytics(\n        payload" in site


def test_runtime_ne_supporte_plus_le_schema_legacy_des_faits():
    js = _read("assets/dashboard-v2.js")
    assert "legacyFactsNotice" not in js
    assert "Array.isArray(detail)" not in js
    assert "detail.version === 2" in js


def test_facts_json_commite_est_strictement_v2():
    import json
    facts = json.loads(_read("assets/data/facts.json"))
    assert isinstance(facts, dict)
    assert facts
    assert all(isinstance(detail, dict) and detail.get("version") == 2 for detail in facts.values())
