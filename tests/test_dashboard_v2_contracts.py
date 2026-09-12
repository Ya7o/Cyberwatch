"""Contrats UX et frontière de responsabilité du dashboard v2."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_runtime_v2_est_le_seul_runtime_charge():
    """dashboard-v2.js est autonome (ses propres esc/normalize/formatDate/...) :
    shared.js et dashboard.js (l'ancien runtime qu'il a remplacé) ont été
    supprimés plutôt que chargés sans être utilisés."""
    html = _read("index.html")
    assert 'src="assets/dashboard-v2.js' in html
    assert 'src="assets/dashboard.js' not in html
    assert 'src="assets/shared.js' not in html
    assert not (ROOT / "assets" / "dashboard.js").exists()
    assert not (ROOT / "assets" / "shared.js").exists()


def test_header_regroupe_sante_sources_et_date_collecte():
    js = _read("assets/dashboard-v2.js")
    html = _read("index.html")
    assert 'id="run-pill-text"' in html
    assert "`${ok}/${total} sources · ${freshnessLabel}`" in js
    assert "`à jour · ${stamp}`" in js
    assert "données périmées" in js
    assert "mise à jour en retard" in js
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
    assert "state.filters.locations.includes(String(incident.location || UNKNOWN))" in js


def test_recherche_permet_jusqua_1000_resultats_par_page():
    html = _read("index.html")
    js = _read("assets/dashboard-v2.js")
    assert "const PAGE_SIZE = 30;" in js
    assert 'id="s-page-size"' in html
    assert '<option value="1000">1000</option>' in html
    assert "rows.slice(start, start + state.pageSize)" in js
    assert 'sessionStorage.setItem("cw-page-size"' in js


def test_v2_restores_audit_and_interaction_contracts():
    html = _read("index.html")
    js = _read("assets/dashboard-v2.js")
    assert 'id="location-close"' in html
    assert 'id="sources-detail-body"' in html
    assert "closeLocations" in js
    assert 'event.key === "Escape"' in js
    assert 'event.target === $("#detail-dialog")' in js
    assert "sectorRows" in js and "Secteur non renseigné" in js


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


def test_footer_editorial_et_liens_descriptifs_sont_retires():
    html = _read("index.html")
    assert "Avertissement éditorial" not in html
    assert "Comprendre les niveaux de preuve" not in html
    assert "Signaler une correction" not in html
    assert "Licence MIT" not in html
    assert "<footer" not in html


def test_cartes_ne_rendent_pas_la_provenance_redondante_ni_inconnu():
    js = _read("assets/dashboard-v2.js")
    assert "provenanceLabel" not in js
    assert "2 sources · corroboré" not in js
    assert "const confirmedSector = incident.sector_status?.status === \"confirmed\"" in js
    assert "sectorTentativeChip(incident)" in js


def test_secteur_suppose_utilise_un_chip_distinct_du_secteur_confirme():
    js = _read("assets/dashboard-v2.js")
    assert "function sectorTentativeChip(incident)" in js
    assert 'data-status="PARTIAL"' in js
    assert "(supposé)" in js
    # Réutilisé identiquement en carte et en détail, jamais dupliqué à la main.
    assert js.count("sectorTentativeChip(incident)") >= 3


def test_secteur_sans_aucun_candidat_est_explicite_plutot_que_silencieux():
    """Cas réel constaté sur Déclic Services : contrairement à SUEZ/Solimut
    (un candidat tentatif existe), aucun indice de secteur n'était affiché du
    tout quand sector_status.status vaut "unknown" (NO_EVIDENCE)."""
    js = _read("assets/dashboard-v2.js")
    assert 'incident.sector_status?.status === "unknown"' in js
    assert "Secteur non déterminé" in js


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


def test_detail_revient_en_haut_du_popup_a_chaque_ouverture():
    """Un <dialog> natif ne réinitialise pas toujours son scroll interne :
    rouvrir la fiche d'un autre incident après avoir scrollé loin dans le
    précédent laissait l'utilisateur au milieu de la nouvelle fiche."""
    js = _read("assets/dashboard-v2.js")
    assert '$("#detail-dialog-content").scrollTop = 0;' in js
    assert '$("#detail-dialog").scrollTop = 0;' in js


def test_couleurs_de_la_fiche_reutilisent_les_variables_reellement_definies():
    """Root cause round 2 : `--muted` n'était défini nulle part dans le CSS —
    tous les `var(--muted)` de dashboard-v2.css retombaient silencieusement
    sur la couleur héritée (donc du texte plein, pas gris), sauf
    `.incident-data-types-title` (style.css) qui utilise `--text-muted`,
    réellement défini — d'où l'impression d'un gris isolé, non harmonisé."""
    css = _read("assets/dashboard-v2.css")
    assert "var(--muted)" not in css
    assert "color:var(--text-muted)" in css


def test_libelles_de_sources_ne_dependent_pas_de_shared_js():
    """`shared.js` a été supprimé (E2) : les libellés de source restent une
    constante locale à `dashboard-v2.js`, jamais un appel à `window.CW`."""
    js = _read("assets/dashboard-v2.js")
    assert "const SOURCE_LABELS" in js
    assert "window.CW" not in js


def test_site_publie_les_faits_resolus_sans_priver_analytics_des_faits_bruts():
    site = _read("cyberwatch/site.py")
    assert "raw_facts = _legacy._source_facts_by_incident" in site
    assert "resolved = _resolved_details(payload, raw_facts)" in site
    assert "return fact_resolution.resolve_all(raw_facts" in site
    assert "analytics.build_analytics(\n        payload" in site
    assert 'row["summary"] = str(detail.get("display_summary") or "")' in site


def test_runtime_ne_supporte_plus_le_schema_legacy_des_faits():
    js = _read("assets/dashboard-v2.js")
    assert "legacyFactsNotice" not in js
    assert "Array.isArray(detail)" not in js
    assert "detail.version === 3" in js


def test_facts_json_commite_est_strictement_v3():
    import json
    facts = json.loads(_read("assets/data/facts.json"))
    assert isinstance(facts, dict)
    assert facts
    assert all(isinstance(detail, dict) and detail.get("version") == 3 for detail in facts.values())


def test_autres_elements_documentes_est_retire_de_la_fiche():
    """Retour utilisateur round 3 : même après le filtre anti-générique du
    round 2 (voir fact_resolution.py::_is_generic_claim_value), un résidu
    comme "accès, extraction et mise en ligne de données" reste un
    passe-partout sans valeur ajoutée pour un incident précis. Section
    retirée plutôt qu'un 3ᵉ raffinement de filtre."""
    js = _read("assets/dashboard-v2.js")
    assert "documentedClaimsHtml" not in js
    assert "detail.claims" not in js


def test_boucle_de_reparation_des_claims_numeriques_evite_les_doublons():
    """Un affected_count typé peut être réparé s'il manque dans la collection
    dédiée, mais jamais dupliqué ni promu avec sa valeur brute non formatée."""
    backend = _read("cyberwatch/fact_resolution.py") + _read(
        "cyberwatch/fact_resolution_counts.py"
    )
    assert 'if value in represented_values:' in backend
    assert 'claim_type and claim_type != "affected count"' in backend
    assert '"raw": _text(claim.get("raw"))})' in backend
    assert '"raw": _text(claim.get("raw")) or value})' not in backend


def test_analyse_affiche_le_pilotage_de_production():
    html = _read("index.html")
    js = _read("assets/dashboard-v2.js")

    assert 'id="production-fold"' in html
    assert 'id="production-metrics"' in html
    assert 'id="sources-fold"' in html
    assert '<details class="sources-detail"><summary>Détail par source</summary>' in html
    assert 'href="assets/dashboard-compact.css' in html
    assert "function renderProduction()" in js
    assert "scheduled_reliability" in js
    assert "missed_duplicate_candidate_pairs" in js
    assert "weak_merge_review_pairs" in js
    assert "validated_same_not_grouped_pairs" in js
    assert "pending_review_pairs" in js
    assert "llm_cost_usd" in js


def test_incidents_complets_ne_sont_charges_qu_a_l_ouverture_de_recherche():
    js = _read("assets/dashboard-v2.js")
    init = js[js.index("async function init()") : js.index("\n  init();")]

    assert 'loadJson("assets/data/incidents.json", [])' in js
    assert "async function ensureIncidents()" in js
    assert 'if (state.view === "recherche") await ensureIncidents();' in js
    assert "assets/data/incidents.json" not in init


def test_detail_presente_un_resume_seul_et_les_sources():
    js = _read("assets/dashboard-v2.js")
    modal = js[js.index("async function openIncident"):js.index("function bindGlobal")]
    assert "incidentSummaryParagraphs(incident, detail)" in modal
    assert 'paragraphs.map((paragraph) => `<p>${esc(paragraph)}</p>`)' in modal
    assert "sourceBadges(incident)" in modal
    assert "resolved-facts" not in modal
    assert "qualityAlertsHtml" not in modal
    assert "detailField" not in js
