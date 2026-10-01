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


def test_filet_de_secours_detecte_une_liste_sans_cartes():
    """Un texte annexe ou un faux état vide ne doit jamais neutraliser le
    secours quand latest.json contient réellement des incidents."""
    html = _read("index.html")
    failsafe = _read("assets/dashboard-failsafe.js")

    assert html.index("assets/dashboard-failsafe.js") < html.index("assets/dashboard-v2.js")
    assert 'function dashboardNeedsFallback()' in failsafe
    assert 'Boolean($("#veille-list")) && !dashboardAlreadyRendered()' in failsafe
    assert "containers.every" not in failsafe


def test_l_attention_est_portee_par_la_raison_sans_module_observateur():
    html = _read("index.html")
    js = _read("assets/dashboard-v2.js")
    assert "dashboard-attention.js" not in html
    assert "À surveiller" not in js
    assert "Identifiants exposés" in js


def test_stockage_navigateur_bloque_ne_casse_pas_le_rendu():
    js = _read("assets/dashboard-v2.js")
    assert 'readStorage("localStorage", "cw-theme")' in js
    assert 'writeStorage("localStorage", "cw-theme"' in js
    assert 'localStorage.getItem(' not in js
    assert 'sessionStorage.getItem(' not in js


def test_header_regroupe_couverture_et_date_collecte():
    js = _read("assets/dashboard-v2.js")
    html = _read("index.html")
    assert 'id="run-pill-text"' in html
    assert "Couverture partielle" in js
    assert "Données périmées" in js
    assert "Mise à jour en retard" in js
    assert 'id="freshness"' not in html


def test_veille_est_un_flux_unique_avec_choix_du_territoire():
    html = _read("index.html")
    js = _read("assets/dashboard-v2.js")
    assert 'id="v-scope"' in html
    assert 'id="focus-body"' not in html
    assert "rows.slice(0, VEILLE_SIZE)" in js
    assert "median_gap_days" not in js
    assert "max_gap_days" not in js


def test_recherche_supporte_plusieurs_territoires_et_les_raccourcis():
    html = _read("index.html")
    js = _read("assets/dashboard-v2.js")
    assert 'id="quick-focus"' in html
    assert 'id="quick-ocean"' in html
    assert "locations: []" in js
    assert 'params.getAll("location")' in js
    assert 'params.append("location", value)' in js
    assert "state.filters.locations.includes(String(incident.location || UNKNOWN))" in js


def test_recherche_utilise_une_pagination_bornee_sans_reglage_superflu():
    html = _read("index.html")
    js = _read("assets/dashboard-v2.js")
    assert "const PAGE_SIZE = 30;" in js
    assert 'id="s-page-size"' not in html
    assert "rows.slice(start, start + PAGE_SIZE)" in js


def test_recherche_garde_les_territoires_accessibles_et_les_filtres_retirables():
    html = _read("index.html")
    js = _read("assets/dashboard-v2.js")
    assert 'id="location-close"' in html
    assert "Valider / Fermer" not in html
    assert "closeLocations" in js
    assert 'event.key === "Escape"' in js
    assert "data-remove-filter" in js
    assert 'id="search-advanced"' in html


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


def test_cartes_ne_rendent_pas_la_provenance_redondante():
    js = _read("assets/dashboard-v2.js")
    card = js[js.index("function incidentCardHtml"):js.index("function renderHeader")]
    assert "sourceBadges" not in card
    assert "Voir le détail" not in card
    assert card.count("data-open-id") == 1
    assert "sectorLabel(incident)" in card


def test_secteur_suppose_garde_sa_reserve_sans_score_de_methode():
    js = _read("assets/dashboard-v2.js")
    label = js[js.index("function sectorLabel"):js.index("function threatLabel")]
    assert "(supposé)" in label
    assert "(estimé)" in label
    assert "confidence" not in label
    assert js.count("sectorLabel(incident)") >= 3


def test_secteur_absent_est_explicite_dans_la_fiche():
    js = _read("assets/dashboard-v2.js")
    assert 'sectorLabel(incident) || "Secteur non déterminé"' in js
    assert 'value === UNKNOWN ? "Non déterminé"' in js


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
    assert "color:var(--text-secondary)" in css


def test_libelles_de_sources_ne_dependent_pas_de_shared_js():
    """`shared.js` a été supprimé (E2) : les libellés de source restent une
    constante locale à `dashboard-v2.js`, jamais un appel à `window.CW`."""
    js = _read("assets/dashboard-v2.js")
    assert "const SOURCE_LABELS" in js
    assert "window.CW" not in js


def test_site_publie_les_faits_resolus_et_filtre_les_candidats_des_analytics():
    site = _read("cyberwatch/site.py")
    assert "raw_facts = _legacy._source_facts_by_incident" in site
    assert "resolved = _resolved_details(payload, raw_facts)" in site
    assert "return fact_resolution.resolve_all(raw_facts" in site
    assert "analytics_payload = [" in site
    assert 'row for row in payload if row.get("admission") != "CANDIDATE"' in site
    assert "analytics.build_analytics(\n        analytics_payload" in site
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


def test_diagnostic_technique_est_separe_de_l_analyse_metier():
    html = _read("index.html")
    js = _read("assets/dashboard-v2.js")
    analysis = html[html.index('id="view-analyse"'):html.index('<dialog id="detail-dialog"')]
    assert "production-metrics" not in analysis
    assert 'id="health-dialog"' in html
    assert 'id="production-fold"' in html
    assert 'id="production-metrics"' in html
    assert 'id="sources-detail-body"' in html
    assert "sources-leds" not in html
    assert "function openHealth(" in js
    assert "function renderProduction()" in js
    assert "llm_cost_usd" in js


def test_incidents_complets_ne_sont_charges_qu_a_l_ouverture_de_recherche():
    js = _read("assets/dashboard-v2.js")
    init = js[js.index("async function init()") : js.index("\n  init();")]

    assert 'loadJson("assets/data/incidents.json", [])' in js
    assert "async function ensureIncidents()" in js
    assert 'if (state.view === "recherche") { await ensureIncidents();' in js
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
