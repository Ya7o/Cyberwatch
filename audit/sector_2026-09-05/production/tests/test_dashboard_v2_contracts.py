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


def test_cartes_ne_rendent_pas_la_provenance_redondante_ni_inconnu():
    js = _read("assets/dashboard-v2.js")
    assert "provenanceLabel" not in js
    assert "2 sources · corroboré" not in js
    assert "[incident.threat, incident.sector].filter(known)" in js


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


def test_volume_documente_porte_un_badge_de_statut_par_entree():
    """DINUM a un volume au statut "negated" (contesté) — il ne doit pas avoir
    le même poids visuel qu'un volume confirmé."""
    js = _read("assets/dashboard-v2.js")
    assert "function affectedHtml(records)" in js
    assert 'claim-status claim-status--${esc(status)}' in js
    assert "CLAIM_STATUS_LABELS[status]" in js


def test_le_badge_de_statut_n_apparait_qu_au_niveau_de_l_acteur():
    """Retour utilisateur round 2 : les bulles "Revendiqué" apparaissaient
    encore sur Tiers/Impact, chaque puce de Volume documenté et chaque ligne
    de chronologie — pas seulement une fois. Le badge ne doit plus vivre que
    sur "Acteur revendicateur"."""
    js = _read("assets/dashboard-v2.js")
    assert "function documentedClaimsHtml" not in js
    assert 'detailField("Acteur revendicateur", fields.threat_actor?.value, fields.threat_actor?.status)' in js
    assert 'detailField("Tiers impliqué", fields.third_party?.value)' in js
    assert 'detailField("Impact", fields.impact?.value)' in js
    # statusBadge() n'est plus appelé que dans sa propre définition et dans
    # detailField() (qui ne le déclenche que si un status lui est passé —
    # seul l'appel Acteur ci-dessus lui en passe un).
    assert js.count("statusBadge(") == 2


def test_detail_affiche_les_champs_resolus_lorsqu_ils_sont_presents():
    """Vecteur d'entrée/CVSS/dates sont réintégrés (structure en sections
    `main`) : `fact_resolution.py` les projette désormais depuis des claims
    typés avec un garde-fou de cohérence (voir `_claim_scalar`/
    `_claim_list_entries`)."""
    js = _read("assets/dashboard-v2.js")
    assert 'detailField("Vecteur d’entrée"' in js
    assert 'detailField("Vulnérabilités exploitées"' in js
    assert 'detailField("Date de l’attaque"' in js
    assert 'detailField("Date de découverte"' in js
    assert 'detailField("CVSS"' in js
    # Pas de mapping figé window.CW-only : initialAccessLabel() reste local
    # et retombe sur le texte libre si la valeur ne matche aucune énumération.
    assert "const initialAccessLabel" in js
    assert "window.CW" not in js


def test_localisation_precise_et_evolution_sont_retirees_de_la_fiche():
    """Retour utilisateur round 2 : ces deux champs sont vides sur les 5
    incidents de l'échantillon et n'apportent rien à l'usage réel — retrait
    ciblé, pas un retour en arrière sur "toujours afficher les champs
    retenus" (les autres champs vides continuent d'afficher un "—")."""
    js = _read("assets/dashboard-v2.js")
    assert 'detailField("Localisation précise"' not in js
    assert 'detailField("Évolution / suite donnée"' not in js


def test_detail_rend_la_chronologie_dedupliquee():
    """La chronologie brute avait été retirée car elle dupliquait les faits
    sourcés et mélangeait formats de date/markdown non nettoyés. Ces deux
    causes sont désormais corrigées côté fact_resolution.py
    (_drop_claims_duplicating_timeline, _drop_timeline_evidence_duplicates,
    normalisation ISO, retrait du markdown) : la chronologie est réaffichée,
    triée, avec les dates passées par formatDate()."""
    js = _read("assets/dashboard-v2.js")
    assert "function timelineHtml(rows)" in js
    assert 'detailSection("Chronologie"' in js
    assert "timelineRows" in js
    assert "formatDate(row.date)" in js


def test_chronologie_se_replie_en_un_seul_bloc():
    """Retour utilisateur round 2 : round 1 ne repliait que la liste détaillée
    ("Chronologie détaillée"), les deux champs de dates restant toujours
    visibles au niveau de la section. La section "Chronologie" entière doit
    désormais se plier/déplier d'un coup, sans repli imbriqué à l'intérieur."""
    js = _read("assets/dashboard-v2.js")
    assert "function detailSection(title, fields, { collapsible = false } = {})" in js
    assert 'return `<details class="resolved-facts-section resolved-facts-section--collapsible"><summary>${esc(title)}</summary>${content}</details>`;' in js
    assert 'detailSection("Chronologie", [' in js
    assert "{ collapsible: true }" in js
    # Plus de repli imbriqué dans le repli : la chronologie détaillée n'est
    # plus enveloppée dans son propre <details> séparé.
    assert '<summary>Chronologie détaillée</summary>' not in js


def test_detail_revient_en_haut_du_popup_a_chaque_ouverture():
    """Un <dialog> natif ne réinitialise pas toujours son scroll interne :
    rouvrir la fiche d'un autre incident après avoir scrollé loin dans le
    précédent laissait l'utilisateur au milieu de la nouvelle fiche."""
    js = _read("assets/dashboard-v2.js")
    assert '$("#detail-dialog-content").scrollTop = 0;' in js
    assert '$("#detail-dialog").scrollTop = 0;' in js


def test_toutes_les_caracteristiques_retenues_s_affichent_meme_vides():
    """Changement de philosophie assumé (retour utilisateur) : une fiche
    incident garde toujours la même forme prévisible, plutôt que de masquer
    silencieusement les champs sans valeur documentée."""
    js = _read("assets/dashboard-v2.js")
    assert 'const empty = !content || (Array.isArray(content) && !content.length);' in js
    assert '<span class="detail-empty">—</span>' in js


def test_groupe_de_donnees_sensibles_est_deplie_par_defaut():
    """Retour utilisateur round 2 : un groupe contenant du IBAN, un mot de
    passe ou une donnée de santé mérite d'être visible sans clic
    supplémentaire, contrairement à un groupe anodin (coordonnées…)."""
    js = _read("assets/dashboard-v2.js")
    assert 'const hasSensitive = items.some((value) => ["critical", "high"].includes(dataTypeSensitivity(value)));' in js
    assert '<details class="incident-data-group"${hasSensitive ? " open" : ""}>' in js


def test_couleurs_de_la_fiche_reutilisent_les_variables_reellement_definies():
    """Root cause round 2 : `--muted` n'était défini nulle part dans le CSS —
    tous les `var(--muted)` de dashboard-v2.css retombaient silencieusement
    sur la couleur héritée (donc du texte plein, pas gris), sauf
    `.incident-data-types-title` (style.css) qui utilise `--text-muted`,
    réellement défini — d'où l'impression d'un gris isolé, non harmonisé."""
    css = _read("assets/dashboard-v2.css")
    assert "var(--muted)" not in css
    assert "color:var(--text-muted)" in css
    assert "color:var(--text-secondary)" in css


def test_systemes_et_perimetres_sont_un_seul_champ_fusionne():
    """"Périmètres de données" redisait ce que "Systèmes concernés" exprimait
    déjà (retour utilisateur : champ perçu comme redondant)."""
    js = _read("assets/dashboard-v2.js")
    assert 'detailField("Systèmes & périmètres concernés", systemsAndPerimeters)' in js
    assert "detailField(\"Systèmes concernés\"" not in js
    assert "detailField(\"Périmètres de données\"" not in js


def test_libelles_de_sources_ne_dependent_pas_de_shared_js():
    """`shared.js` a été supprimé (E2) : les libellés de source restent une
    constante locale à `dashboard-v2.js`, jamais un appel à `window.CW`."""
    js = _read("assets/dashboard-v2.js")
    assert "const SOURCE_LABELS" in js
    assert "window.CW" not in js


def test_detail_mobile_donne_toute_la_largeur_aux_listes_et_textes_longs():
    js = _read("assets/dashboard-v2.js")
    css = _read("assets/dashboard-v2.css")
    assert 'resolved-field--wide' in js
    assert 'String(content || "").trim().length > 26' in js
    assert '.resolved-field--wide { grid-template-columns:1fr;' in css


def test_site_publie_les_faits_resolus_sans_priver_analytics_des_faits_bruts():
    site = _read("cyberwatch/site.py")
    assert "raw_facts = _legacy._source_facts_by_incident" in site
    assert "resolved = fact_resolution.resolve_all(raw_facts" in site
    assert 'store.write_json(store.SITE_DATA_DIR / "facts.json", resolved)' in site
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


def test_groupes_et_puces_de_donnees_partagent_l_echelle_typographique_harmonisee():
    """Root cause round 3 : `.incident-data-group > summary` (style.css, code
    hérité) porte `font-weight:600` sans aucune taille de police, donc il
    hérite du corps de page (~16px) — bien plus gros que le reste de la
    fiche redessinée (.82-.86rem). Même lacune sur `.incident-data-value`.

    Round 4 : `.incident-data-value` héritait aussi de style.css un rayon de
    coin plein (`border-radius:999px`, pastille), jamais aligné sur les
    autres puces de la fiche (`.detail-chip`, réduites à 12px dès le round 2
    pour éviter l'effet pastille déformée sur texte long) — retour
    utilisateur réel ("parfois une bulle, parfois pas")."""
    css = _read("assets/dashboard-v2.css")
    assert ".incident-data-group > summary { min-height:0; padding:.15rem 0; font-size:.86rem; color:var(--text-secondary); }" in css
    assert ".incident-data-value { padding:.14rem .45rem; font-size:.82rem; border-radius:12px; }" in css
    assert ".incident-data-types-title { grid-column:1 / -1; margin-bottom:0; font-size:.86rem; }" in css


def test_volume_documente_plafonne_les_puces_visibles():
    """Retour utilisateur round 3 : jusqu'à 10-12 puces dans "Volume
    documenté" (cas réel Solimut) rendaient le champ illisible. Seules les
    plus significatives restent visibles ; le reste se déplie."""
    js = _read("assets/dashboard-v2.js")
    assert "const VOLUME_VISIBLE_CAP = 4;" in js
    assert "const sorted = [...records].sort((a, b) => (Number(b.value) || 0) - (Number(a.value) || 0));" in js
    assert 'class="volume-more"' in js


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
    backend = _read("cyberwatch/fact_resolution.py")
    assert 'if value in represented_values:' in backend
    assert 'claim_type and claim_type != "affected count"' in backend
    assert '"raw": _text(claim.get("raw"))})' in backend
    assert '"raw": _text(claim.get("raw")) or value})' not in backend
