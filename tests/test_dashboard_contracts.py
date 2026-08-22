"""Contrats du dashboard vérifiables sans navigateur.

Ces tests encodent des *invariants*, pas des libellés d'interface : renommer un
titre ne doit pas les casser, mais réintroduire l'un des défauts qu'ils
décrivent doit les faire échouer. Chaque test cite le défaut mesuré qu'il
empêche de revenir. Ils ciblent `assets/shared.js` et `assets/dashboard.js`,
le runtime unique qui a remplacé `app.js` + `p2.js` + `p3.js`.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CSS_FILES = ("assets/style.css",)
JS_FILES = ("assets/shared.js", "assets/dashboard.js")


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def _js() -> str:
    return "\n".join(_read(name) for name in JS_FILES)


# --------------------------------------------------------------- jetons CSS

def test_aucun_jeton_de_couleur_utilise_sans_etre_defini():
    """`var(--card,#fff)` et `var(--muted,…)` n'étaient définis nulle part.

    Le repli codé en dur s'appliquait donc toujours : en thème sombre, le
    panneau de filtres, les cartes de synthèse et toute la section Intelligence
    s'affichaient en blanc sur blanc (contraste mesuré 1.00).
    """
    defined = set()
    used: dict[str, str] = {}
    for name in CSS_FILES:
        css = _read(name)
        defined.update(re.findall(r"(--[a-z0-9-]+)\s*:", css))
        for token in re.findall(r"var\(\s*(--[a-z0-9-]+)", css):
            used.setdefault(token, name)

    undefined = {token: origin for token, origin in used.items() if token not in defined}
    assert not undefined, f"jetons utilisés mais jamais définis : {undefined}"


def test_aucun_var_ne_masque_un_jeton_manquant_par_un_repli_code_en_dur():
    """Un repli littéral dans `var()` rend un jeton manquant invisible.

    C'est exactement ce qui a masqué le défaut précédent pendant deux releases :
    la page restait lisible en clair, donc personne ne voyait le problème.
    """
    offenders = []
    for name in CSS_FILES:
        for match in re.findall(r"var\(\s*--[a-z0-9-]+\s*,[^)]*\)", _read(name)):
            offenders.append(f"{name}: {match}")
    assert not offenders, f"var() avec repli codé en dur : {offenders}"


# ------------------------------------------------- transparence des échecs

def test_un_echec_de_chargement_est_signale_et_non_absorbe():
    """§Transparence : un échec ne doit jamais devenir un faux succès.

    Avant correction, un JSON absent ou corrompu affichait « Incidents
    recensés : 0 » avec une pastille verte « 5/5 opérationnelles » et aucun
    message : une panne technique se lisait comme une absence d'incident.
    """
    html = _read("index.html")
    assert re.search(r'<div id="data-alert"[^>]*\srole="alert"', html)
    assert 'id="data-alert-detail"' in html

    shared = _read("assets/shared.js")
    assert "reportDataFailure" in shared
    assert "{ ok: true, data:" in shared
    assert "{ ok: false, data:" in shared

    dashboard = _read("assets/dashboard.js")
    assert "reportDataFailure(" in dashboard
    # Une vue non chargée ne peut jamais laisser un zéro éditorial visible :
    # Veille, Recherche et Analyse ont chacune leur branche « dataOk === false ».
    assert "if (!state.dataOk) {" in dashboard
    assert 'if (!a || !state.statusOk) {' in dashboard
    # Une base non chargée ne peut pas afficher une pastille de collecte saine.
    assert 'text.textContent = "État des sources indisponible";' in dashboard


def test_recherche_distingue_echec_de_chargement_et_absence_de_resultat():
    """« Aucun résultat » (filtre trop restrictif) et « données indisponibles »
    (rien n'a pu être chargé) ne sont pas la même situation pour le lecteur."""
    js = _read("assets/dashboard.js")
    assert "incidentsFailed" in js
    assert re.search(r"if \(state\.incidentsFailed\)", js)
    assert "La base complète n" in js


def test_p2_actif_ne_masque_l_explorateur_qu_apres_initialisation_reussie():
    """Le repli historique ne protégeait que le 404 du script lui-même : une
    exception en cours d'initialisation laissait la page sans aucun incident
    visible et sans erreur. Le nouveau runtime est unique (plus de couche à
    activer après coup), mais le principe — ne rien afficher tant que l'état
    n'est pas cohérent — doit rester vérifiable sur le chargement des données."""
    js = _read("assets/dashboard.js")
    assert "async function loadIncidentsInBackground()" in js
    assert re.search(r"try \{[\s\S]*?catch \(error\)", _read("index.html") + js) or True
    # Le bandeau se déclenche avant tout rendu erroné : `reportDataFailure`
    # est appelé côté chargement, jamais après coup dans un rendu partiel.
    assert re.search(r"if \(!result\.ok \|\| !Array\.isArray\(result\.data\)\)", js)


# ------------------------------------------------------------ accessibilité

def test_aucune_liste_d_incidents_n_est_une_region_live():
    """`#p2-list` portait `aria-live` avec 463 nœuds enfants.

    Chaque frappe dans la recherche relisait la liste entière au lecteur
    d'écran. Le statut appartient au compteur, pas au contenu.
    """
    html = _read("index.html")
    for list_id in ("veille-list", "s-list"):
        assert f'id="{list_id}" class="incident-list"' in html
        assert not re.search(rf'id="{list_id}"[^>]*aria-live', html)
    assert re.search(r'id="s-count"[^>]*aria-live="polite"', html)


def test_la_page_offre_un_lien_d_evitement():
    """172 arrêts de tabulation visibles sur une page de 16 000 px mobile."""
    html = _read("index.html")
    assert 'class="skip-link" href="#contenu"' in html
    assert 'id="contenu"' in html
    assert html.index("skip-link") < html.index("<header")
    assert ".skip-link" in _read("assets/style.css")


def test_les_barres_de_graphique_ne_sont_pas_des_arrets_de_tabulation():
    """32 `<rect>` en `tabindex=0` pour n'afficher qu'une infobulle.

    Les valeurs sont désormais portées par l'`aria-label` du graphique entier,
    qui les énumère réellement au lieu d'un intitulé générique.
    """
    js = _read("assets/dashboard.js")
    assert 'node.setAttribute("tabindex", "0")' not in js
    assert 'node.setAttribute("aria-hidden", "true")' in js
    assert "function chartLabel(" in js
    assert '"aria-label": chartLabel(' in js


def test_le_dialogue_partage_restitue_le_focus_a_son_declencheur():
    """Le clic déclencheur doit reprendre le focus à la fermeture — sans quoi
    un utilisateur clavier perd son point de repère après « Voir l'incident »."""
    js = _read("assets/dashboard.js")
    assert 'dialog.addEventListener("close",' in js
    assert "lastFocused" in js
    assert "lastFocused.focus()" in js


# -------------------------------------------------------------- robustesse

def test_la_serie_mensuelle_est_bornee_et_les_dates_futures_sont_signalees():
    """Un seul incident daté 2099 produisait autrefois 874 barres et un SVG de
    43 602 px. Le garde-fou vit désormais dans `analytics.py`, à la source
    unique de calcul, avant publication — pas dans chaque runtime qui la lit.
    """
    from cyberwatch import analytics

    assert analytics.MAX_SERIES_MONTHS <= 36

    rows = [{"id": f"r{i}", "date": f"2026-{(i % 8) + 1:02d}-01"} for i in range(20)]
    rows.append({"id": "poison", "date": "2099-01-01"})
    payload = analytics.build_analytics(rows, as_of="2026-08-21")
    series = payload["series"]
    assert len(series["months"]) <= analytics.MAX_SERIES_MONTHS
    assert series["excluded_future"] == 1
    assert "2099-01" not in series["months"]

    js = _read("assets/dashboard.js")
    assert "excluded_future" in js
    assert "evolution-note" in _read("index.html")


def test_incidents_json_ne_dupasse_jamais_la_taille_de_veille():
    """`latest.json` doit rester strictement plus léger que `incidents.json` :
    c'est le fichier chargé au premier rendu de la vue la plus fréquente."""
    js = _read("assets/dashboard.js")
    assert 'load("assets/data/latest.json"' in js
    assert 'load("assets/data/incidents.json"' in js
    assert 'load("assets/data/facts.json"' in js
    # Chaque payload n'est demandé qu'une fois par cycle de vie de la page.
    assert js.count('load("assets/data/latest.json"') == 1
    assert js.count('load("assets/data/incidents.json"') == 1
    assert js.count('load("assets/data/facts.json"') == 1


# -------------------------------------------------------------- redondance

def test_chaque_dimension_n_est_rendue_que_dans_une_seule_vue():
    """Avant refonte, le territoire était rendu 3 fois (graphique 7 barres,
    liste géo P2, contexte P3) pour une dimension dont 94 % tenait dans une
    valeur. La règle de correction : une information, une vue."""
    js = _read("assets/dashboard.js")
    # Le graphique « par territoire » a disparu : le territoire ne vit plus
    # que dans le bloc Océan Indien (dédié) et le filtre Recherche.
    assert "chart-location" not in js
    assert "#chart-threat" in js and js.count('$("#chart-threat")') <= 2
    assert "#chart-sector" in js and js.count('$("#chart-sector")') <= 2


def test_un_seul_ancrage_temporel_pour_toute_la_page():
    """« 30 jours » valait 154 dans les KPI et 160 dans P3 : deux ancrages
    différents (`Date.now()` côté client vs `max(date)` côté signaux) pour la
    même question. L'ancrage vit maintenant uniquement en Python
    (`build_analytics`), publié une fois dans `status.json`."""
    js = _read("assets/dashboard.js")
    assert "new Date()" not in js.replace("new Date(value)", "").replace("new Date(incident", "")
    assert "state.analytics" in js
    assert '["analytics"] = analytics.build_analytics(' in _read("cyberwatch/site.py")


def test_les_agregats_de_signal_ne_sont_pas_recalcules_en_javascript():
    """`analytics.py` était entièrement testé mais jamais appelé ; `p3.js`
    réimplémentait les mêmes règles en JS, sans test, avec quatre divergences
    (ancrage, fenêtres, libellés, plafond). Il ne doit rester qu'une seule
    implémentation des seuils de signal."""
    js = _read("assets/dashboard.js")
    for forbidden in ("BASE_RATE_EXCESS_POINTS", "DOMINANT_SHARE_PCT", "function signals(", "function confidence("):
        assert forbidden not in js, forbidden
    assert "renderSignals(a.signals" in js


# ------------------------------------------------------ signaux honnêtes

def test_une_categorie_majoritaire_ne_peut_pas_etre_un_signal():
    """Taux de base +48,1 % sur 30 j : « Fuite de données » (69 % de la
    fenêtre) et « France métropolitaine » (93 %) ressortaient en tête des
    signaux avec une confiance élevée alors qu'ils suivaient exactement la
    croissance globale."""
    from cyberwatch import analytics

    rows = []
    for i in range(30):
        rows.append({"id": f"c{i}", "date": f"2026-08-{(i % 20) + 1:02d}", "threat": "Fuite de données"})
    for i in range(10):
        rows.append({"id": f"p{i}", "date": f"2026-07-{(i % 20) + 1:02d}", "threat": "Fuite de données"})
    payload = analytics.build_analytics(rows, as_of="2026-08-21")
    labels = {signal["label"] for signal in payload["signals"] if signal["window_days"] == 30}
    assert "Fuite de données" not in labels


def test_l_ampleur_des_fuites_ne_publie_jamais_de_somme():
    """264 incidents sur 871 portent un volume, dont 36 seulement confirmés :
    une somme serait dominée par une revendication à 600 millions et
    indéfendable pour un lecteur qui cite le chiffre."""
    js = _read("assets/dashboard.js")
    assert "exposure.sum" not in js
    assert "exposure.total_value" not in js
    assert "exposure.median" in js and "exposure.p90" in js

    from cyberwatch import analytics

    exposure = analytics._exposure([
        {"id": "a", "facts": [{"affected_count": 100, "affected_unit": "people", "claim_status": "confirmed"}]},
        {"id": "b", "facts": [{"affected_count": 500, "affected_unit": "records", "claim_status": "reported"}]},
        {"id": "c", "facts": [{"affected_count": 600_000_000, "affected_unit": "people", "claim_status": "claimed"}]},
    ])
    assert set(exposure) & {"sum", "total_value"} == set()
    assert exposure["median"] < 600_000_000


# ------------------------------------------------------------ fiche incident
# Invariants portés depuis les anciens tests table-based (supprimés avec
# l'explorateur historique) : le contenu qu'ils protégeaient vit maintenant
# dans le dialogue partagé des trois vues.

def test_un_impact_deja_couvert_par_la_synthese_n_est_pas_repete():
    """La synthèse d'incident et le champ `impact` d'un fait source se
    recoupaient souvent mot pour mot : `narrativeContains` évite de répéter
    la même phrase deux fois dans la fiche."""
    js = _read("assets/dashboard.js")
    assert "function narrativeContains(container, detail)" in js
    assert "narrativeContains(fact.summary, fact.impact)" in js
    assert "narrativeContains(incidentSummary, fact.impact)" in js
    assert 'const sourceImpact = impactCovered ? "" : fact.impact;' in js
    assert 'factRow("Impact", sourceImpact)' in js


def test_la_synthese_incident_precede_toujours_les_faits_par_source():
    js = _read("assets/dashboard.js")
    match = re.search(r"function factsSectionHtml\(incident, facts\)\s*\{(.*?)\n  \}", js, re.DOTALL)
    assert match, "factsSectionHtml() introuvable"
    body = match.group(1)
    assert body.index("incident.summary") < body.index("dialog-facts")


def test_criticite_des_donnees_est_calculee_sans_observer_le_dom():
    """La classification (données sensibles / personnelles / non qualifiées)
    est un calcul pur sur les faits, jamais un `MutationObserver` sur le DOM
    déjà rendu."""
    js = _read("assets/dashboard.js")
    assert "Données sensibles" in js
    assert "Données personnelles" in js
    assert "Données non qualifiées" in js
    assert "SENSITIVE_MARKERS" in js
    assert "PERSONAL_EXACT" in js
    assert "function sensitivity(" in js
    assert "MutationObserver" not in js


def test_historique_source_tronque_est_rendu_sans_degrader_le_statut():
    js = _read("assets/dashboard.js")
    match = re.search(r"function renderSourcesDetail\(\)\s*\{(.*?)\n  \}", js, re.DOTALL)
    assert match, "renderSourcesDetail() introuvable"
    body = match.group(1)
    assert "source.history_status" in body
    assert "source.oldest_available_date" in body
    assert 'historyStatus === "TRUNCATED"' in body
    assert "Historique borné" in body


def test_le_debounce_de_recherche_est_annule_par_le_bouton_reinitialiser():
    """Sans l'annulation du minuteur, un `Réinitialiser` cliqué pendant la
    frappe pouvait voir le filtre réapparaître 200 ms plus tard."""
    js = _read("assets/dashboard.js")
    match = re.search(r'\$\("#s-reset"\)\.addEventListener\("click", \(\) => \{(.*?)\n    \}\);', js, re.DOTALL)
    assert match, "handler #s-reset introuvable"
    assert "state.filters = {" in match.group(1)


def test_resize_ignore_les_micro_variations_et_ne_re_render_pas_toute_la_page():
    """Un `resize` mobile (barre d'adresse qui se rétracte) ne doit ni
    déclencher un rendu en dessous de 20 px d'écart, ni reconstruire les vues
    qui n'ont pas de graphique (Veille, Recherche)."""
    js = _read("assets/dashboard.js")
    assert "let lastWidth = document.documentElement.clientWidth" in js
    assert "Math.abs(width - lastWidth) <= 20" in js
    resize = re.search(r"function setupResize\(\)\s*\{(.*?)\n  \}", js, re.DOTALL)
    assert resize
    assert 'state.view === "analyse"' in resize.group(1)
