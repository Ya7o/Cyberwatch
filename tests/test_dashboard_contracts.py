"""Contrats du dashboard vérifiables sans navigateur.

Ces tests encodent des *invariants*, pas des libellés d'interface : renommer un
titre ne doit pas les casser, mais réintroduire l'un des défauts qu'ils
décrivent doit les faire échouer. Chaque test cite le défaut mesuré qu'il
empêche de revenir.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CSS_FILES = (
    "assets/style.css",
    "assets/dashboard-runtime.css",
    "assets/dashboard-mobile-fixes.css",
    "assets/p2.css",
    "assets/p3.css",
)


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


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

    Avant correction, un `incidents.json` absent ou corrompu affichait
    « Incidents recensés : 0 » avec une pastille verte « 5/5 opérationnelles »
    et aucun message : une panne technique se lisait comme une absence
    d'incident.
    """
    html = _read("index.html")
    # L'attribut doit porter sur le bandeau lui-même : une sous-chaîne
    # `role="alert"` trouvée ailleurs ne prouve rien.
    assert re.search(r'<div id="data-alert"[^>]*\srole="alert"', html)
    assert 'id="data-alert-detail"' in html

    for runtime in ("assets/app.js", "assets/p2.js"):
        js = _read(runtime)
        assert "reportDataFailure" in js, runtime
        # `load` remonte l'issue au lieu de renvoyer directement le repli.
        assert "{ ok: true, data:" in js, runtime
        assert "{ ok: false, data:" in js, runtime

    app = _read("assets/app.js")
    assert "renderUnavailable" in app
    # Les compteurs passent à « — », jamais à 0, quand rien n'a été chargé.
    assert 'if (!state.dataOk) return renderUnavailable();' in app
    # Une base non chargée ne peut pas afficher une pastille de collecte saine.
    assert 'text.textContent = "Incidents non chargés";' in app

    p3 = _read("assets/p3.js")
    # Une section Intelligence vide se lirait comme « aucun signal ».
    assert "function abort(" in p3
    assert 'return abort(' in p3


def test_les_agregats_p2_ne_montrent_aucun_zero_sans_donnees():
    """Le bandeau ne suffit pas si les cartes affichent encore des zéros.

    « 0 organisations distinctes » et un zéro par territoire se lisent comme
    « rien n'a été observé », alors que rien n'a été *chargé* — et la légende
    géographique dit justement qu'un zéro est un angle mort d'observation.
    """
    js = _read("assets/p2.js")
    assert "renderUnavailableInsights" in js
    assert re.search(r"if \(state\.dataOk\) \{\s+renderSummary\(rows\);", js)
    assert re.search(r"\} else \{\s+renderUnavailableInsights\(\);", js)
    assert 'state.dataOk ? "0 incident" : "Données indisponibles"' in js


def test_p2_ne_masque_l_explorateur_qu_apres_une_initialisation_complete():
    """Le repli ne protégeait que le 404 du script lui-même.

    Une exception levée après `injectShell()` laissait `p2-active` posé :
    l'explorateur historique restait masqué derrière une coquille P2 vide, et
    la page affichait zéro incident sur 871 sans aucune erreur visible.
    """
    js = _read("assets/p2.js")
    activation = 'document.documentElement.classList.add("p2-active")'
    assert activation in js
    # L'activation ne vit que dans `activate()`, appelée en dernier.
    assert js.count(activation) == 1
    assert re.search(r"function activate\(\)\s*\{\s*" + re.escape(activation), js)
    assert re.search(r"render\(\);\s*\n\s*activate\(\);", js)
    # Et un échec la retire explicitement.
    assert 'classList.remove("p2-active")' in js
    assert re.search(r"catch \(error\) \{\s*\n\s*rollback\(error\);", js)


# ------------------------------------------------------------ accessibilité

def test_la_liste_des_incidents_n_est_pas_une_region_live():
    """`#p2-list` portait `aria-live` avec 463 nœuds enfants.

    Chaque frappe dans la recherche relisait la liste entière au lecteur
    d'écran. Le statut appartient au compteur, pas au contenu.
    """
    js = _read("assets/p2.js")
    assert 'id="p2-list" class="p2-list"></div>' in js
    assert 'id="p2-list" class="p2-list" aria-live' not in js
    assert re.search(r'id="p2-count"[^>]*aria-live="polite"', js)


def test_la_page_offre_un_lien_d_evitement():
    """172 arrêts de tabulation visibles sur une page de 16 000 px mobile."""
    html = _read("index.html")
    assert 'class="skip-link" href="#contenu"' in html
    assert 'id="contenu"' in html
    assert html.index("skip-link") < html.index('<header')
    assert ".skip-link" in _read("assets/dashboard-runtime.css")


def test_les_barres_de_graphique_ne_sont_pas_des_arrets_de_tabulation():
    """32 `<rect>` en `tabindex=0` pour n'afficher qu'une infobulle.

    Les valeurs sont désormais portées par l'`aria-label` du graphique entier,
    qui les énumère réellement au lieu d'un intitulé générique.
    """
    js = _read("assets/app.js")
    assert 'node.setAttribute("tabindex", "0")' not in js
    assert 'node.setAttribute("aria-hidden", "true")' in js
    assert "function chartLabel(" in js
    assert '"aria-label": chartLabel(' in js


# ------------------------------------------------------------- robustesse

def test_l_axe_mensuel_est_borne_et_les_dates_futures_sont_signalees():
    """Un seul incident daté 2099 produisait 874 barres et un SVG de 43 602 px."""
    js = _read("assets/app.js")
    assert "const MAX_CHART_MONTHS = 36;" in js
    assert "key <= currentKey" in js
    # Les dates écartées sont comptées et affichées, jamais silencieusement
    # supprimées.
    assert "month-note" in js
    assert "month-note" in _read("index.html")
