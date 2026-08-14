"""Référentiel des sources (§13 à §23).

Chaque source déclare son URL de départ, son protocole, son test de succès et sa
règle de localisation. Ce fichier est la traduction exécutable du tableau du
§23. Cinq lignes sont volontairement inactives, chacune avec le motif de
sa désactivation et son critère de réactivation (§21).

Deux écarts assumés par rapport à la méthode d'origine, tous deux documentés
dans `METHODOLOGY.md` :

- `RANSOMWARE_LIVE` est **activée** : elle était désactivée faute d'accès
  opérationnel en conversation, alors qu'il s'agit d'une API JSON publique. La
  méthode la désigne elle-même comme prioritaire (§21).
- Les couches de veille interrogent **directement les flux des médias** au
  lieu d'un moteur de recherche. La voie Google News, envisagée d'abord, est
  fermée : son `robots.txt` interdit `/rss/search`. Le remplacement suit la
  règle « source directe > recherche moteur » (§31).
"""

from __future__ import annotations

from . import config, watchlists
from .collectors.base import SourceSpec
from .model import SOURCE_COLUMNS

# --------------------------------------------------------------------------
# Médias suivis par territoire, pour les couches de veille.
# Ces domaines sont interrogés via leur propre flux : c'est la traduction de la
# règle « source directe > recherche moteur » (§31).
# --------------------------------------------------------------------------

REUNION_MEDIA = [
    "www.zinfos974.com",
    "www.linfo.re",
    "www.clicanoo.re",
    "www.ipreunion.com",
    "www.imazpress.com",
    "la1ere.francetvinfo.fr/reunion",
]

MAYOTTE_MEDIA = [
    "www.linfokwezi.fr",
    "mayottehebdo.com",
    "lejournaldemayotte.yt",
    "la1ere.francetvinfo.fr/mayotte",
]

MAURICE_MEDIA = ["defimedia.info", "lexpress.mu", "www.lemauricien.com"]
MADAGASCAR_MEDIA = ["lexpress.mg", "midi-madagasikara.mg"]
SEYCHELLES_MEDIA = ["www.nation.sc"]
COMORES_MEDIA = ["alwatwan.net", "lagazettedescomores.com"]

# --------------------------------------------------------------------------
# Couche A — CORE_DIRECT : archives et agrégateurs parcourables directement
# --------------------------------------------------------------------------

CORE_SOURCES = [
    SourceSpec(
        source_id="FRENCHBREACHES",
        layer=config.LAYER_CORE,
        zone=config.LOC_FRANCE,
        start_url="https://frenchbreaches.com/feed.xml",
        collector="feed",
        active=True,
        default_threat=config.THREAT_LEAK,
        location_rule=config.LOC_INCONNU,
        params={
            "title_is_organisation": True,
            "feed_url": "https://frenchbreaches.com/feed.xml",
        },
        protocol=(
            "Lire le flux RSS complet des alertes de fuite, descendre jusqu'à "
            "TARGET_START, relever date, organisation, titre, menace et URL."
        ),
        success_test=(
            "Borne de date atteinte et toutes les entrées de la fenêtre énumérées."
        ),
        notes=(
            "Chaque entrée est nommée d'après l'organisation touchée : le titre "
            "de l'entrée est l'organisation. Localisation par défaut France "
            "métropolitaine sauf indication contraire."
        ),
    ),
    SourceSpec(
        source_id="BONJOURLAFUITE",
        layer=config.LAYER_CORE,
        zone=config.LOC_FRANCE,
        start_url="https://bonjourlafuite.eu.org/",
        collector="bonjourlafuite",
        default_threat=config.THREAT_LEAK,
        location_rule=config.LOC_INCONNU,
        params={"title_is_organisation": True},
        protocol=(
            "Parcourir la timeline : date, organisation, via, données concernées, "
            "source. Filtrer par période."
        ),
        success_test="Timeline parcourue jusqu'à la borne, chaque item daté et nommé.",
        notes=(
            "Chaque bloc de la chronologie est nommé d'après l'organisation "
            "touchée : le titre de l'entrée est l'organisation. "
            "Page de contrôle de volume : https://bonjourlafuite.eu.org/stats.html"
        ),
    ),
    SourceSpec(
        source_id="CYBERATTAQUE_ORG",
        layer=config.LAYER_CORE,
        zone=config.LOC_FRANCE,
        start_url="https://www.cyberattaque.org/type/attaque/",
        collector="cyberattaque_org",
        active=True,
        location_rule=config.LOC_INCONNU,
        params={"categories": "attaque", "scope_is_cyber": True, "include_content": True},
        protocol=(
            "Parcourir séquentiellement la pagination sans sauter de page, "
            "jusqu'à une date antérieure à TARGET_START."
        ),
        success_test="Toutes les pages nécessaires parcourues, aucune page sautée.",
        notes=(
            "La catégorie « attaque » du site ne publie que des incidents : son "
            "périmètre fait foi, le garde-fou de vocabulaire ne s'y applique pas. "
            "Victime extraite seulement depuis une relation explicite ou un préfixe "
            "de titre non rédactionnel."
        ),
    ),
    SourceSpec(
        source_id="RANSOMWARE_LIVE",
        layer=config.LAYER_CORE,
        zone="Multi",
        start_url="https://api.ransomware.live/",
        collector="ransomware_live",
        active=True,
        default_threat=config.THREAT_RANSOMWARE,
        params={
            "countries": ["FR", "RE", "YT", "MU", "MG", "SC", "KM"],
            "live_repeat_cooldown_seconds": config.RANSOMWARE_LIVE_RATE_LIMIT_SECONDS,
        },
        protocol=(
            "Interroger l'API pour chaque pays du périmètre : organisation, "
            "date, groupe, pays, secteur si disponible."
        ),
        success_test="Tous les pays du périmètre interrogés avec succès.",
        notes=(
            "Activée par rapport à la méthode d'origine : source prioritaire (§21), "
            "les sources françaises étant fortement orientées fuite de données."
        ),
    ),
    SourceSpec(
        source_id="CERT_MU_ALERTS",
        layer=config.LAYER_CORE,
        zone=config.LOC_MAURICE,
        start_url="https://cert-mu.govmu.org/cert-mu/?page_id=1439",
        collector="autodetect",
        active=False,
        location_rule=config.LOC_MAURICE,
        protocol="Lire toutes les Security Alerts de la fenêtre : date, titre, URL.",
        success_test="Liste datée énumérable et parcourue intégralement.",
        notes="Une alerte générique de phishing ou de scam ne crée pas d'incident.",
    ),
    SourceSpec(
        source_id="CIRT_MG",
        layer=config.LAYER_DISABLED,
        zone=config.LOC_MADAGASCAR,
        start_url="https://www.cirt.gov.mg/",
        collector="autodetect",
        active=False,
        location_rule=config.LOC_MADAGASCAR,
        protocol="Lire les bulletins et alertes datés de la fenêtre.",
        success_test="Bulletins énumérables de façon stable.",
        notes=(
            "Inactive depuis la vérification du 12/08/2026 : le site est une "
            "coquille JavaScript de 1,5 Ko, ses flux répondent 200 avec zéro "
            "entrée et toutes les pages de pagination sont identiques. Aucun "
            "bulletin n'y est énumérable sans navigateur. Réactiver dès que la "
            "commande probe y trouve des entrées datées."
        ),
    ),
    SourceSpec(
        source_id="CERT_SC_ALERTS",
        layer=config.LAYER_DISABLED,
        zone=config.LOC_SEYCHELLES,
        start_url="https://cert-sc.sc/alerts/",
        collector="autodetect",
        active=False,
        location_rule=config.LOC_SEYCHELLES,
        protocol="Énumérer les alertes et relever leur date.",
        success_test="Toutes les alertes énumérables et datables.",
        notes=(
            "Inactive depuis la vérification du 12/08/2026 : /alerts/ renvoie la "
            "page d'accueil (titre « Welcome »), sans aucune liste datée, et les "
            "flux répondent 404. L'URL du protocole d'origine n'existe plus sous "
            "cette forme. Réactiver après avoir retrouvé l'URL réelle des alertes."
        ),
    ),
]

# --------------------------------------------------------------------------
# Couche B — LOCAL_MEDIA_DIRECT : rubriques thématiques de médias locaux
# --------------------------------------------------------------------------

LOCAL_MEDIA_SOURCES = [
    SourceSpec(
        source_id="ZINFOS974_CYBER",
        layer=config.LAYER_DISABLED,
        zone=config.LOC_REUNION,
        start_url="https://www.zinfos974.com/dossier/cyberattaque/",
        collector="autodetect",
        active=False,
        location_rule=config.LOC_REUNION,
        protocol="Lire chaque article du dossier, suivre la pagination jusqu'à la borne.",
        success_test="Pagination parcourue jusqu'à la borne, tous les items datés.",
        notes=(
            "Inactive depuis la vérification du 12/08/2026 : le site répond 403 "
            "à toute requête, y compris sur les chemins que son propre robots.txt "
            "autorise, et après une nouvelle tentative sous un agent accepté par "
            "les pare-feux courants. Les articles réunionnais restent atteints par "
            "REUNION_ENTITY_WATCH, qui lit quatre autres médias du territoire."
        ),
    ),
    SourceSpec(
        source_id="LINFO_CYBER",
        layer=config.LAYER_DISABLED,
        zone=config.LOC_REUNION,
        start_url="https://www.linfo.re/tags/cyberattaque",
        collector="autodetect",
        active=False,
        location_rule=config.LOC_REUNION,
        protocol="Lire toutes les cartes de l'étiquette, parcourir les pages numériques.",
        success_test="Pagination complète, chaque carte datée avec URL.",
        notes=(
            "Inactive depuis la vérification du 12/08/2026 : même refus 403 "
            "systématique que Zinfos974, robots.txt pourtant permissif. Les "
            "articles réunionnais restent atteints par REUNION_ENTITY_WATCH."
        ),
    ),
    SourceSpec(
        source_id="KWEZI_NUMERIQUE",
        layer=config.LAYER_LOCAL_MEDIA,
        zone=config.LOC_MAYOTTE,
        start_url="https://www.linfokwezi.fr/numerique/",
        collector="kwezi",
        active=True,
        location_rule=config.LOC_INCONNU,
        params={"categories": "numerique", "include_content": True},
        protocol="Lire la rubrique Numérique jusqu'à la borne, retenir les contenus cyber.",
        success_test="Liste parcourue jusqu'à la borne, chaque item daté avec URL.",
        notes="Incident créé uniquement si une organisation victime est nommée.",
    ),
]

# --------------------------------------------------------------------------
# Couche C — ENTITY_WATCH : surveillance nominative via les flux des médias
# --------------------------------------------------------------------------

_WATCH_PROTOCOL = (
    "Lire le flux de chaque média du territoire, retenir les articles relevant "
    "du cyber, et reconnaître nominativement les entités surveillées."
)
_WATCH_SUCCESS = (
    "OK seulement si tous les médias du territoire ont répondu ET si les flux "
    "remontent jusqu'au début de la fenêtre ; sinon PARTIAL avec la couverture "
    "réelle, jamais un zéro vérifié."
)
_WATCH_NOTE = (
    "Les requêtes Google News de la méthode d'origine ont été abandonnées : le "
    "robots.txt de Google interdit /rss/search. Les médias sont donc interrogés "
    "directement, conformément à la règle « source directe > recherche moteur » "
    "(§31). Un flux ne portant que ses dernières publications, cette couche "
    "surveille le présent et ne reconstitue pas l'historique."
)


def _watch(source_id, zone, media, entities, layer, require_entity=True, notes=""):
    """Source de veille : flux directs des médias + entités surveillées."""
    return SourceSpec(
        source_id=source_id,
        layer=layer,
        zone=zone,
        start_url=f"https://{media[0]}/" if media else "",
        collector="mediawatch",
        active=False,
        location_rule=zone if zone in config.LOCATIONS else "",
        params={
            "domains": media,
            "entities": watchlists.as_params(entities),
            "require_entity": require_entity,
        },
        protocol=_WATCH_PROTOCOL,
        success_test=_WATCH_SUCCESS,
        notes=" ".join(filter(None, [notes, _WATCH_NOTE])),
    )


ENTITY_WATCH_SOURCES = [
    _watch(
        "REUNION_ENTITY_WATCH",
        config.LOC_REUNION,
        REUNION_MEDIA,
        watchlists.REUNION_ENTITIES,
        config.LAYER_ENTITY_WATCH,
        notes="24 communes et 20 entités critiques de La Réunion.",
    ),
    _watch(
        "MAYOTTE_ENTITY_WATCH",
        config.LOC_MAYOTTE,
        MAYOTTE_MEDIA,
        watchlists.MAYOTTE_ENTITIES,
        config.LAYER_ENTITY_WATCH,
        notes="17 communes et les entités critiques de Mayotte.",
    ),
]

# --------------------------------------------------------------------------
# Couche D — REGIONAL_WATCH : veille par territoire
# --------------------------------------------------------------------------

REGIONAL_WATCH_SOURCES = [
    _watch(
        "MAYOTTE_MEDIA_WATCH",
        config.LOC_MAYOTTE,
        MAYOTTE_MEDIA,
        [],
        config.LAYER_REGIONAL_WATCH,
        require_entity=False,
        notes="Tout contenu cyber mahorais, sans exiger une entité de la liste.",
    ),
    _watch(
        "MAURITIUS_REGIONAL_WATCH",
        config.LOC_MAURICE,
        MAURICE_MEDIA,
        watchlists.MAURICE_ENTITIES,
        config.LAYER_REGIONAL_WATCH,
        require_entity=False,
        notes="Un article général ne crée pas d'incident sans organisation nommée.",
    ),
    _watch(
        "MADAGASCAR_REGIONAL_WATCH",
        config.LOC_MADAGASCAR,
        MADAGASCAR_MEDIA,
        watchlists.MADAGASCAR_ENTITIES,
        config.LAYER_REGIONAL_WATCH,
        require_entity=False,
    ),
    _watch(
        "SEYCHELLES_REGIONAL_WATCH",
        config.LOC_SEYCHELLES,
        SEYCHELLES_MEDIA,
        watchlists.SEYCHELLES_ENTITIES,
        config.LAYER_REGIONAL_WATCH,
        require_entity=False,
        notes="Territoire anglophone.",
    ),
    _watch(
        "COMORES_REGIONAL_WATCH",
        config.LOC_COMORES,
        COMORES_MEDIA,
        watchlists.COMORES_ENTITIES,
        config.LAYER_REGIONAL_WATCH,
        require_entity=False,
        notes="Indexation locale faible : la couverture réelle est publiée telle quelle.",
    ),
]

# --------------------------------------------------------------------------
# Couche E — CANDIDATE_DISABLED : sources non activées (§21)
# --------------------------------------------------------------------------

DISABLED_SOURCES = [
    SourceSpec(
        source_id="HACKMAGEDDON",
        layer=config.LAYER_DISABLED,
        zone="Multi",
        start_url="https://www.hackmageddon.com/category/security/cyber-attacks-timeline/",
        collector="autodetect",
        active=False,
        protocol="Paginer la catégorie, détecter le format, parser, géofiltrer.",
        success_test="Chaque événement individuel de toutes les périodes extractible.",
        notes=(
            "Inactive : formats multiples (HTML, CSV, timeline interactive) ne "
            "permettant pas une extraction fiable événement par événement."
        ),
    ),
]

ALL_SOURCES: list[SourceSpec] = (
    CORE_SOURCES
    + LOCAL_MEDIA_SOURCES
    + ENTITY_WATCH_SOURCES
    + REGIONAL_WATCH_SOURCES
    + DISABLED_SOURCES
)


def active_sources(layers: list[str] | None = None) -> list[SourceSpec]:
    """Sources actives, éventuellement restreintes à certaines couches."""
    selected = [spec for spec in ALL_SOURCES if spec.active]
    if layers:
        selected = [spec for spec in selected if spec.layer in layers]
    return selected


def by_id(source_id: str) -> SourceSpec | None:
    for spec in ALL_SOURCES:
        if spec.source_id == source_id:
            return spec
    return None


def to_rows() -> list[dict]:
    """Référentiel `SOURCES` prêt à écrire (§4.3)."""
    rows = []
    for spec in ALL_SOURCES:
        rows.append(
            {
                "Source_ID": spec.source_id,
                "Active": "YES" if spec.active else "NO",
                "Layer": spec.layer,
                "Zone": spec.zone,
                "Start_URL": spec.start_url,
                "Method": spec.collector,
                "Protocol": spec.protocol,
                "Success_test": spec.success_test,
                "Default_threat": spec.default_threat,
                "Location_rule": spec.location_rule,
                "Notes": spec.notes,
            }
        )
    return sorted(rows, key=lambda row: row["Source_ID"])


def expected_units(spec: SourceSpec) -> int:
    """Nombre d'unités attendues pour une source, avant exécution.

    Sert au mode `diagnose` pour estimer le coût d'un run complet sans le
    lancer.
    """
    params = spec.params or {}
    entities = params.get("entities") or []
    queries = params.get("queries") or []
    if spec.collector == "mediawatch":
        return len(params.get("domains") or [])
    if spec.collector == "newsrss":
        return len(entities) * 2 + len(queries)
    if spec.collector == "ransomware_live":
        return len(params.get("countries") or [])
    return 1
