"""Référentiel des sources (§13 à §23).

Chaque source déclare son URL de départ, son protocole, son test de succès et sa
règle de localisation. Ce fichier est la traduction exécutable du tableau du
§23 : dix-neuf lignes, dont deux volontairement inactives.

Deux écarts assumés par rapport à la méthode d'origine, tous deux documentés
dans `METHODOLOGY.md` :

- `RANSOMWARE_LIVE` est **activée** : elle était désactivée faute d'accès
  opérationnel en conversation, alors qu'il s'agit d'une API JSON publique. La
  méthode la désigne elle-même comme prioritaire (§21).
- Les couches de veille passent par **Google News RSS** plutôt que par un
  moteur de recherche généraliste, aucun n'étant appelable gratuitement en
  script. Les requêtes exécutées restent fixes et documentées (§22).
"""

from __future__ import annotations

from . import config, watchlists
from .collectors.base import SourceSpec
from .collectors.newsrss import domain_queries
from .model import SOURCE_COLUMNS

# --------------------------------------------------------------------------
# Couche A — CORE_DIRECT : archives et agrégateurs parcourables directement
# --------------------------------------------------------------------------

CORE_SOURCES = [
    SourceSpec(
        source_id="FRENCHBREACHES",
        layer=config.LAYER_CORE,
        zone=config.LOC_FRANCE,
        start_url="https://frenchbreaches.com/archives",
        collector="autodetect",
        default_threat=config.THREAT_LEAK,
        location_rule=config.LOC_FRANCE,
        protocol=(
            "Parcourir l'archive des alertes de fuite, descendre jusqu'à "
            "TARGET_START, relever date, organisation, titre, menace et URL."
        ),
        success_test=(
            "Borne de date atteinte et toutes les entrées de la fenêtre énumérées."
        ),
        notes="Localisation par défaut France métropolitaine sauf indication contraire.",
    ),
    SourceSpec(
        source_id="BONJOURLAFUITE",
        layer=config.LAYER_CORE,
        zone=config.LOC_FRANCE,
        start_url="https://bonjourlafuite.eu.org/",
        collector="autodetect",
        default_threat=config.THREAT_LEAK,
        location_rule=config.LOC_FRANCE,
        protocol=(
            "Parcourir la timeline : date, organisation, via, données concernées, "
            "source. Filtrer par période."
        ),
        success_test="Timeline parcourue jusqu'à la borne, chaque item daté et nommé.",
        notes="Page de contrôle de volume : https://bonjourlafuite.eu.org/stats.html",
    ),
    SourceSpec(
        source_id="CYBERATTAQUE_ORG",
        layer=config.LAYER_CORE,
        zone=config.LOC_FRANCE,
        start_url="https://www.cyberattaque.org/type/attaque/",
        collector="autodetect",
        location_rule=config.LOC_FRANCE,
        params={"categories": "attaque"},
        protocol=(
            "Parcourir séquentiellement la pagination sans sauter de page, "
            "jusqu'à une date antérieure à TARGET_START."
        ),
        success_test="Toutes les pages nécessaires parcourues, aucune page sautée.",
        notes="Organisation déduite du texte précédant « : » dans le titre.",
    ),
    SourceSpec(
        source_id="RANSOMWARE_LIVE",
        layer=config.LAYER_CORE,
        zone="Multi",
        start_url="https://api.ransomware.live/",
        collector="ransomware_live",
        default_threat=config.THREAT_RANSOMWARE,
        params={"countries": ["FR", "MU", "MG", "SC", "KM"]},
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
        location_rule=config.LOC_MAURICE,
        protocol="Lire toutes les Security Alerts de la fenêtre : date, titre, URL.",
        success_test="Liste datée énumérable et parcourue intégralement.",
        notes="Une alerte générique de phishing ou de scam ne crée pas d'incident.",
    ),
    SourceSpec(
        source_id="CIRT_MG",
        layer=config.LAYER_CORE,
        zone=config.LOC_MADAGASCAR,
        start_url="https://www.cirt.gov.mg/",
        collector="autodetect",
        location_rule=config.LOC_MADAGASCAR,
        protocol="Lire les bulletins et alertes datés de la fenêtre.",
        success_test="Bulletins énumérables de façon stable ; sinon PARTIAL.",
        notes="Incident créé uniquement si une organisation victime est nommée.",
    ),
    SourceSpec(
        source_id="CERT_SC_ALERTS",
        layer=config.LAYER_CORE,
        zone=config.LOC_SEYCHELLES,
        start_url="https://cert-sc.sc/alerts/",
        collector="autodetect",
        location_rule=config.LOC_SEYCHELLES,
        protocol="Énumérer les alertes et relever leur date.",
        success_test="Toutes les alertes énumérables et datables.",
        notes="Incident seulement si victime ou cible nommée.",
    ),
]

# --------------------------------------------------------------------------
# Couche B — LOCAL_MEDIA_DIRECT : rubriques thématiques de médias locaux
# --------------------------------------------------------------------------

LOCAL_MEDIA_SOURCES = [
    SourceSpec(
        source_id="ZINFOS974_CYBER",
        layer=config.LAYER_LOCAL_MEDIA,
        zone=config.LOC_REUNION,
        start_url="https://www.zinfos974.com/dossier/cyberattaque/",
        collector="autodetect",
        location_rule=config.LOC_REUNION,
        protocol="Lire chaque article du dossier, suivre la pagination jusqu'à la borne.",
        success_test="Pagination parcourue jusqu'à la borne, tous les items datés.",
        notes="Les reprises nationales ne deviennent réunionnaises que si elles visent La Réunion.",
    ),
    SourceSpec(
        source_id="LINFO_CYBER",
        layer=config.LAYER_LOCAL_MEDIA,
        zone=config.LOC_REUNION,
        start_url="https://www.linfo.re/tags/cyberattaque",
        collector="autodetect",
        location_rule=config.LOC_REUNION,
        protocol="Lire toutes les cartes de l'étiquette, parcourir les pages numériques.",
        success_test="Pagination complète, chaque carte datée avec URL.",
        notes="Ne jamais transformer automatiquement un article « France » en incident réunionnais.",
    ),
    SourceSpec(
        source_id="KWEZI_NUMERIQUE",
        layer=config.LAYER_LOCAL_MEDIA,
        zone=config.LOC_MAYOTTE,
        start_url="https://www.linfokwezi.fr/numerique/",
        collector="autodetect",
        location_rule=config.LOC_MAYOTTE,
        protocol="Lire la rubrique Numérique jusqu'à la borne, retenir les contenus cyber.",
        success_test="Liste parcourue jusqu'à la borne, chaque item daté avec URL.",
        notes="Incident créé uniquement si une organisation victime est nommée.",
    ),
]

# --------------------------------------------------------------------------
# Couche C — ENTITY_WATCH : surveillance nominative
# --------------------------------------------------------------------------

ENTITY_WATCH_SOURCES = [
    SourceSpec(
        source_id="REUNION_ENTITY_WATCH",
        layer=config.LAYER_ENTITY_WATCH,
        zone=config.LOC_REUNION,
        start_url="https://news.google.com/rss/search",
        collector="newsrss",
        location_rule=config.LOC_REUNION,
        params={
            "entities": watchlists.as_params(watchlists.REUNION_ENTITIES),
            "lang": "fr",
        },
        protocol=(
            "Deux requêtes fixes par entité (fusion documentée de Q1-Q4), pour "
            "les 24 communes et les 20 entités critiques de La Réunion."
        ),
        success_test=(
            "Calls_expected = nombre d'entités x 2. OK seulement si toutes les "
            "requêtes ont été exécutées ; sinon PARTIAL, jamais un zéro vérifié."
        ),
        notes="Un article de sensibilisation générale n'est pas un incident.",
    ),
    SourceSpec(
        source_id="MAYOTTE_ENTITY_WATCH",
        layer=config.LAYER_ENTITY_WATCH,
        zone=config.LOC_MAYOTTE,
        start_url="https://news.google.com/rss/search",
        collector="newsrss",
        location_rule=config.LOC_MAYOTTE,
        params={
            "entities": watchlists.as_params(watchlists.MAYOTTE_ENTITIES),
            "lang": "fr",
        },
        protocol="Mêmes requêtes que La Réunion, pour les 17 communes et les entités critiques.",
        success_test="Toutes les communes et entités critiques interrogées.",
        notes="",
    ),
]

# --------------------------------------------------------------------------
# Couche D — REGIONAL_WATCH : veille par territoire et par média
# --------------------------------------------------------------------------


def _regional(
    source_id: str,
    zone: str,
    domains: list[str],
    territory: str,
    entities,
    lang: str = "fr",
    notes: str = "",
) -> SourceSpec:
    """Source régionale : requêtes par domaine média + entités critiques."""
    queries: list[str] = []
    for domain in domains:
        queries.extend(domain_queries(domain, territory, lang))
    return SourceSpec(
        source_id=source_id,
        layer=config.LAYER_REGIONAL_WATCH,
        zone=zone,
        start_url="https://news.google.com/rss/search",
        collector="newsrss",
        location_rule=zone,
        params={
            "queries": queries,
            "entities": watchlists.as_params(entities),
            "lang": lang,
        },
        protocol=(
            f"Deux requêtes fixes par domaine ({', '.join(domains)}) et deux "
            "par entité critique du territoire."
        ),
        success_test="Toutes les requêtes prévues exécutées.",
        notes=notes,
    )


REGIONAL_WATCH_SOURCES = [
    _regional(
        "MAYOTTE_MEDIA_WATCH",
        config.LOC_MAYOTTE,
        ["linfokwezi.fr", "mayottehebdo.com", "lejournaldemayotte.yt", "gazeti.fr"],
        "Mayotte",
        [],
        notes="Complète la rubrique Numérique de Kwezi par les autres médias mahorais.",
    ),
    _regional(
        "MAURITIUS_REGIONAL_WATCH",
        config.LOC_MAURICE,
        ["defimedia.info", "lexpress.mu", "lemauricien.com"],
        "Maurice",
        watchlists.MAURICE_ENTITIES,
        notes="Un article général ne crée pas d'incident sans organisation victime nommée.",
    ),
    _regional(
        "MADAGASCAR_REGIONAL_WATCH",
        config.LOC_MADAGASCAR,
        ["lexpress.mg"],
        "Madagascar",
        watchlists.MADAGASCAR_ENTITIES,
        notes="Les ajouts de médias doivent être documentés ici avant usage.",
    ),
    _regional(
        "SEYCHELLES_REGIONAL_WATCH",
        config.LOC_SEYCHELLES,
        ["nation.sc"],
        "Seychelles",
        watchlists.SEYCHELLES_ENTITIES,
        lang="en",
        notes="Territoire anglophone : requêtes en anglais.",
    ),
    _regional(
        "COMORES_REGIONAL_WATCH",
        config.LOC_COMORES,
        ["alwatwan.net", "lagazettedescomores.com"],
        "Comores",
        watchlists.COMORES_ENTITIES,
        notes=(
            "Indexation locale faible : un protocole complet sans résultat récent "
            "donne OK avec zéro item ; une indexation insuffisante donne PARTIAL."
        ),
    ),
    SourceSpec(
        source_id="LINFO_OCEAN_INDIEN_WATCH",
        layer=config.LAYER_REGIONAL_WATCH,
        zone="Océan Indien",
        start_url="https://news.google.com/rss/search",
        collector="newsrss",
        params={
            "queries": [
                q
                for territory in ["Maurice", "Madagascar", "Mayotte", "Seychelles", "Comores"]
                for q in domain_queries("linfo.re", territory)
            ],
            "lang": "fr",
        },
        protocol="Deux requêtes fixes par territoire sur le domaine linfo.re.",
        success_test="Les dix requêtes exécutées.",
        notes=(
            "La localisation doit provenir du contenu ou de la rubrique, jamais "
            "d'une mention géographique secondaire."
        ),
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
    if spec.collector == "newsrss":
        return len(entities) * 2 + len(queries)
    if spec.collector == "ransomware_live":
        return len(params.get("countries") or [])
    return 1
