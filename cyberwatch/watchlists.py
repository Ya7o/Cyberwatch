"""Listes fixes d'entités surveillées (§14.3, §15.2, §16.2, §17.2, §18.2, §19.1).

Ces listes sont normatives : elles définissent la couverture attendue des
couches `ENTITY_WATCH`. Toute entité qui y figure et n'a pas été interrogée fait
baisser la couverture de la source — c'est ce qui rend le `PARTIAL` mesurable.

Les communes sont surveillées sous la forme « Mairie de X » plutôt que « X » :
c'est le nom de l'organisation réellement victime, et cela évite la confusion
avec les homonymes métropolitains (Saint-Denis, Sainte-Marie, Saint-Louis…).
Le contexte territorial est ajouté à la requête pour la même raison.
"""

from __future__ import annotations

from . import config
from .model import WatchedEntity


def _commune(name: str, territory: str) -> WatchedEntity:
    """Entité « mairie » d'une commune, avec ses formulations alternatives."""
    return WatchedEntity(
        name=f"Mairie de {name}",
        territory=territory,
        kind="commune",
        sector_hint=config.SECTOR_ADMIN,
        aliases=[f"commune de {name}", f"ville de {name}", name],
    )


# --------------------------------------------------------------------------
# La Réunion — 24 communes (§14.3)
# --------------------------------------------------------------------------

REUNION_COMMUNES = [
    "Les Avirons", "Bras-Panon", "Cilaos", "Entre-Deux", "L'Étang-Salé",
    "La Plaine-des-Palmistes", "La Possession", "Le Port", "Le Tampon",
    "Les Trois-Bassins", "Petite-Île", "Saint-André", "Saint-Benoît",
    "Saint-Denis", "Saint-Joseph", "Saint-Leu", "Saint-Louis", "Saint-Paul",
    "Saint-Philippe", "Saint-Pierre", "Sainte-Marie", "Sainte-Rose",
    "Sainte-Suzanne", "Salazie",
]

REUNION_CRITICAL = [
    ("Région Réunion", config.SECTOR_ADMIN, ["Conseil régional de La Réunion"]),
    ("Département de La Réunion", config.SECTOR_ADMIN, ["Conseil départemental de La Réunion"]),
    ("Préfecture de La Réunion", config.SECTOR_ADMIN, []),
    ("CHU de La Réunion", config.SECTOR_HEALTH, ["CHU Réunion", "centre hospitalier universitaire de La Réunion"]),
    ("Université de La Réunion", config.SECTOR_EDUCATION, []),
    ("Rectorat de La Réunion", config.SECTOR_EDUCATION, ["Académie de La Réunion"]),
    ("CAF de La Réunion", config.SECTOR_ADMIN, ["Caisse d'allocations familiales de La Réunion"]),
    ("CGSS Réunion", config.SECTOR_ADMIN, ["Caisse générale de sécurité sociale de La Réunion"]),
    ("Grand Port Maritime de La Réunion", config.SECTOR_TRANSPORT, ["Port Réunion"]),
    ("Aéroport de La Réunion Roland-Garros", config.SECTOR_TRANSPORT, ["aéroport Roland-Garros"]),
    ("Aéroport de Pierrefonds", config.SECTOR_TRANSPORT, []),
    ("Air Austral", config.SECTOR_TRANSPORT, []),
    ("EDF Réunion", config.SECTOR_ENERGY, ["EDF à La Réunion"]),
    ("Runéo", config.SECTOR_ENERGY, []),
    ("CISE Réunion", config.SECTOR_ENERGY, []),
    ("Orange Réunion", config.SECTOR_TECH, []),
    ("SFR Réunion", config.SECTOR_TECH, []),
    ("Zeop", config.SECTOR_TECH, []),
    ("CCI Réunion", config.SECTOR_RETAIL, ["Chambre de commerce et d'industrie de La Réunion"]),
    ("Chambre de Métiers et de l'Artisanat de La Réunion", config.SECTOR_RETAIL, []),
]

# --------------------------------------------------------------------------
# Mayotte — 17 communes (§15.2)
# --------------------------------------------------------------------------

MAYOTTE_COMMUNES = [
    "Acoua", "Bandraboua", "Bandrélé", "Bouéni", "Chiconi", "Chirongui",
    "Dembéni", "Dzaoudzi-Labattoir", "Kani-Kéli", "Koungou", "Mamoudzou",
    "M'Tsamboro", "M'Tsangamouji", "Ouangani", "Pamandzi", "Sada", "Tsingoni",
]

MAYOTTE_CRITICAL = [
    ("Département de Mayotte", config.SECTOR_ADMIN, ["Conseil départemental de Mayotte"]),
    ("Préfecture de Mayotte", config.SECTOR_ADMIN, []),
    ("Centre Hospitalier de Mayotte", config.SECTOR_HEALTH, ["CHM"]),
    ("Rectorat de Mayotte", config.SECTOR_EDUCATION, ["Académie de Mayotte"]),
    ("Centre universitaire de Mayotte", config.SECTOR_EDUCATION, ["CUFR Mayotte"]),
    ("Caisse de Sécurité Sociale de Mayotte", config.SECTOR_ADMIN, ["CSSM"]),
    ("Électricité de Mayotte", config.SECTOR_ENERGY, ["EDM Mayotte"]),
    ("SMAE Mayotte", config.SECTOR_ENERGY, ["Société mahoraise des eaux"]),
    ("Port de Longoni", config.SECTOR_TRANSPORT, []),
    ("Aéroport de Dzaoudzi-Pamandzi", config.SECTOR_TRANSPORT, ["aéroport de Mayotte"]),
    ("CCI Mayotte", config.SECTOR_RETAIL, []),
    ("Orange Mayotte", config.SECTOR_TECH, []),
    ("SFR Mayotte", config.SECTOR_TECH, []),
    ("Mayotte Telecom", config.SECTOR_TECH, []),
]

# --------------------------------------------------------------------------
# Entités critiques régionales (§16.2, §17.2, §18.2, §19.1)
# --------------------------------------------------------------------------

MAURICE_CRITICAL = [
    ("Government of Mauritius", config.SECTOR_ADMIN, []),
    ("Mauritius Telecom", config.SECTOR_TECH, []),
    ("Emtel", config.SECTOR_TECH, []),
    ("Central Electricity Board", config.SECTOR_ENERGY, []),
    ("Central Water Authority", config.SECTOR_ENERGY, []),
    ("Air Mauritius", config.SECTOR_TRANSPORT, []),
    ("Airports of Mauritius", config.SECTOR_TRANSPORT, []),
    ("Bank of Mauritius", config.SECTOR_FINANCE, []),
    ("Mauritius Commercial Bank", config.SECTOR_FINANCE, ["MCB"]),
    ("State Bank of Mauritius", config.SECTOR_FINANCE, ["SBM"]),
    ("Mauritius Revenue Authority", config.SECTOR_FINANCE, ["MRA"]),
]

MADAGASCAR_CRITICAL = [
    ("Gouvernement malgache", config.SECTOR_ADMIN, ["ministère malgache"]),
    ("Orange Madagascar", config.SECTOR_TECH, []),
    ("Telma", config.SECTOR_TECH, ["Telma Madagascar"]),
    ("Airtel Madagascar", config.SECTOR_TECH, []),
    ("JIRAMA", config.SECTOR_ENERGY, []),
    ("Madagascar Airlines", config.SECTOR_TRANSPORT, ["Air Madagascar"]),
    ("Banky Foibe", config.SECTOR_FINANCE, ["Banque centrale de Madagascar"]),
    ("Douanes malgaches", config.SECTOR_FINANCE, ["direction générale des impôts Madagascar"]),
]

SEYCHELLES_CRITICAL = [
    ("Government of Seychelles", config.SECTOR_ADMIN, ["Department of Information Communications Technology"]),
    ("Central Bank of Seychelles", config.SECTOR_FINANCE, []),
    ("Seychelles Commercial Bank", config.SECTOR_FINANCE, []),
    ("Airtel Seychelles", config.SECTOR_TECH, []),
    ("Cable & Wireless Seychelles", config.SECTOR_TECH, []),
    ("Air Seychelles", config.SECTOR_TRANSPORT, []),
    ("Seychelles Civil Aviation Authority", config.SECTOR_TRANSPORT, []),
    ("Public Utilities Corporation", config.SECTOR_ENERGY, []),
]

COMORES_CRITICAL = [
    ("ANADEN", config.SECTOR_ADMIN, ["Agence nationale de développement du numérique"]),
    ("Gouvernement des Comores", config.SECTOR_ADMIN, ["Union des Comores"]),
    ("Banque Centrale des Comores", config.SECTOR_FINANCE, []),
    ("Comores Telecom", config.SECTOR_TECH, []),
    ("Telma Comores", config.SECTOR_TECH, []),
    ("Société Nationale d'Électricité des Comores", config.SECTOR_ENERGY, ["SONELEC"]),
    ("Aéroport de Moroni", config.SECTOR_TRANSPORT, ["aéroport Prince Said Ibrahim"]),
    ("Port de Moroni", config.SECTOR_TRANSPORT, []),
]


def _build(
    communes: list[str],
    critical: list[tuple[str, str, list[str]]],
    territory: str,
) -> list[WatchedEntity]:
    entities = [_commune(name, territory) for name in communes]
    entities += [
        WatchedEntity(
            name=name,
            territory=territory,
            kind="critique",
            sector_hint=sector,
            aliases=list(aliases),
        )
        for name, sector, aliases in critical
    ]
    return entities


REUNION_ENTITIES = _build(REUNION_COMMUNES, REUNION_CRITICAL, config.LOC_REUNION)
MAYOTTE_ENTITIES = _build(MAYOTTE_COMMUNES, MAYOTTE_CRITICAL, config.LOC_MAYOTTE)
MAURICE_ENTITIES = _build([], MAURICE_CRITICAL, config.LOC_MAURICE)
MADAGASCAR_ENTITIES = _build([], MADAGASCAR_CRITICAL, config.LOC_MADAGASCAR)
SEYCHELLES_ENTITIES = _build([], SEYCHELLES_CRITICAL, config.LOC_SEYCHELLES)
COMORES_ENTITIES = _build([], COMORES_CRITICAL, config.LOC_COMORES)

ALL_ENTITIES = (
    REUNION_ENTITIES
    + MAYOTTE_ENTITIES
    + MAURICE_ENTITIES
    + MADAGASCAR_ENTITIES
    + SEYCHELLES_ENTITIES
    + COMORES_ENTITIES
)

#: Contexte territorial ajouté aux requêtes, pour écarter les homonymes.
TERRITORY_CONTEXT = {
    config.LOC_REUNION: "La Réunion",
    config.LOC_MAYOTTE: "Mayotte",
    config.LOC_MAURICE: "Maurice",
    config.LOC_MADAGASCAR: "Madagascar",
    config.LOC_SEYCHELLES: "Seychelles",
    config.LOC_COMORES: "Comores",
}


def as_params(entities: list[WatchedEntity]) -> list[dict]:
    """Entités converties au format attendu par les collecteurs de veille.

    Les alias transmis sont ceux qui **identifient** l'entité : le nom nu d'une
    commune en est exclu, faute de quoi la moindre mention de la ville
    rattacherait l'article à sa mairie.
    """
    return [
        {
            "name": entity.name,
            "aliases": identifying_labels(entity)[1:],
            "context": TERRITORY_CONTEXT.get(entity.territory, ""),
            "territory": entity.territory,
            "kind": entity.kind,
            "sector_hint": entity.sector_hint,
        }
        for entity in entities
    ]


def entity_index() -> dict[str, WatchedEntity]:
    """Index des entités par nom, pour retrouver secteur et territoire."""
    return {entity.name: entity for entity in ALL_ENTITIES}


def entity_territories() -> dict[str, str]:
    """Index « clé normalisée -> territoire » des entités surveillées.

    Permet à une organisation reconnue d'imposer son territoire, quelle que soit
    la source qui la mentionne : Air Austral est réunionnaise même lorsqu'un
    agrégateur national la relaie. Seuls les libellés identifiants sont indexés,
    pour la même raison que dans `known_organisations()`.
    """
    from .normalize import searchable

    index: dict[str, str] = {}
    for entity in ALL_ENTITIES:
        for label in identifying_labels(entity):
            key = searchable(label)
            if key and key not in index:
                index[key] = entity.territory
    return index


#: Qualificatifs rendant un libellé de commune non ambigu.
_COMMUNE_QUALIFIERS = ("mairie", "commune", "ville")


def identifying_labels(entity: WatchedEntity) -> list[str]:
    """Libellés permettant d'attribuer un article à une entité.

    Pour une commune, le nom nu est écarté : citer « Saint-Denis » désigne la
    ville, pas sa mairie. Sans cette règle, tout fait divers survenu sur le
    territoire communal devenait un incident de la collectivité — c'est ainsi
    qu'une intrusion dans une fourrière est entrée dans la base.
    """
    from .normalize import searchable

    labels = [entity.name, *entity.aliases]
    if entity.kind != "commune":
        return labels
    return [
        label
        for label in labels
        if any(q in searchable(label) for q in _COMMUNE_QUALIFIERS)
    ]


def known_organisations() -> dict[str, str]:
    """Index « clé normalisée -> libellé officiel » de toutes les entités.

    Sert à reconnaître une organisation citée dans un article de presse sans
    recourir à un rapprochement flou, interdit par le §7.

    Les noms de communes nus (« Saint-Denis », « Sainte-Marie ») sont exclus :
    ils sont trop ambigus hors du contexte d'une requête nominative et
    attribueraient des incidents métropolitains à une commune ultramarine.
    Ils restent utilisables pour la vérification de mention au sein de la
    couche `ENTITY_WATCH`, où la requête a déjà fixé le contexte.
    """
    from .normalize import searchable

    index: dict[str, str] = {}
    for entity in ALL_ENTITIES:
        for label in [entity.name, *entity.aliases]:
            key = searchable(label)
            if not key or key in index:
                continue
            if entity.kind == "commune" and not any(
                qualifier in key for qualifier in _COMMUNE_QUALIFIERS
            ):
                continue
            index[key] = entity.name
    return index
