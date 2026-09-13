"""Contrat de réponse du registre public d'entreprises, entièrement pur.

Le registre est une source de premier rang : la fiche est du contenu réellement
téléchargé, l'identité y est vérifiable, et le code d'activité y figure
littéralement. Mais une requête au registre se fait **par nom**, et une
concordance de nom n'est pas une identification.

Mesuré sur la vraie API le 2026-09-12, pour ``q=qare`` :

    nom_complet="QARE", siren="921071882", activite_principale="68.20B",
    siege.commune="RIXHEIM", etat_administratif="A"

C'est une société de location immobilière du Haut-Rhin, et non la plateforme de
téléconsultation que le corpus connaît sous ce nom — que
``tests/test_sector_resolution.py`` verrouille d'ailleurs à ``Inconnu``.
Accepter cette fiche publierait « Construction / BTP » sur une organisation de
santé, à partir de son seul nom : précisément ce que le contrat interdit.

D'où la règle de ce module : **une fiche n'est jamais retenue sur la seule
concordance de nom.** Il faut une corroboration indépendante, déjà sourcée
dans Cyberwatch, à l'échelle de la commune ou d'un département d'outre-mer.
« France métropolitaine » couvre 96 départements : une concordance à cette
échelle n'est pas une corroboration, c'est une tautologie — et c'est justement
celle que la fiche Qare satisfait. Conséquence assumée : le registre s'abstient
sur la plupart des cas métropolitains.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import urlencode

from . import config
from .normalize import searchable
from .organisation_activity import (
    EXTERNAL_IDENTITY_AMBIGUOUS_REGISTRY,
    EXTERNAL_IDENTITY_UNVERIFIED,
    EXTERNAL_NAF_NOT_MAPPABLE,
    EXTERNAL_REGISTRY_UNREADABLE,
    NAF_BLOCKED,
    REGISTRY_ACTIVE,
    REGISTRY_SOURCE,
    canonical_name_key,
    naf_division,
)

#: Départements dont le code identifie à lui seul un territoire de la
#: taxonomie Cyberwatch. Volontairement limité à l'outre-mer du périmètre : un
#: département métropolitain ne mène qu'à « France métropolitaine », qui ne
#: corrobore rien.
CORROBORATING_DEPARTMENTS = {
    "974": config.LOC_REUNION,
    "976": config.LOC_MAYOTTE,
    "971": config.LOC_GUADELOUPE,
}

#: Articles retirés avant comparaison de communes : « Le Tampon » et
#: « Tampon » désignent la même commune. « Saint » n'en est pas un — le retirer
#: ferait concorder Saint-Denis avec Saint-Pierre.
_ARTICLES = frozenset({"le", "la", "les", "l", "de", "du", "des", "d", "aux", "au"})

#: Deux résultats suffisent à trancher « unique » ou « ambigu » ; en demander
#: davantage ne changerait aucune décision et alourdirait la réponse.
REGISTRY_PAGE_SIZE = 5


@dataclass(frozen=True)
class RegistryRecord:
    siren: str
    nom_complet: str
    nom_raison_sociale: str
    sigle: str
    etat_administratif: str
    activite_principale: str
    commune: str
    departement: str

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(
            value for value in (self.nom_complet, self.nom_raison_sociale, self.sigle)
            if value.strip()
        )


def registry_query_url(organisation: str, base_url: str) -> str:
    """URL de requête. Le nom sert à *chercher*, jamais à conclure."""
    name = " ".join(str(organisation or "").split())
    if not name:
        return ""
    return f"{base_url}?{urlencode({'q': name, 'per_page': REGISTRY_PAGE_SIZE})}"


def _text(value: object) -> str:
    return "" if value is None else str(value).strip()


def parse(body: str) -> list[RegistryRecord] | None:
    """Fiches lisibles de la réponse, ou ``None`` si elle est inexploitable."""
    try:
        payload = json.loads(str(body or ""))
    except (ValueError, TypeError):
        return None
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        return None
    records: list[RegistryRecord] = []
    for entry in payload["results"]:
        if not isinstance(entry, dict):
            continue
        raw_siege = entry.get("siege")
        siege: dict = raw_siege if isinstance(raw_siege, dict) else {}
        records.append(RegistryRecord(
            siren=_text(entry.get("siren")),
            nom_complet=_text(entry.get("nom_complet")),
            nom_raison_sociale=_text(entry.get("nom_raison_sociale")),
            sigle=_text(entry.get("sigle")),
            etat_administratif=_text(entry.get("etat_administratif")),
            activite_principale=_text(entry.get("activite_principale")),
            commune=_text(siege.get("libelle_commune")) or _text(siege.get("commune")),
            departement=_text(siege.get("departement")),
        ))
    return records


def select(records: list[RegistryRecord] | None, organisation_key: str,
           ) -> tuple[RegistryRecord | None, str]:
    """Fiche unique, active, dont un des noms porte la clé canonique attendue.

    Deux homonymes actifs ne sont pas un choix à faire : c'est une abstention.
    Le registre est ici l'outil qui **détecte** l'homonymie, pas celui qui la
    tranche.
    """
    if records is None:
        return None, EXTERNAL_REGISTRY_UNREADABLE
    matches = [
        record for record in records
        if record.etat_administratif == REGISTRY_ACTIVE
        and record.siren.strip()
        and record.activite_principale.strip()
        and any(canonical_name_key(name) == organisation_key for name in record.names)
    ]
    if not matches:
        return None, EXTERNAL_IDENTITY_UNVERIFIED
    if len({record.siren for record in matches}) > 1:
        return None, EXTERNAL_IDENTITY_AMBIGUOUS_REGISTRY
    return matches[0], ""


def _significant(value: str) -> set[str]:
    tokens = {token for token in searchable(value).split() if token not in _ARTICLES}
    return tokens if any(len(token) >= 4 for token in tokens) else set()


def commune_matches(fine_location: str, commune: str) -> bool:
    """Concordance de commune, par inclusion d'un jeu de jetons dans l'autre.

    ``Fine_Location`` porte parfois un quartier et sa commune
    (« Sainte-Clotilde / Saint-Denis ») : l'inclusion dans un sens ou dans
    l'autre couvre les deux formes sans accepter deux communes distinctes qui
    partagent seulement « Saint ».
    """
    left, right = _significant(fine_location), _significant(commune)
    if not left or not right:
        return False
    return left <= right or right <= left


def geographic_rejection(record: RegistryRecord, location: str,
                         fine_location: str) -> str:
    """Corroboration indépendante, à l'échelle commune ou département d'outre-mer.

    Aucune autre échelle n'est admise. En particulier ni ``France
    métropolitaine`` ni ``Inconnu`` ne corroborent quoi que ce soit : ce sont
    les deux valeurs que porte la majorité du corpus, et les accepter
    reviendrait à valider n'importe quelle fiche homonyme.
    """
    if commune_matches(fine_location, record.commune):
        return ""
    territory = CORROBORATING_DEPARTMENTS.get(record.departement.strip())
    if territory and territory == str(location or "").strip():
        return ""
    return EXTERNAL_IDENTITY_UNVERIFIED


def activity_label(record: RegistryRecord) -> tuple[str, str]:
    """Libellé officiel de la division NAF, ou motif d'abstention.

    Le libellé vient de ``data/naf_divisions.csv`` — la nomenclature INSEE —
    et non d'une reformulation : le code est littéralement dans la réponse
    téléchargée, le libellé est sa traduction officielle. Une division dont le
    verdict déterministe est mesuré faux, ou qui ne dit rien du métier réel
    (« Activités des sièges sociaux » décrit une coquille de holding), est
    marquée ``BLOCKED`` et fait abstenir le provider.
    """
    division = naf_division(record.activite_principale)
    if division is None or division.status == NAF_BLOCKED:
        return "", EXTERNAL_NAF_NOT_MAPPABLE
    return division.label, ""


def structured_quote(record: RegistryRecord) -> str:
    """Fragment JSON canonique de la fiche : la citation de la preuve structurée.

    Trié et compact, donc reproductible d'un run à l'autre. Il porte le nom, le
    SIREN, l'état administratif, le code d'activité, le siège et le marqueur de
    source qui sert de discriminant à ``organisation_activity.structured_proof``.

    Les clés du siège sont **aplaties** avec un souligné, et ce n'est pas un
    détail de style : mesuré, un siège imbriqué produit les jetons isolés
    ``commune`` et ``departement``, qui sont deux motifs du lexique
    ``SECTOR_ADMIN``. La citation classait alors « Administration /
    Collectivité » — un secteur déduit d'un **nom de champ**, que
    ``_decision_from_facts`` aurait publié via ``ACTIVITY_EVIDENCE_RULE``.
    Souligné compris, ``searchable`` garde ``siege_commune`` en un seul jeton,
    qu'aucun motif ne reconnaît. Le risque résiduel — une raison sociale ou une
    commune qui contient un mot du lexique — reste attrapé par
    ``evidence_sector_rejection``, appliquée à la citation entière.
    """
    payload = {
        "activite_principale": record.activite_principale,
        "etat_administratif": record.etat_administratif,
        "nom_complet": record.nom_complet,
        "siege_commune": record.commune,
        "siege_departement": record.departement,
        "siren": record.siren,
        "source": REGISTRY_SOURCE,
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
