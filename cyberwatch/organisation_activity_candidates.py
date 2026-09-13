"""Découverte de candidats : *où* regarder, jamais *quoi conclure*.

Ce module est pur. Il ne télécharge rien, ne juge rien et ne produit aucune
citation : il rend des URL à essayer, dans un ordre explicite. Toute la
responsabilité de la preuve reste à Cyberwatch, en aval.

Deux providers déterministes sont livrés, dans cet ordre :

1. ``owned_url`` — des URL que Cyberwatch **possède déjà** : le
   ``Victim_Website`` extrait par une autre source pour la même identité
   canonique, et l'URL de validation d'une ligne de référentiel qui ne donne
   pas déjà le secteur. Leur provenance est acquise, donc c'est le premier
   endroit à regarder, et il ne coûte aucune requête de recherche.
2. ``entreprises_registry`` — le registre public, interrogé par nom. Le nom
   sert à *chercher* ; c'est la vérification en aval qui décide, et elle exige
   une corroboration indépendante (voir
   :mod:`cyberwatch.organisation_activity_registry`).

Aucun moteur de recherche généraliste n'est implémenté, ni simulé. Un tel
provider s'injecte : il suffit qu'il rende des :class:`ActivityCandidate`.
"""

from __future__ import annotations

from .model import Item
from .org_identity import effective_organisation_key
from .normalize import organisation_key
from .organisation_activity import (
    PROVIDER_OWNED_URL,
    PROVIDER_REGISTRY,
    SOURCE_OFFICIAL_SITE,
    SOURCE_PUBLIC_REGISTRY,
    ActivityCandidate,
    SourcePolicy,
)
from .organisation_activity_registry import registry_query_url


def _normalised(url: str) -> str:
    """URL exploitable, ou chaîne vide. Un hôte nu reçoit un schéma https."""
    value = str(url or "").strip()
    if not value or " " in value:
        return ""
    if value.startswith(("http://", "https://")):
        return value
    if value.startswith("//"):
        return f"https:{value}"
    return f"https://{value}" if "." in value.split("/")[0] else ""


def owned_website_urls(organisation_key_value: str, items: list[Item],
                       facts: list[dict]) -> list[str]:
    """``Victim_Website`` observés pour cette identité canonique, dédupliqués.

    La provenance vient d'une autre source du référentiel, qui a extrait ce
    site pour la même organisation : c'est une URL que le projet possède, pas
    une URL devinée depuis un nom.
    """
    keys = {
        item.Item_ID: effective_organisation_key(item.Organisation_Raw, item.Organisation_Key)
        for item in items
    }
    found: list[str] = []
    for fact in facts:
        if keys.get(str(fact.get("Item_ID") or "")) != organisation_key_value:
            continue
        url = _normalised(str(fact.get("Victim_Website") or ""))
        if url and url not in found:
            found.append(url)
    return found


def reference_url(organisation: str, organisation_key_value: str,
                  reference: dict) -> str:
    """URL de validation d'une ligne de référentiel qui ne donne pas le secteur.

    Si le référentiel porte déjà un secteur, il tranche bien avant le niveau 2
    (``REFERENCE_EXACT``, confiance 0.90) et aller lire sa page ne servirait à
    rien. Une ligne qui ne renseigne qu'un territoire, en revanche, laisse le
    secteur ouvert tout en portant une URL dont la provenance est validée.
    """
    for key in (organisation_key(organisation), organisation_key_value):
        entry = (reference or {}).get(key)
        if entry is None:
            continue
        if str(getattr(entry, "sector", "") or "").strip():
            return ""
        return _normalised(str(getattr(entry, "validation_url", "") or ""))
    return ""


def discover(organisation: str, organisation_key_value: str, items: list[Item],
             facts: list[dict], reference: dict,
             policy: SourcePolicy) -> list[ActivityCandidate]:
    """Candidats autorisés par la policy, ordonnés par rang croissant.

    L'ordre est celui du cahier des charges : URL déjà connue, puis registre
    public. Le plafond par organisation s'applique **après** l'ordonnancement,
    pour qu'il tronque les sources les moins fiables et jamais les meilleures.
    """
    candidates: list[ActivityCandidate] = []
    if not policy.provider_rejection(PROVIDER_OWNED_URL):
        urls = owned_website_urls(organisation_key_value, items, facts)
        extra = reference_url(organisation, organisation_key_value, reference)
        if extra and extra not in urls:
            urls.append(extra)
        candidates.extend(
            ActivityCandidate(url=url, provider=PROVIDER_OWNED_URL,
                              source_type=SOURCE_OFFICIAL_SITE, rank=0)
            for url in urls
        )
    if not policy.provider_rejection(PROVIDER_REGISTRY):
        query = registry_query_url(organisation, policy.registry_url)
        if query:
            candidates.append(ActivityCandidate(
                url=query, provider=PROVIDER_REGISTRY,
                source_type=SOURCE_PUBLIC_REGISTRY, rank=1))
    ordered = sorted(candidates, key=lambda item: (item.rank, item.source_type, item.url))
    return ordered[:max(0, policy.budgets.max_candidates)]
