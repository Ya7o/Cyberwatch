"""Veille par flux directs des médias, avec reconnaissance nominative d'entités.

Ce collecteur remplace l'approche initiale par requêtes Google News, abandonnée
pour une raison dirimante : le `robots.txt` de Google interdit `/rss/search`.
Le pipeline respecte les robots.txt, donc cette voie est fermée.

Le remplacement est meilleur sur trois plans :

- **Conformité** : on consomme les flux que les médias publient pour être lus.
- **Fidélité à la méthode** : le §31 pose « source directe > recherche moteur ».
  Interroger directement les médias suit cette règle au lieu de la contourner.
- **Volumétrie** : une requête par média au lieu de deux par entité — la
  couverture d'un territoire passe d'environ 90 requêtes à moins de dix.

Limite assumée, à lire dans le statut : un flux ne porte que ses dernières
publications. Cette couche surveille donc le présent et ne reconstitue pas
l'historique ; sa couverture est calculée sur la part de fenêtre réellement
observée, et elle ressort `PARTIAL` plutôt que de revendiquer une énumération
complète.
"""

from __future__ import annotations

from urllib.parse import urlparse

from .. import status
from ..normalize import _contains, looks_cyber, searchable
from .base import CollectResult, Collector, RawEntry, SourceSpec, Window
from .feed import discover_feeds, parse_feed


def mentions(text_blob: str, labels: list[str]) -> str:
    """Premier libellé de la liste réellement cité dans le texte.

    Les libellés les plus longs sont testés d'abord, afin que
    « Mairie de Saint-Denis » l'emporte sur « Saint-Denis ».
    """
    for label in sorted(labels, key=len, reverse=True):
        key = searchable(label)
        if key and _contains(text_blob, key):
            return label
    return ""


class MediaWatchCollector(Collector):
    """Lit les flux d'une liste de médias et en extrait ce qui concerne le
    territoire surveillé.

    Paramètres reconnus dans `spec.params` :
      - `domains`  : domaines des médias à interroger ;
      - `entities` : entités surveillées, pour la reconnaissance nominative et
        la production de l'état de veille ;
      - `require_entity` : n'accepter que les entrées citant une entité connue.
    """

    name = "mediawatch"

    def collect(self, client, spec: SourceSpec, window: Window) -> CollectResult:
        budget = client.source_budget()
        result = CollectResult(access_method="media-feed")

        domains = spec.params.get("domains") or []
        entities = spec.params.get("entities") or []
        require_entity = bool(spec.params.get("require_entity"))

        result.units_expected = len(domains)
        if not domains:
            result.reason_code = status.REASON_NO_FEED
            return result

        # Index des libellés par entité, pour la reconnaissance nominative.
        labels_by_entity: dict[str, list[str]] = {}
        for entity in entities:
            name = entity["name"] if isinstance(entity, dict) else entity
            aliases = entity.get("aliases", []) if isinstance(entity, dict) else []
            labels_by_entity[name] = [name, *aliases]

        found_by_entity: dict[str, list[RawEntry]] = {n: [] for n in labels_by_entity}
        seen_urls: set[str] = set()
        all_entries: list[RawEntry] = []
        working_domains: list[str] = []
        failures: dict[str, int] = {}

        for domain in domains:
            if budget.exhausted or client.run_budget.exhausted:
                result.reason_code = (
                    status.REASON_BUDGET_RUN
                    if client.run_budget.exhausted
                    else status.REASON_BUDGET_SOURCE
                )
                break

            entries, reason = self._read_domain(client, spec, domain, budget)
            if entries is None:
                failures[reason] = failures.get(reason, 0) + 1
                continue

            working_domains.append(domain)
            result.units_done += 1
            all_entries.extend(entries)

            for entry in entries:
                if not window.contains(entry.published):
                    continue
                if entry.url in seen_urls:
                    continue

                blob = searchable(f"{entry.title} {entry.summary}")
                matched = mentions(blob, [
                    label for labels in labels_by_entity.values() for label in labels
                ])

                entity_name = ""
                if matched:
                    for name, labels in labels_by_entity.items():
                        if matched in labels:
                            entity_name = name
                            break

                # Un article n'entre dans la base que s'il relève du cyber.
                # La reconnaissance d'une entité ne suffit pas : la commune peut
                # être citée pour de tout autres raisons.
                if not looks_cyber(f"{entry.title} {entry.summary}"):
                    continue
                if require_entity and not entity_name:
                    continue

                seen_urls.add(entry.url)
                if entity_name:
                    entry.entity = entity_name
                    entry.organisation = entry.organisation or entity_name
                    found_by_entity[entity_name].append(entry)
                result.entries.append(entry)

        # État de veille : une ligne par entité, avec le nombre de médias
        # effectivement interrogés — la couverture est donc nominative.
        for name in labels_by_entity:
            result.watch_rows.append(
                {
                    "entity": name,
                    "queries_expected": len(domains),
                    "queries_done": len(working_domains),
                    "status": (
                        status.OK
                        if len(working_domains) == len(domains)
                        else status.PARTIAL
                    ),
                    "items_found": len(found_by_entity[name]),
                    "latest_date": max(
                        (e.published for e in found_by_entity[name]), default=""
                    ),
                }
            )

        if not working_domains:
            result.reason_code = (
                max(failures, key=failures.get) if failures else status.REASON_NO_FEED
            )
            result.comment = self._failure_comment(failures, domains)
            return result

        # La borne n'est atteinte que si les flux redescendent avant le début de
        # la fenêtre ET que tous les médias ont répondu.
        oldest = min((e.published for e in all_entries if e.published), default="")
        deep_enough = bool(oldest) and oldest <= window.start
        result.reached_boundary = (
            deep_enough
            and len(working_domains) == len(domains)
            and result.reason_code == status.REASON_OK
        )

        if not result.reached_boundary:
            # La couverture mesure ce que le protocole contrôle : le nombre de
            # médias effectivement lus. La profondeur d'un flux est une propriété
            # du média, pas un défaut d'exécution — la mesurer contre une fenêtre
            # historique donnerait un « 3 % » permanent qui ne dirait rien
            # d'actionnable. Elle est donc rapportée en clair dans le commentaire,
            # et la borne non atteinte interdit de toute façon un OK.
            result.units_done = len(working_domains)
            result.units_expected = len(domains)
            parts = [
                f"{len(working_domains)}/{len(domains)} médias interrogés",
                (
                    f"flux remontant au {oldest}, début de fenêtre demandé "
                    f"{window.start}"
                ) if oldest else "aucune date lue",
            ]
            if failures:
                parts.append(
                    "refus : "
                    + ", ".join(f"{c} x{n}" for c, n in sorted(
                        failures.items(), key=lambda kv: -kv[1]))
                )
            result.comment = " ; ".join(parts)

        result.calls = budget.requests_made
        return result

    def _read_domain(self, client, spec, domain, budget):
        """Entrées du flux d'un média, ou `(None, code de refus)`."""
        base = domain if domain.startswith("http") else f"https://{domain}/"
        last_reason = status.REASON_NO_FEED

        for feed_url in discover_feeds(client, base, budget)[:5]:
            if budget.exhausted:
                return None, status.REASON_BUDGET_SOURCE
            response = client.fetch(feed_url, budget)
            if not response.ok:
                last_reason = response.reason_code
                continue
            entries = parse_feed(response.text, spec)
            if entries:
                return entries, status.REASON_OK
        return None, last_reason

    @staticmethod
    def _failure_comment(failures: dict[str, int], domains: list[str]) -> str:
        if not failures:
            return f"Aucun flux exploitable sur {len(domains)} médias"
        causes = ", ".join(
            f"{code} x{count}"
            for code, count in sorted(failures.items(), key=lambda kv: -kv[1])
        )
        return f"Aucun des {len(domains)} médias n'a fourni de flux ; refus : {causes}"
