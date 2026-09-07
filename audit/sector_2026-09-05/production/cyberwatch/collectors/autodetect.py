"""Chaîne d'accès automatique : cas dédiés puis WordPress → flux → JSON-LD.

Les sources génériques suivent la chaîne standardisée. Une source peut toutefois
avoir un contrat fonctionnel propre lorsque sa structure et son indicateur de
santé sont explicitement définis. BonjourLaFuite est le seul cas dédié de la V0 :
son statut dépend de la reconnaissance des blocs de timeline, pas de la borne de
la fenêtre.
"""

from __future__ import annotations

from .. import status
from .base import CollectResult, Collector, SourceSpec, Window
from .feed import FeedCollector
from .jsonld import JsonLdCollector
from .wordpress import WordPressCollector


class AutodetectCollector(Collector):
    """Route les cas dédiés, sinon essaie les collecteurs génériques.

    Pour les sources génériques, « meilleur » signifie : le premier chemin qui
    atteint la borne de date. À défaut, celui qui a ramené le plus d'entrées —
    un résultat partiel exploitable vaut mieux qu'un échec déclaré à tort OK.

    BonjourLaFuite ne passe jamais par cette logique de borne/couverture : le
    collecteur dédié implémente strictement son contrat OK/FAIL V0.
    """

    name = "autodetect"

    #: Ordre de préférence, du plus fiable au plus approximatif.
    CHAIN = [WordPressCollector, FeedCollector, JsonLdCollector]

    def collect(self, client, spec: SourceSpec, window: Window) -> CollectResult:
        if spec.source_id == "BONJOURLAFUITE":
            # Import local pour ne pas introduire de dépendance circulaire dans
            # le registre générique des collecteurs.
            from .bonjourlafuite import BonjourLaFuiteCollector

            return BonjourLaFuiteCollector().collect(client, spec, window)

        attempts: list[CollectResult] = []
        total_calls = 0

        for collector_class in self.CHAIN:
            collector = collector_class()
            try:
                result = collector.collect(client, spec, window)
            except Exception as exc:  # une source ne doit jamais casser le run
                result = CollectResult(
                    reason_code=status.REASON_PARSE_ERROR,
                    access_method=collector.name,
                    comment=f"{type(exc).__name__}: {exc}"[:200],
                )

            total_calls += result.calls
            result.calls = total_calls
            attempts.append(result)

            if result.reached_boundary:
                result.comment = (result.comment or "") or (
                    f"Accès retenu : {result.access_method}"
                )
                return result

            # Inutile d'insister si le site nous refuse l'accès.
            if result.reason_code in (status.REASON_ROBOTS, status.REASON_HTTP_403):
                return result

        # Aucun chemin n'a atteint la borne : on garde le plus fourni.
        best = max(attempts, key=lambda r: (len(r.entries), r.units_done))
        best.calls = total_calls
        if not best.entries and best.reason_code == status.REASON_OK:
            best.reason_code = status.REASON_NO_FEED
        if best.entries and not best.comment:
            best.comment = (
                f"Borne de date non atteinte via {best.access_method} : "
                "collecte déclarée partielle"
            )
        return best
