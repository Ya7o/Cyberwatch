"""Chaîne d'accès automatique : WordPress → flux → JSON-LD.

C'est la réponse au problème central du projet : les structures HTML des sites
sources ne sont pas connues à l'avance et changent avec le temps. Plutôt que
d'écrire un parser sur mesure par site, on essaie successivement trois formats
standardisés et l'on **enregistre celui qui a fonctionné** dans `RUN_SOURCES`.

Le dashboard affiche cette méthode d'accès : on sait donc à tout moment par
quel chemin chaque source est réellement lue.
"""

from __future__ import annotations

from .. import status
from .base import CollectResult, Collector, SourceSpec, Window
from .feed import FeedCollector
from .jsonld import JsonLdCollector
from .wordpress import WordPressCollector


class AutodetectCollector(Collector):
    """Essaie chaque collecteur générique et retient le meilleur résultat.

    « Meilleur » signifie : le premier qui atteint la borne de date. À défaut,
    celui qui a ramené le plus d'entrées — un résultat partiel exploitable vaut
    mieux qu'un échec, à condition d'être déclaré `PARTIAL`.
    """

    name = "autodetect"

    #: Ordre de préférence, du plus fiable au plus approximatif.
    CHAIN = [WordPressCollector, FeedCollector, JsonLdCollector]

    def collect(self, client, spec: SourceSpec, window: Window) -> CollectResult:
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
