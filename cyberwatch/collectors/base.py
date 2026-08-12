"""Interface commune des collecteurs.

Un collecteur ne connaît ni la base, ni la déduplication : il énumère des
entrées brutes et rend compte de ce qu'il a réellement pu parcourir. C'est le
runner qui traduit ce compte rendu en statut.

Notion centrale : **la borne de date est-elle atteinte ?** C'est la traduction
littérale du `Success_test` de la méthode — une source n'est `OK` que si elle a
été remontée jusqu'au début de la fenêtre demandée, pas seulement si elle a
répondu HTTP 200 (§5).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .. import status
from ..normalize import date_or_empty


@dataclass
class Window:
    """Fenêtre de collecte, bornes incluses, au format `AAAA-MM-JJ`."""

    start: str
    end: str

    def contains(self, date: str) -> bool:
        if not date:
            return False
        return self.start <= date <= self.end

    def is_before_start(self, date: str) -> bool:
        return bool(date) and date < self.start

    @property
    def days(self) -> int:
        begin = date_or_empty(self.start)
        finish = date_or_empty(self.end)
        if begin is None or finish is None:
            return 0
        return max(1, (finish - begin).days + 1)


@dataclass
class RawEntry:
    """Entrée brute telle que lue chez la source, avant toute normalisation."""

    title: str = ""
    url: str = ""
    published: str = ""
    summary: str = ""
    event_date: str = ""
    organisation: str = ""
    sector: str = ""
    location: str = ""
    threat: str = ""
    entity: str = ""


@dataclass
class SourceSpec:
    """Déclaration d'une source dans le référentiel `SOURCES` (§4.3)."""

    source_id: str
    layer: str
    zone: str
    start_url: str = ""
    collector: str = "autodetect"
    active: bool = True
    default_threat: str = ""
    location_rule: str = ""
    protocol: str = ""
    success_test: str = ""
    notes: str = ""
    params: dict = field(default_factory=dict)


@dataclass
class CollectResult:
    """Compte rendu d'exécution d'un collecteur."""

    entries: list[RawEntry] = field(default_factory=list)
    reached_boundary: bool = False
    units_done: int = 0
    units_expected: int = 0
    calls: int = 0
    reason_code: str = status.REASON_OK
    access_method: str = ""
    comment: str = ""
    #: État de veille par entité, renseigné par les couches de surveillance
    #: nominative. Alimente `ENTITY_WATCH` et le focus Réunion / Mayotte.
    watch_rows: list[dict] = field(default_factory=list)

    def resolve(self) -> tuple[str, int]:
        """Traduit le compte rendu en couple (statut, couverture).

        Trois cas seulement, ce qui rend le statut lisible :
          - borne atteinte sans incident de parcours     -> `OK`, 100 %
          - parcours entamé mais interrompu              -> `PARTIAL`, couverture réelle
          - rien d'exploitable                           -> `FAIL`, 0 %

        Un `OK` avec zéro entrée est un **zéro vérifié**, pas une anomalie.
        """
        if self.reason_code in (
            status.REASON_ROBOTS,
            status.REASON_LAYER_NOT_SCHEDULED,
            status.REASON_SOURCE_INACTIVE,
        ):
            return status.SKIPPED, 0

        if self.reached_boundary and self.reason_code == status.REASON_OK:
            return status.OK, 100

        if self.units_done > 0 or self.entries:
            coverage = status.compute_coverage(
                self.units_done, self.units_expected or self.units_done
            )
            # Une borne non atteinte interdit de revendiquer 100 %.
            if not self.reached_boundary:
                coverage = min(coverage, 99)
            return status.PARTIAL, coverage

        return status.FAIL, 0


class Collector:
    """Classe de base. Un collecteur implémente `collect`."""

    name = "base"

    def collect(self, client, spec: SourceSpec, window: Window) -> CollectResult:
        raise NotImplementedError


def coverage_from_days(entries: list[RawEntry], window: Window) -> int:
    """Couverture estimée d'une source non paginable (flux RSS notamment).

    Un flux ne remonte que ses N dernières entrées. S'il ne redescend pas
    jusqu'au début de la fenêtre, la couverture vaut la part de la fenêtre
    réellement observée — une estimation honnête plutôt qu'un faux 100 %.
    """
    dates = sorted(e.published for e in entries if e.published)
    if not dates or window.days <= 0:
        return 0
    oldest = date_or_empty(dates[0])
    start = date_or_empty(window.start)
    end = date_or_empty(window.end)
    if oldest is None or start is None or end is None:
        return 0
    covered = (end - max(oldest, start)).days + 1
    return status.compute_coverage(max(0, covered), window.days)
