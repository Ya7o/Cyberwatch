"""Interface commune des collecteurs.

Un collecteur ne connaît ni la base, ni la déduplication : il énumère des
entrées brutes et rend compte de ce qu'il a réellement pu parcourir. C'est le
runner qui traduit ce compte rendu en statut.

Notion centrale : **la borne de date est-elle atteinte ?** C'est la traduction
littérale du `Success_test` de la méthode — une source n'est `OK` que si elle a
été remontée jusqu'au début de la fenêtre demandée, pas seulement si elle a
répondu HTTP 200 (§5).

Exception explicite : BonjourLaFuite possède en V0 un contrat fonctionnel
OK/FAIL propre à la source. Un collecteur peut donc fournir `status_override`
quand son protocole définit lui-même le statut sans couverture ni borne.
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
    #: Identifiant natif stable fourni par la source lorsqu'il existe. Il ne
    #: doit jamais être synthétisé à partir d'un nom, d'une date ou d'une URL.
    source_item_id: str = ""
    published: str = ""
    summary: str = ""
    #: Corps complet d'un article lorsque la source le demande explicitement.
    #: Il reste distinct de l'extrait (`summary`) afin de ne pas changer la
    #: sémantique des collecteurs qui ne l'utilisent pas.
    content: str = ""
    event_date: str = ""
    organisation: str = ""
    sector: str = ""
    #: Localisation **publiée par la source** (rubrique géographique, pays d'une
    #: API). Un collecteur ne doit jamais y recopier la règle fixe de la source :
    #: le runner l'applique lui-même au rang 3, après le territoire de l'entité
    #: reconnue. La préremplir ici la ferait passer au rang 1 et écraserait ce
    #: rang 2 — c'est ce qui maintenait Air Austral en « France métropolitaine ».
    location: str = ""
    threat: str = ""
    entity: str = ""
    #: Donnée déjà structurée transmise par un collecteur (JSON API, snapshot
    #: JSON) sans être aplatie dans `summary`/`content`. Rétrocompatible :
    #: absent des anciens appels positionnels, il vaut alors `{}`.
    source_metadata: dict = field(default_factory=dict)


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
    #: Statut imposé par un protocole propre à une source. `None` signifie que
    #: le modèle générique borne/couverture s'applique. En V0, seul
    #: BonjourLaFuite l'utilise afin de rester strictement sur OK/FAIL.
    status_override: str | None = None
    #: État de veille par entité, renseigné par les couches de surveillance
    #: nominative. Alimente `ENTITY_WATCH` et le focus Réunion / Mayotte.
    watch_rows: list[dict] = field(default_factory=list)
    #: Compteur structurel indépendant des entrées conservées dans la fenêtre.
    items_seen: int | None = None
    #: Sous-ensemble structurellement reconnu dans la fenêtre demandée. Cette
    #: mesure ne représente jamais une unité technique du protocole.
    items_in_window: int | None = None
    #: Date (AAAA-MM-JJ) de l'entrée la plus ancienne effectivement offerte
    #: par la source dans ce run, quand un collecteur peut la calculer.
    #: Distinct de `reached_boundary` : un flux peut être `OK` (borne
    #: acceptée via un protocole propre, ex. `feed_has_no_pagination`) tout en
    #: ayant une profondeur réelle plus courte que la fenêtre demandée — ce
    #: champ permet de le documenter sans reconsidérer `Status`/`Coverage`.
    oldest_available_date: str = ""

    def resolve(self) -> tuple[str, int]:
        """Traduit le compte rendu en couple (statut, couverture).

        Le chemin normal conserve trois cas :
          - borne atteinte sans incident de parcours     -> `OK`, 100 %
          - parcours entamé mais interrompu              -> `PARTIAL`, couverture réelle
          - rien d'exploitable                           -> `FAIL`, 0 %

        Un protocole source-spécifique peut fournir `status_override`. Dans ce
        cas, aucune borne, aucun score de santé et aucune couverture ne décide du
        statut ; la couverture retournée n'est qu'une valeur de compatibilité
        pour les consommateurs historiques du modèle.
        """
        if self.status_override is not None:
            if self.status_override == status.OK:
                return status.OK, 100
            return status.FAIL, 0

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
            self._ensure_reason(status.REASON_INCOMPLETE)
            return status.PARTIAL, coverage

        self._ensure_reason(status.REASON_NO_RESULT)
        return status.FAIL, 0

    def _ensure_reason(self, fallback: str) -> None:
        """Un statut dégradé ne doit jamais porter la raison « tout va bien ».

        Sans ce garde-fou, une source pouvait ressortir en `FAIL` accompagnée de
        « Protocole complet, test de succès satisfait » — un compte rendu qui se
        contredit lui-même et ne dit rien d'actionnable.

        Le repli diffère selon la sévérité : dire « rien d'exploitable » d'une
        source ayant abouti aux deux tiers serait tout aussi faux.
        """
        if self.reason_code == status.REASON_OK:
            self.reason_code = fallback


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
