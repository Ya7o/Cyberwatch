"""Modèle de statuts d'exécution.

Refonte du §5 de la méthodologie, qui mélangeait deux questions distinctes dans
un seul mot. Le modèle sépare désormais trois informations orthogonales :

  1. `Status`   — le protocole a-t-il abouti ?      OK / PARTIAL / FAIL / SKIPPED
  2. `Coverage` — quelle part du protocole a tourné ?          entier 0 à 100
  3. `Reason`   — pourquoi, en clair et en code machine.

Conséquence directe : un `Items_collected = 0` n'est un vrai zéro que si le
statut est `OK`. Partout ailleurs, zéro veut dire « on ne sait pas ».

Correspondance avec l'ancien vocabulaire :
    EMPTY   -> OK avec Items_collected = 0   (un zéro vérifié, pas une anomalie)
    NOT_RUN -> SKIPPED                       (hors périmètre, pas une erreur)
    PARTIAL -> PARTIAL + Coverage chiffrée   (« 68 % » et non « partiel »)
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import config

# --------------------------------------------------------------------------
# Statut d'une source pour un run
# --------------------------------------------------------------------------

OK = "OK"
PARTIAL = "PARTIAL"
FAIL = "FAIL"
SKIPPED = "SKIPPED"

#: Ordre de sévérité croissante, utilisé pour trier et agréger.
STATUS_SEVERITY = {OK: 0, SKIPPED: 1, PARTIAL: 2, FAIL: 3}

STATUS_LABELS = {
    OK: "Protocole exécuté intégralement",
    PARTIAL: "Protocole exécuté partiellement",
    FAIL: "Énumération impossible",
    SKIPPED: "Hors périmètre de ce run",
}

# --------------------------------------------------------------------------
# Codes de raison — machine + phrase française associée
# --------------------------------------------------------------------------

REASON_OK = "OK"
REASON_NO_FEED = "NO_FEED_FOUND"
REASON_NO_DATE = "NO_DATE_FOUND"
REASON_HTTP_403 = "HTTP_403"
REASON_HTTP_404 = "HTTP_404"
REASON_HTTP_429 = "HTTP_429"
REASON_HTTP_ERROR = "HTTP_ERROR"
REASON_TIMEOUT = "TIMEOUT"
REASON_PAGINATION = "PAGINATION_BROKEN"
REASON_ROBOTS = "ROBOTS_DISALLOW"
REASON_BUDGET_SOURCE = "SOURCE_BUDGET_REACHED"
REASON_BUDGET_RUN = "RUN_BUDGET_REACHED"
REASON_LAYER_NOT_SCHEDULED = "LAYER_NOT_SCHEDULED"
REASON_SOURCE_INACTIVE = "SOURCE_INACTIVE"
REASON_PARSE_ERROR = "PARSE_ERROR"
REASON_NO_RESULT = "NO_RESULT"
REASON_INCOMPLETE = "INCOMPLETE"

REASON_TEXTS = {
    REASON_OK: "Protocole complet, test de succès satisfait.",
    REASON_NO_FEED: "Aucun format exploitable trouvé (ni API WordPress, ni flux, ni JSON-LD).",
    REASON_NO_DATE: "Les entrées ont été trouvées mais aucune date exploitable n'a pu être lue.",
    REASON_HTTP_403: "Accès refusé par le site (HTTP 403).",
    REASON_HTTP_404: "Page introuvable (HTTP 404) : l'URL de départ a probablement changé.",
    REASON_HTTP_429: "Débit limité par le service (HTTP 429) : collecte interrompue avant la fin.",
    REASON_HTTP_ERROR: "Erreur HTTP empêchant la lecture de la source.",
    REASON_TIMEOUT: "Délai d'attente dépassé.",
    REASON_PAGINATION: "Pagination incohérente : impossible de garantir qu'aucune page n'a été sautée.",
    REASON_ROBOTS: "Chemin interdit par le robots.txt du site : source volontairement non interrogée.",
    REASON_BUDGET_SOURCE: "Plafond de la source atteint (requêtes, pages ou durée).",
    REASON_BUDGET_RUN: "Budget global du run atteint : la source n'a pas pu être terminée.",
    REASON_LAYER_NOT_SCHEDULED: "Couche non planifiée pour ce run (balayage hebdomadaire).",
    REASON_SOURCE_INACTIVE: "Source désactivée dans le référentiel SOURCES.",
    REASON_PARSE_ERROR: "Contenu récupéré mais illisible.",
    REASON_NO_RESULT: (
        "Aucune unité du protocole n'a abouti : la source n'a rien renvoyé "
        "d'exploitable, sans que la cause ait pu être qualifiée."
    ),
    REASON_INCOMPLETE: (
        "Protocole partiellement exécuté : une partie seulement des unités "
        "prévues a abouti. Le détail figure dans le commentaire de la source."
    ),
}


def reason_text(code: str) -> str:
    """Phrase française associée à un code de raison."""
    return REASON_TEXTS.get(code, code)


# --------------------------------------------------------------------------
# Statut global d'un run
# --------------------------------------------------------------------------

HEALTHY = "HEALTHY"
DEGRADED = "DEGRADED"
BROKEN = "BROKEN"

RUN_STATUS_LABELS = {
    HEALTHY: "Toutes les sources planifiées ont abouti.",
    DEGRADED: "Base utilisable, mais certaines sources sont incomplètes ou en échec.",
    BROKEN: "Une source centrale est en échec : ne pas conclure sur les tendances.",
}

#: En dessous de ce score, le run est déclaré BROKEN quelle que soit la couche.
BROKEN_SCORE_THRESHOLD = 50


@dataclass
class SourceOutcome:
    """Résultat d'une source pour un run — une ligne de `RUN_SOURCES`."""

    source_id: str
    layer: str
    status: str = OK
    coverage: int = 100
    reason_code: str = REASON_OK
    units_done: int = 0
    units_expected: int = 0
    calls: int = 0
    items_seen: int = 0
    items_collected: int = 0
    new_items: int = 0
    latest_item_date: str = ""
    access_method: str = ""
    duration_seconds: float = 0.0
    comment: str = ""

    @property
    def reason(self) -> str:
        return reason_text(self.reason_code)

    @property
    def zero_is_trusted(self) -> bool:
        """Un zéro n'a de sens que si le protocole est allé au bout."""
        return self.status == OK and self.items_collected == 0

    @property
    def counts_towards_health(self) -> bool:
        """Les sources hors périmètre ne pénalisent pas le score."""
        return self.status != SKIPPED


def compute_coverage(units_done: int, units_expected: int) -> int:
    """Couverture en pourcentage entier, bornée à [0, 100].

    Une source sans unité attendue (par exemple une API renvoyant tout d'un
    bloc) est considérée comme intégralement couverte dès lors qu'elle a
    abouti.
    """
    if units_expected <= 0:
        return 100
    ratio = (units_done / units_expected) * 100
    return max(0, min(100, int(round(ratio))))


def resolve_status(
    units_done: int,
    units_expected: int,
    reason_code: str = REASON_OK,
) -> tuple[str, int]:
    """Déduit le couple (statut, couverture) d'une collecte terminée.

    Le statut n'est `OK` que si toutes les unités attendues ont été traitées :
    c'est la traduction littérale du `Success_test` de la méthode.
    """
    coverage = compute_coverage(units_done, units_expected)
    if reason_code in (REASON_LAYER_NOT_SCHEDULED, REASON_SOURCE_INACTIVE, REASON_ROBOTS):
        return SKIPPED, 0
    if coverage >= 100 and reason_code == REASON_OK:
        return OK, 100
    if units_done <= 0:
        return FAIL, 0
    return PARTIAL, coverage


def health_score(outcomes: list[SourceOutcome]) -> int:
    """Score 0–100 : moyenne des couvertures pondérée par couche.

    Les sources `SKIPPED` sont exclues du calcul — ne pas avoir interrogé une
    couche non planifiée n'est pas un défaut de couverture.
    """
    total_weight = 0
    weighted = 0
    for outcome in outcomes:
        if not outcome.counts_towards_health:
            continue
        weight = config.LAYER_WEIGHTS.get(outcome.layer, 1)
        if weight <= 0:
            continue
        total_weight += weight
        weighted += weight * outcome.coverage
    if total_weight == 0:
        return 0
    return int(round(weighted / total_weight))


def overall_status(outcomes: list[SourceOutcome]) -> str:
    """Statut global du run selon les trois niveaux motivés du plan."""
    considered = [o for o in outcomes if o.counts_towards_health]
    if not considered:
        return BROKEN

    core_failed = any(
        o.layer == config.LAYER_CORE and o.status == FAIL for o in considered
    )
    if core_failed:
        return BROKEN
    if health_score(outcomes) < BROKEN_SCORE_THRESHOLD:
        return BROKEN
    if any(o.status in (PARTIAL, FAIL) for o in considered):
        return DEGRADED
    return HEALTHY


def blind_spots(outcomes: list[SourceOutcome]) -> list[dict]:
    """Angles morts du run : ce qui n'a pas été couvert, et pourquoi.

    Alimente le bandeau du dashboard qui rend visible la règle
    « transparence des trous de couverture > faux zéro » (§31).
    """
    spots = []
    for outcome in sorted(
        outcomes, key=lambda o: (-STATUS_SEVERITY[o.status], o.source_id)
    ):
        if outcome.status in (PARTIAL, FAIL):
            spots.append(
                {
                    "source_id": outcome.source_id,
                    "layer": outcome.layer,
                    "status": outcome.status,
                    "coverage": outcome.coverage,
                    "reason_code": outcome.reason_code,
                    "reason": outcome.reason,
                    "detail": (
                        f"{outcome.units_done}/{outcome.units_expected} unités traitées"
                        if outcome.units_expected
                        else ""
                    ),
                }
            )
    return spots


def status_counts(outcomes: list[SourceOutcome]) -> dict[str, int]:
    """Répartition des sources par statut, pour `RUN_LOG` et le dashboard."""
    counts = {OK: 0, PARTIAL: 0, FAIL: 0, SKIPPED: 0}
    for outcome in outcomes:
        counts[outcome.status] = counts.get(outcome.status, 0) + 1
    return counts
