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
NOT_COVERED = "NOT_COVERED"

#: Ordre de sévérité croissante, utilisé pour trier et agréger.
STATUS_SEVERITY = {OK: 0, SKIPPED: 1, NOT_COVERED: 2, PARTIAL: 3, FAIL: 4}

STATUS_LABELS = {
    OK: "Protocole exécuté intégralement",
    PARTIAL: "Protocole exécuté partiellement",
    FAIL: "Énumération impossible",
    SKIPPED: "Hors périmètre de ce run",
    NOT_COVERED: "Source attendue mais non activée",
}

# --------------------------------------------------------------------------
# Couverture historique — axe orthogonal à Status/Coverage (§stabilisation
# pré-release). Un protocole peut aboutir (`Status=OK`) sans que l'historique
# collecté couvre la fenêtre demandée depuis son début : c'est le cas d'un
# flux sans pagination (`feed_has_no_pagination`), dont la profondeur réelle
# recule avec le temps. Mélanger cette information dans `Status`/`Reason`
# reproduirait exactement le défaut que ce module corrige déjà pour
# Status/Coverage/Reason (cf. docstring ci-dessus) : ne jamais surcharger un
# champ avec deux questions différentes.
# --------------------------------------------------------------------------

#: L'historique collecté remonte réellement jusqu'au début de la fenêtre demandée.
HISTORY_COMPLETE = "COMPLETE"
#: `Status=OK` malgré une profondeur réelle plus courte que la fenêtre demandée
#: (protocole propre à la source, ex. `feed_has_no_pagination`, qui accepte la
#: borne sans jamais la reconsidérer comme un incident de collecte).
HISTORY_TRUNCATED = "TRUNCATED"
#: Aucune date fiable pour juger la profondeur réelle (collecteur qui ne
#: renseigne pas `oldest_available_date`, ou protocole non `OK`).
HISTORY_UNKNOWN = "UNKNOWN"

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
# Statut des sources candidates (non activées) — pourquoi elles ne tournent
# pas, sans les confondre avec un échec de collecte (§13/§16 du Lot 1
# Mayotte : un titre arrêté ou incertain n'est pas un échec de couverture).
# --------------------------------------------------------------------------

CANDIDATE_BLIND_SPOT = "BLIND_SPOT"
CANDIDATE_TO_CONFIRM = "TO_CONFIRM"
CANDIDATE_CEASED = "CEASED"

CANDIDATE_STATUS_LABELS = {
    CANDIDATE_BLIND_SPOT: "Angle mort technique",
    CANDIDATE_TO_CONFIRM: "Activité à confirmer",
    CANDIDATE_CEASED: "Titre arrêté",
}


# --------------------------------------------------------------------------
# Statut global d'un run
# --------------------------------------------------------------------------

BROKEN = "BROKEN"

RUN_STATUS_LABELS = {
    OK: "Toutes les sources actives ont abouti.",
    BROKEN: "Au moins une source active n'a pas abouti.",
}


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
    items_in_window: int = 0
    items_collected: int = 0
    new_items: int = 0
    latest_item_date: str = ""
    latest_item_org: str = ""
    access_method: str = ""
    duration_seconds: float = 0.0
    comment: str = ""
    history_status: str = HISTORY_UNKNOWN
    oldest_available_date: str = ""
    collect_duration_seconds: float = 0.0
    processing_duration_seconds: float = 0.0
    source_facts_llm_duration_seconds: float = 0.0
    source_facts_llm_calls: int = 0
    source_facts_llm_cost_usd: float = 0.0

    @property
    def reason(self) -> str:
        return reason_text(self.reason_code)

    @property
    def zero_is_trusted(self) -> bool:
        """Un zéro n'a de sens que si le protocole est allé au bout."""
        return self.status == OK and self.items_collected == 0


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


def overall_status(outcomes: list[SourceOutcome]) -> str:
    """Un run n'est OK que si toutes ses sources actives sont OK."""
    return OK if outcomes and all(o.status == OK for o in outcomes) else BROKEN


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
