"""Détection conservatrice des doublons d'organisation à examiner.

Ce module ne modifie jamais les items et ne rapproche aucune identité : il
produit uniquement des candidats étayés par des indices reproductibles. La
menace et la catégorie de l'organisation ne servent pas de filtre d'identité :
deux sources peuvent qualifier différemment le même événement, et les victimes
institutionnelles doivent rester auditables comme les autres.
"""

from __future__ import annotations

from dataclasses import dataclass

from .model import Item
from .normalize import date_or_empty


@dataclass(frozen=True)
class DuplicateCandidate:
    """Deux items proches, mais volontairement non fusionnés."""

    short: Item
    long: Item
    days_apart: int
    reason_code: str = "DUPLICATE_CANDIDATE_NAME_CONTAINMENT"


def _contains_word_sequence(long_key: str, short_key: str) -> bool:
    long_words = long_key.split()
    short_words = short_key.split()
    if not short_words or len(short_words) >= len(long_words):
        return False
    width = len(short_words)
    return any(
        long_words[index:index + width] == short_words
        for index in range(len(long_words) - width + 1)
    )


def find_duplicate_candidates(items: list[Item], max_days: int = 3) -> list[DuplicateCandidate]:
    """Retourne des candidats d'audit sans jamais ordonner leur fusion.

    Critères strictement déterministes : sources distinctes, dates à moins de
    `max_days` et inclusion d'une séquence entière de mots d'organisation. La
    menace n'est pas un critère d'identité et aucun mot générique (agence,
    fédération, université, ville...) n'est exclu : ces cas doivent précisément
    rester visibles dans l'audit.
    """
    candidates: list[DuplicateCandidate] = []
    ordered = sorted(
        items,
        key=lambda item: (
            item.Published_Date,
            item.Source_ID,
            item.Item_ID,
            item.URL,
        ),
    )

    for index, left in enumerate(ordered):
        left_date = date_or_empty(left.best_date)
        if not left.Organisation_Key or not left_date:
            continue

        for right in ordered[index + 1:]:
            if left.Source_ID == right.Source_ID:
                continue

            right_date = date_or_empty(right.best_date)
            if not right.Organisation_Key or not right_date:
                continue

            days_apart = abs((left_date - right_date).days)
            if days_apart > max_days:
                continue

            short, long = sorted(
                (left, right),
                key=lambda item: (
                    len(item.Organisation_Key.split()),
                    len(item.Organisation_Key),
                    item.Organisation_Key,
                ),
            )
            if _contains_word_sequence(long.Organisation_Key, short.Organisation_Key):
                candidates.append(DuplicateCandidate(short, long, days_apart))

    return sorted(
        candidates,
        key=lambda candidate: (
            candidate.short.Organisation_Key,
            candidate.long.Organisation_Key,
            candidate.days_apart,
            candidate.short.Source_ID,
            candidate.long.Source_ID,
        ),
    )
