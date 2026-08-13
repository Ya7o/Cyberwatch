"""Détection conservative des doublons d'organisation à examiner.

Ce module ne modifie jamais les items et ne rapproche aucune identité : il
produit uniquement des candidats étayés par des indices reproductibles.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import config
from .model import Item
from .normalize import date_or_empty


GENERIC_ORGANISATION_WORDS = frozenset({
    "agence", "association", "centre", "clinique", "commune", "departement",
    "direction", "ecole", "federation", "groupe", "hopital", "mairie",
    "ministere", "office", "region", "service", "societe", "universite", "ville",
})


@dataclass(frozen=True)
class DuplicateCandidate:
    """Deux items proches, mais volontairement non fusionnés."""

    short: Item
    long: Item
    days_apart: int


def _contains_word_sequence(long_key: str, short_key: str) -> bool:
    long_words = long_key.split()
    short_words = short_key.split()
    if not short_words or len(short_words) >= len(long_words):
        return False
    width = len(short_words)
    return any(long_words[index:index + width] == short_words
               for index in range(len(long_words) - width + 1))


def _has_generic_word(key: str) -> bool:
    return any(word in GENERIC_ORGANISATION_WORDS for word in key.split())



def _compatible_threats(left: Item, right: Item) -> bool:
    return left.Threat == right.Threat or config.THREAT_UNKNOWN in {left.Threat, right.Threat}


def find_duplicate_candidates(items: list[Item], max_days: int = 3) -> list[DuplicateCandidate]:
    """Retourne les candidats satisfaisant les critères d'audit stricts.

    Les deux sources doivent être distinctes, les noms doivent avoir une
    inclusion de mots entière, et une paire ne peut être retenue qu'avec la
    même menace (ou une menace inconnue). Aucun résultat n'est une instruction
    de fusion.
    """
    candidates: list[DuplicateCandidate] = []
    ordered = sorted(items, key=lambda item: (
        item.Published_Date, item.Source_ID, item.Item_ID, item.URL,
    ))
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
            if days_apart > max_days or not _compatible_threats(left, right):
                continue
            short, long = sorted((left, right), key=lambda item: (
                len(item.Organisation_Key.split()), len(item.Organisation_Key), item.Organisation_Key,
            ))
            if _has_generic_word(short.Organisation_Key) or _has_generic_word(long.Organisation_Key):
                continue
            if _contains_word_sequence(long.Organisation_Key, short.Organisation_Key):
                candidates.append(DuplicateCandidate(short, long, days_apart))
    return sorted(candidates, key=lambda candidate: (
        candidate.short.Organisation_Key, candidate.long.Organisation_Key,
        candidate.days_apart, candidate.short.Source_ID, candidate.long.Source_ID,
    ))
