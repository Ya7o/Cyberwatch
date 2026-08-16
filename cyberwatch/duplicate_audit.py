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


DUPLICATE_CANDIDATE_NAME_CONTAINMENT = "DUPLICATE_CANDIDATE_NAME_CONTAINMENT"
#: Concaténation exacte : « france casse » vs « francecasse » (mêmes lettres,
#: espace en moins, un nombre de mots différent).
DUPLICATE_CANDIDATE_CONCATENATION = "DUPLICATE_CANDIDATE_CONCATENATION"
#: Permutation exacte des mêmes mots : « cravero motoculture » vs
#: « motoculture cravero » (mêmes mots, même nombre, ordre différent).
DUPLICATE_CANDIDATE_PERMUTATION = "DUPLICATE_CANDIDATE_PERMUTATION"

#: Signaux "haute confiance" (§Lot 4, gate qualité) : correspondance EXACTE
#: sur l'ensemble des mots — rien en plus, rien en moins, juste réarrangés ou
#: recollés. Contrairement à l'inclusion, volontairement large et non
#: bloquante (des victimes institutionnelles légitimement distinctes s'y
#: recoupent, cf. tests), ces deux signaux n'ont pas de faux positif connu :
#: exiger l'ensemble exact des mots exclut structurellement les sous-entités
#: (« City Pro » / « City Pro Marionneau » ne matche ni l'un ni l'autre).
HIGH_CONFIDENCE_REASON_CODES = frozenset({
    DUPLICATE_CANDIDATE_CONCATENATION,
    DUPLICATE_CANDIDATE_PERMUTATION,
})


@dataclass(frozen=True)
class DuplicateCandidate:
    """Deux items proches, mais volontairement non fusionnés."""

    short: Item
    long: Item
    days_apart: int
    reason_code: str = DUPLICATE_CANDIDATE_NAME_CONTAINMENT


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


def _same_concatenated(a_key: str, b_key: str) -> bool:
    """Vrai si les deux clés ne diffèrent que par la présence d'espaces."""
    a_tokens, b_tokens = a_key.split(), b_key.split()
    if len(a_tokens) == len(b_tokens):
        return False
    return "".join(a_tokens) == "".join(b_tokens)


def _same_permutation(a_key: str, b_key: str) -> bool:
    """Vrai si les deux clés partagent exactement les mêmes mots, dans un
    ordre différent."""
    a_tokens, b_tokens = a_key.split(), b_key.split()
    return a_key != b_key and len(a_tokens) > 1 and sorted(a_tokens) == sorted(b_tokens)


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
            # Un seul reason_code par paire : les trois signaux ne se
            # recouvrent jamais en pratique (containment exige une longueur
            # de mots strictement différente avec sous-séquence contiguë,
            # concaténation exige un nombre de mots différent avec fusion
            # exacte des lettres, permutation exige le même nombre de mots
            # avec un ordre différent — mutuellement exclusifs par
            # construction), l'ordre ci-dessous ne fait que documenter la
            # priorité en cas de doute futur.
            if _contains_word_sequence(long.Organisation_Key, short.Organisation_Key):
                candidates.append(DuplicateCandidate(short, long, days_apart))
            elif _same_concatenated(short.Organisation_Key, long.Organisation_Key):
                candidates.append(DuplicateCandidate(
                    short, long, days_apart, DUPLICATE_CANDIDATE_CONCATENATION
                ))
            elif _same_permutation(short.Organisation_Key, long.Organisation_Key):
                candidates.append(DuplicateCandidate(
                    short, long, days_apart, DUPLICATE_CANDIDATE_PERMUTATION
                ))

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
