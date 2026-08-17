"""Détection conservatrice des cas de déduplication à examiner.

Ce module ne modifie jamais les items et ne rapproche aucune identité : il
produit uniquement des candidats étayés par des indices reproductibles. La
menace et la catégorie de l'organisation ne servent pas de filtre d'identité :
deux sources peuvent qualifier différemment le même événement, et les victimes
institutionnelles doivent rester auditables comme les autres.
"""

from __future__ import annotations

from dataclasses import dataclass

from .dedup import MERGE, NO_DECISION, decide_merge
from .model import Item
from .normalize import date_or_empty, organisation_key


DUPLICATE_CANDIDATE_NAME_CONTAINMENT = "DUPLICATE_CANDIDATE_NAME_CONTAINMENT"
#: Concaténation exacte : « france casse » vs « francecasse » (mêmes lettres,
#: espace en moins, un nombre de mots différent).
DUPLICATE_CANDIDATE_CONCATENATION = "DUPLICATE_CANDIDATE_CONCATENATION"
#: Permutation exacte des mêmes mots : « cravero motoculture » vs
#: « motoculture cravero » (mêmes mots, même nombre, ordre différent).
DUPLICATE_CANDIDATE_PERMUTATION = "DUPLICATE_CANDIDATE_PERMUTATION"
#: Deux identités textuelles distinctes résolues par le registre vers le même
#: identifiant d'entreprise. C'est une preuve d'identité, pas de même incident.
DUPLICATE_CANDIDATE_SHARED_COMPANY_ID = "DUPLICATE_CANDIDATE_SHARED_COMPANY_ID"

MERGE_REVIEW_WEAK_CANONICAL_NAME = "MERGE_REVIEW_WEAK_CANONICAL_NAME"
MERGE_REVIEW_WEAK_ALIAS = "MERGE_REVIEW_WEAK_ALIAS"

RISK_MISSED_DUPLICATE = "POSSIBLE_MISSED_DUPLICATE"
RISK_FALSE_MERGE = "POSSIBLE_FALSE_MERGE"

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


@dataclass(frozen=True)
class DedupAuditCandidate:
    """Paire à challenger sans modifier la déduplication de production."""

    risk_type: str
    left: Item
    right: Item
    days_apart: int
    reason_code: str
    company_id: str = ""


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


def _effective_key(item: Item) -> str:
    """Clé d'organisation actuelle, aliases compris, sans réécrire l'item."""
    return organisation_key(item.Organisation_Raw) or item.Organisation_Key


def _ordered_pair(left: Item, right: Item) -> tuple[Item, Item]:
    return tuple(sorted(
        (left, right),
        key=lambda item: (
            item.best_date,
            item.Source_ID,
            item.Source_Item_ID,
            item.Item_ID,
            item.URL,
        ),
    ))  # type: ignore[return-value]


def _days_apart(left: Item, right: Item) -> int | None:
    left_date = date_or_empty(left.best_date)
    right_date = date_or_empty(right.best_date)
    if not left_date or not right_date:
        return None
    return abs((left_date - right_date).days)


def _company_id(item: Item, company_ids: dict[str, str]) -> str:
    """Résout l'identifiant déjà validé dans le cache d'enrichissement."""
    return (
        company_ids.get(item.Organisation_Key, "")
        or company_ids.get(_effective_key(item), "")
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


def find_audit_candidates(
    items: list[Item],
    company_ids: dict[str, str] | None = None,
    max_days: int = 3,
) -> list[DedupAuditCandidate]:
    """Retourne uniquement les décisions de déduplication qui méritent revue.

    Deux risques sont exposés sans jamais changer la production :
    - ``POSSIBLE_MISSED_DUPLICATE`` : le moteur reste en ``NO_DECISION`` mais
      un signal de nom ou un Company_ID commun suggère la même victime ;
    - ``POSSIBLE_FALSE_MERGE`` : le moteur fusionne sur le seul nom/alias et
      la proximité temporelle, sans identifiant natif ni date d'événement égale.

    ``Company_ID`` est seulement un signal d'identité d'organisation : il ne
    suffit jamais à affirmer qu'il s'agit du même incident.
    """
    company_ids = company_ids or {}
    candidates: dict[tuple[str, str, str], DedupAuditCandidate] = {}

    def add(candidate: DedupAuditCandidate) -> None:
        left, right = _ordered_pair(candidate.left, candidate.right)
        normalized = DedupAuditCandidate(
            candidate.risk_type,
            left,
            right,
            candidate.days_apart,
            candidate.reason_code,
            candidate.company_id,
        )
        key = (normalized.risk_type, left.Item_ID, right.Item_ID)
        existing = candidates.get(key)
        # Pour les doublons manqués, le Company_ID commun est plus probant
        # qu'une simple forme de nom et remplace donc le signal lexical.
        if (
            existing
            and existing.reason_code == DUPLICATE_CANDIDATE_SHARED_COMPANY_ID
        ):
            return
        candidates[key] = normalized

    # Signaux lexicaux existants, mais uniquement s'ils sont encore réellement
    # non résolus par les aliases courants et par decide_merge().
    for lexical in find_duplicate_candidates(items, max_days=max_days):
        if _effective_key(lexical.short) == _effective_key(lexical.long):
            continue
        if decide_merge(lexical.short, lexical.long).action != NO_DECISION:
            continue
        add(DedupAuditCandidate(
            RISK_MISSED_DUPLICATE,
            lexical.short,
            lexical.long,
            lexical.days_apart,
            lexical.reason_code,
        ))

    ordered = sorted(
        items,
        key=lambda item: (
            item.best_date,
            item.Source_ID,
            item.Source_Item_ID,
            item.Item_ID,
            item.URL,
        ),
    )
    for index, left in enumerate(ordered):
        if not left.best_date:
            continue
        for right in ordered[index + 1:]:
            days_apart = _days_apart(left, right)
            if days_apart is None or days_apart > max_days:
                continue

            decision = decide_merge(left, right)
            if decision.action == NO_DECISION and _effective_key(left) != _effective_key(right):
                left_company = _company_id(left, company_ids)
                right_company = _company_id(right, company_ids)
                if left_company and left_company == right_company:
                    add(DedupAuditCandidate(
                        RISK_MISSED_DUPLICATE,
                        left,
                        right,
                        days_apart,
                        DUPLICATE_CANDIDATE_SHARED_COMPANY_ID,
                        left_company,
                    ))
                continue

            if decision.action != MERGE:
                continue
            if decision.reason_code == "INCIDENT_MERGE_CANONICAL_NAME":
                reason_code = MERGE_REVIEW_WEAK_CANONICAL_NAME
            elif decision.reason_code == "INCIDENT_MERGE_ALIAS":
                reason_code = MERGE_REVIEW_WEAK_ALIAS
            else:
                continue
            add(DedupAuditCandidate(
                RISK_FALSE_MERGE,
                left,
                right,
                days_apart,
                reason_code,
            ))

    return sorted(
        candidates.values(),
        key=lambda candidate: (
            candidate.risk_type,
            candidate.left.best_date,
            candidate.left.Organisation_Key,
            candidate.right.Organisation_Key,
            candidate.left.Source_ID,
            candidate.right.Source_ID,
            candidate.left.Item_ID,
            candidate.right.Item_ID,
        ),
    )
