"""Détection conservatrice des cas de déduplication à examiner."""

from __future__ import annotations

from dataclasses import dataclass

from . import config
from .dedup import MERGE, NO_DECISION, decide_merge
from .model import Item
from .normalize import date_or_empty, organisation_key

DUPLICATE_CANDIDATE_NAME_CONTAINMENT = "DUPLICATE_CANDIDATE_NAME_CONTAINMENT"
DUPLICATE_CANDIDATE_CONCATENATION = "DUPLICATE_CANDIDATE_CONCATENATION"
DUPLICATE_CANDIDATE_PERMUTATION = "DUPLICATE_CANDIDATE_PERMUTATION"
DUPLICATE_CANDIDATE_SHARED_COMPANY_ID = "DUPLICATE_CANDIDATE_SHARED_COMPANY_ID"

MERGE_REVIEW_WEAK_CANONICAL_NAME = "MERGE_REVIEW_WEAK_CANONICAL_NAME"
MERGE_REVIEW_WEAK_ALIAS = "MERGE_REVIEW_WEAK_ALIAS"
MERGE_REVIEW_RANSOMWARE_CORROBORATION = "MERGE_REVIEW_RANSOMWARE_CORROBORATION"

RISK_MISSED_DUPLICATE = "POSSIBLE_MISSED_DUPLICATE"
RISK_FALSE_MERGE = "POSSIBLE_FALSE_MERGE"

HIGH_CONFIDENCE_REASON_CODES = frozenset({
    DUPLICATE_CANDIDATE_CONCATENATION,
    DUPLICATE_CANDIDATE_PERMUTATION,
})


@dataclass(frozen=True)
class DuplicateCandidate:
    short: Item
    long: Item
    days_apart: int
    reason_code: str = DUPLICATE_CANDIDATE_NAME_CONTAINMENT


@dataclass(frozen=True)
class DedupAuditCandidate:
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
    a_tokens, b_tokens = a_key.split(), b_key.split()
    if len(a_tokens) == len(b_tokens):
        return False
    return "".join(a_tokens) == "".join(b_tokens)


def _same_permutation(a_key: str, b_key: str) -> bool:
    a_tokens, b_tokens = a_key.split(), b_key.split()
    return a_key != b_key and len(a_tokens) > 1 and sorted(a_tokens) == sorted(b_tokens)


def _effective_key(item: Item) -> str:
    return organisation_key(item.Organisation_Raw) or item.Organisation_Key


def _ordered_pair(left: Item, right: Item) -> tuple[Item, Item]:
    return tuple(sorted(
        (left, right),
        key=lambda item: (
            item.best_date, item.Source_ID, item.Source_Item_ID, item.Item_ID, item.URL,
        ),
    ))  # type: ignore[return-value]


def _days_apart(left: Item, right: Item) -> int | None:
    left_date = date_or_empty(left.best_date)
    right_date = date_or_empty(right.best_date)
    if not left_date or not right_date:
        return None
    return abs((left_date - right_date).days)


def _company_id(item: Item, company_ids: dict[str, str]) -> str:
    return company_ids.get(item.Organisation_Key, "") or company_ids.get(_effective_key(item), "")


def find_duplicate_candidates(
    items: list[Item],
    max_days: int = config.INCIDENT_GAP_DAYS,
) -> list[DuplicateCandidate]:
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
            if days_apart > max_days:
                continue
            short, long = sorted(
                (left, right),
                key=lambda item: (
                    len(item.Organisation_Key.split()), len(item.Organisation_Key), item.Organisation_Key,
                ),
            )
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

    return sorted(candidates, key=lambda candidate: (
        candidate.short.Organisation_Key, candidate.long.Organisation_Key,
        candidate.days_apart, candidate.short.Source_ID, candidate.long.Source_ID,
    ))


def find_audit_candidates(
    items: list[Item],
    company_ids: dict[str, str] | None = None,
    max_days: int = config.INCIDENT_GAP_DAYS,
) -> list[DedupAuditCandidate]:
    company_ids = company_ids or {}
    candidates: dict[tuple[str, str, str], DedupAuditCandidate] = {}

    def add(candidate: DedupAuditCandidate) -> None:
        left, right = _ordered_pair(candidate.left, candidate.right)
        normalized = DedupAuditCandidate(
            candidate.risk_type, left, right, candidate.days_apart,
            candidate.reason_code, candidate.company_id,
        )
        key = (normalized.risk_type, left.Item_ID, right.Item_ID)
        existing = candidates.get(key)
        if existing and existing.reason_code == DUPLICATE_CANDIDATE_SHARED_COMPANY_ID:
            return
        candidates[key] = normalized

    for lexical in find_duplicate_candidates(items, max_days=max_days):
        if _effective_key(lexical.short) == _effective_key(lexical.long):
            continue
        if decide_merge(lexical.short, lexical.long).action != NO_DECISION:
            continue
        add(DedupAuditCandidate(
            RISK_MISSED_DUPLICATE, lexical.short, lexical.long,
            lexical.days_apart, lexical.reason_code,
        ))

    ordered = sorted(items, key=lambda item: (
        item.best_date, item.Source_ID, item.Source_Item_ID, item.Item_ID, item.URL,
    ))
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
                        RISK_MISSED_DUPLICATE, left, right, days_apart,
                        DUPLICATE_CANDIDATE_SHARED_COMPANY_ID, left_company,
                    ))
                continue

            if decision.action != MERGE:
                continue
            if left.Source_ID == right.Source_ID and left.URL and left.URL == right.URL:
                continue
            if decision.reason_code == "INCIDENT_MERGE_CANONICAL_NAME":
                reason_code = MERGE_REVIEW_WEAK_CANONICAL_NAME
            elif decision.reason_code == "INCIDENT_MERGE_ALIAS":
                reason_code = MERGE_REVIEW_WEAK_ALIAS
            elif decision.reason_code == "INCIDENT_MERGE_RANSOMWARE_CORROBORATION":
                reason_code = MERGE_REVIEW_RANSOMWARE_CORROBORATION
            else:
                continue
            add(DedupAuditCandidate(
                RISK_FALSE_MERGE, left, right, days_apart, reason_code,
            ))

    return sorted(candidates.values(), key=lambda candidate: (
        candidate.risk_type, candidate.left.best_date, candidate.left.Organisation_Key,
        candidate.right.Organisation_Key, candidate.left.Source_ID, candidate.right.Source_ID,
        candidate.left.Item_ID, candidate.right.Item_ID,
    ))
