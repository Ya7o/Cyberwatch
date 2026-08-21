"""Gap-driven semantic selection for Cyberattaque.org.

Length and deterministic richness are deliberately not positive signals. The LLM
is reserved for explicit ambiguity/negation and unresolved third-party relations,
which are cases the semantic extractor is designed to disambiguate.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from ..normalize import searchable

SELECTION_VERSION = "2"

_AMBIGUITY = (
    "pourrait", "pourraient", "susceptible", "hypothese", "non confirme",
    "selon l attaquant", "selon le groupe", "revendique", "revendication",
)
_NEGATION = ("n ont pas ete", "n a pas ete", "ne sont pas", "nie ", "dement")
_THIRD_PARTY = ("prestataire", "fournisseur", "supply chain", "sous traitant", "aws", "azure", "cloud")


@dataclass(frozen=True)
class SelectionDecision:
    use_llm: bool
    score: int
    reasons: tuple[str, ...]
    version: str = SELECTION_VERSION

    def as_dict(self) -> dict:
        return {"use_llm": self.use_llm, "score": self.score, "reasons": list(self.reasons), "version": self.version}


def _has_any(low: str, tokens: tuple[str, ...]) -> bool:
    return any(token in low for token in tokens)


def _count(value) -> int:
    return len(value) if isinstance(value, list) else 0


def decide(text: str, deterministic: dict) -> SelectionDecision:
    low = searchable(text or "")
    deterministic = deterministic if isinstance(deterministic, dict) else {}
    reasons: list[str] = []
    score = 0

    if _has_any(low, _AMBIGUITY):
        reasons.append("ambiguous_claim")
        score += 3
    if _has_any(low, _NEGATION):
        reasons.append("negation_detected")
        score += 3
    if _has_any(low, _THIRD_PARTY) and _count(deterministic.get("relations")) == 0:
        reasons.append("missing_third_party_relation")
        score += 2

    richness = sum(_count(deterministic.get(key)) for key in (
        "affected_counts", "data_volumes", "timeline", "relations", "data_types"
    ))
    if richness >= 5 and score < 3:
        score = max(0, score - 2)
        reasons = [reason for reason in reasons if reason in {"ambiguous_claim", "negation_detected"}]

    return SelectionDecision(use_llm=score >= 2, score=score, reasons=tuple(reasons))


def reason_counts(decisions: list[SelectionDecision]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for decision in decisions:
        counts.update(decision.reasons)
    return dict(sorted(counts.items()))
