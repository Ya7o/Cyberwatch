"""Arbitre unique des candidats de qualification."""
from __future__ import annotations
from dataclasses import dataclass, replace
from collections import defaultdict
from .model import Item
from .qualification_decision import QualificationDecision, precedence

@dataclass(frozen=True)
class QualificationCandidate:
    item_id: str
    source_id: str
    field: str
    value: str
    origin: str
    confidence: str = ""
    evidence: str = ""
    match_strategy: str = ""

    @classmethod
    def from_decision(cls, decision: QualificationDecision) -> "QualificationCandidate":
        return cls(decision.item_id, decision.source_id, decision.field,
                   decision.candidate_value or decision.final_value, decision.origin,
                   decision.confidence, decision.evidence, decision.match_strategy)

def choose_winner(candidates: list[QualificationCandidate]) -> QualificationCandidate | None:
    usable = [candidate for candidate in candidates if candidate.value]
    if not usable:
        return None
    return min(usable, key=lambda candidate: (precedence(candidate.origin), candidate.origin,
                                               candidate.value, candidate.match_strategy, candidate.evidence))

def reconcile(items: list[Item], decisions: list[QualificationDecision]) -> list[QualificationDecision]:
    by_key = defaultdict(list)
    for decision in decisions:
        by_key[(decision.item_id, decision.field)].append(decision)
    items_by_id = {item.Item_ID: item for item in items}
    output = []
    for key, rows in sorted(by_key.items()):
        applied = [row for row in rows if row.decision == "APPLIED" and (row.candidate_value or row.final_value)]
        winner = choose_winner([QualificationCandidate.from_decision(row) for row in applied])
        item = items_by_id.get(key[0])
        winning_value = winner.value if winner else (str(getattr(item, key[1], "") or "") if item else "")
        winning_origin = winner.origin if winner else ""
        if item is not None and winner is not None:
            setattr(item, key[1], winner.value)
        for row in rows:
            same = winner is not None and row.decision == "APPLIED" and row.origin == winner.origin and (row.candidate_value or row.final_value) == winner.value
            if same:
                output.append(replace(row, final_value=winning_value, rejected_reason="", winning_origin=winning_origin, winning_value=winning_value))
            elif row.decision == "APPLIED" and winner is not None:
                output.append(replace(row, final_value=winning_value, decision="REJECTED_LOWER_PRIORITY",
                                      rejected_reason="lower_priority", winning_origin=winning_origin, winning_value=winning_value))
            else:
                reason = row.rejected_reason or _reason_from_decision(row.decision)
                output.append(replace(row, final_value=winning_value or row.final_value, rejected_reason=reason,
                                      winning_origin=winning_origin, winning_value=winning_value))
    return sorted(output, key=lambda row: (row.item_id, row.field, precedence(row.origin), row.origin, row.decision))

def _reason_from_decision(decision: str) -> str:
    if decision == "PROTECTED":
        return "protected_by_existing_value"
    if decision.startswith("REJECTED_"):
        return decision.removeprefix("REJECTED_").lower()
    return ""
