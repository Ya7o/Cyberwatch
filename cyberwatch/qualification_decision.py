"""Instrumentation canonique des décisions de qualification.

Ce module ne décide pas de la valeur métier. Il observe les mutations effectuées
par les couches existantes et expose une représentation homogène utilisable par
les benchmarks, les audits et, à terme, l'arbitre de qualification.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass

from .model import Item

QUALIFICATION_FIELDS = ("Sector", "Location", "Threat")


@dataclass(frozen=True)
class QualificationDecision:
    item_id: str
    source_id: str
    field: str
    previous_value: str
    candidate_value: str
    final_value: str
    origin: str
    confidence: str = ""
    evidence: str = ""
    match_strategy: str = ""
    decision: str = "APPLIED"

    @classmethod
    def from_provenance(cls, row: dict[str, str]) -> "QualificationDecision":
        return cls(
            item_id=row.get("Item_ID", ""),
            source_id=row.get("Source_ID", ""),
            field=row.get("Field", ""),
            previous_value=row.get("Previous_Value", ""),
            candidate_value=row.get("Candidate_Value", ""),
            final_value=row.get("Final_Value", ""),
            origin=row.get("Origin", ""),
            confidence=row.get("Confidence", ""),
            evidence=row.get("Evidence", ""),
            match_strategy=row.get("Match_Strategy", ""),
            decision=row.get("Decision", ""),
        )

    def to_row(self) -> dict[str, str]:
        return {
            "Item_ID": self.item_id,
            "Source_ID": self.source_id,
            "Field": self.field,
            "Previous_Value": self.previous_value,
            "Candidate_Value": self.candidate_value,
            "Final_Value": self.final_value,
            "Origin": self.origin,
            "Confidence": self.confidence,
            "Evidence": self.evidence,
            "Match_Strategy": self.match_strategy,
            "Decision": self.decision,
        }


def snapshot_fields(items: list[Item]) -> dict[str, dict[str, str]]:
    """Photographie les champs qualifiés par Item_ID avant une couche mutante."""
    return {
        item.Item_ID: {field: str(getattr(item, field, "") or "") for field in QUALIFICATION_FIELDS}
        for item in items
        if item.Item_ID
    }


def record_mutations(
    before: dict[str, dict[str, str]],
    items: list[Item],
    *,
    origin: str,
    confidence: str,
    evidence: str = "",
    match_strategy: str = "",
) -> list[QualificationDecision]:
    """Convertit les mutations d'une couche en décisions homogènes."""
    decisions: list[QualificationDecision] = []
    for item in items:
        previous = before.get(item.Item_ID)
        if previous is None:
            continue
        for field in QUALIFICATION_FIELDS:
            old = previous.get(field, "")
            new = str(getattr(item, field, "") or "")
            if new == old:
                continue
            decisions.append(
                QualificationDecision(
                    item_id=item.Item_ID,
                    source_id=item.Source_ID,
                    field=field,
                    previous_value=old,
                    candidate_value=new,
                    final_value=new,
                    origin=origin,
                    confidence=confidence,
                    evidence=evidence,
                    match_strategy=match_strategy,
                    decision="APPLIED",
                )
            )
    return sorted(decisions, key=_decision_sort_key)


def decisions_from_provenance(rows: list[dict[str, str]]) -> list[QualificationDecision]:
    return sorted(
        (QualificationDecision.from_provenance(row) for row in rows),
        key=_decision_sort_key,
    )


def summarize_decisions(decisions: list[QualificationDecision]) -> list[dict[str, object]]:
    """Agrège volume et résultat par origine/champ pour les rapports de run."""
    grouped: dict[tuple[str, str], list[QualificationDecision]] = defaultdict(list)
    for decision in decisions:
        grouped[(decision.origin, decision.field)].append(decision)

    rows: list[dict[str, object]] = []
    for (origin, field), values in sorted(grouped.items()):
        statuses = Counter(value.decision for value in values)
        confidences = Counter(value.confidence or "UNSPECIFIED" for value in values)
        rows.append(
            {
                "Origin": origin,
                "Field": field,
                "Decisions": len(values),
                "Applied": statuses.get("APPLIED", 0),
                "Rejected": sum(count for name, count in statuses.items() if name.startswith("REJECTED")),
                "Protected": statuses.get("PROTECTED", 0),
                "Other": sum(
                    count
                    for name, count in statuses.items()
                    if name != "APPLIED" and name != "PROTECTED" and not name.startswith("REJECTED")
                ),
                "Confidence": dict(sorted(confidences.items())),
            }
        )
    return rows


def _decision_sort_key(decision: QualificationDecision) -> tuple[str, str, str, str]:
    return (decision.item_id, decision.field, decision.origin, decision.decision)
