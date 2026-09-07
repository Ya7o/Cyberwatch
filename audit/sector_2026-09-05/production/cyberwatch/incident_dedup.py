"""Registre persistant des verdicts LLM d'identité d'incident.

Le registre ne remplace pas les preuves déterministes fortes. Il mémorise
uniquement le verdict final sur une paire d'items ambiguë afin que REPLAY et
les exécutions suivantes reproduisent la même décision sans nouvel appel LLM.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping


SAME = "SAME"
DIFFERENT = "DIFFERENT"

REGISTRY_COLUMNS = [
    "Pair_Key",
    "Left_Item_ID",
    "Right_Item_ID",
    "Decision",
    "Confidence",
    "Evidence",
    "Reason",
    "Matched_Facts_JSON",
    "Conflicting_Facts_JSON",
    "First_Seen",
    "Last_Validated",
    "Model",
    "Prompt_Version",
    "Input_Hash",
]


def pair_key(left_item_id: str, right_item_id: str) -> str:
    """Clé symétrique stable d'une paire d'items."""
    return "|".join(sorted((str(left_item_id or ""), str(right_item_id or ""))))


def _normalise(row: Mapping[str, object]) -> dict[str, str]:
    return {column: str(row.get(column, "") or "") for column in REGISTRY_COLUMNS}


def decision_map(rows: Iterable[Mapping[str, object]]) -> dict[str, str]:
    """Retourne les décisions structurellement valides, indexées par paire."""
    decisions: dict[str, str] = {}
    for raw in rows:
        row = _normalise(raw)
        left_id, right_id = row["Left_Item_ID"], row["Right_Item_ID"]
        expected = pair_key(left_id, right_id)
        if not left_id or not right_id or left_id == right_id:
            continue
        if row["Pair_Key"] != expected:
            continue
        if row["Decision"] not in {SAME, DIFFERENT}:
            continue
        decisions[expected] = row["Decision"]
    return decisions


def merge_rows(
    existing: Iterable[Mapping[str, object]],
    proposals: Iterable[Mapping[str, object]],
    *,
    current_item_ids: set[str] | None = None,
) -> tuple[list[dict[str, str]], list[str]]:
    """Fusionne les décisions par paire et retire les références orphelines."""
    by_pair: dict[str, dict[str, str]] = {}
    problems: list[str] = []

    def accept(raw: Mapping[str, object], *, replace: bool) -> None:
        row = _normalise(raw)
        left_id, right_id = sorted((row["Left_Item_ID"], row["Right_Item_ID"]))
        expected = pair_key(left_id, right_id)
        if not left_id or not right_id or left_id == right_id:
            problems.append("Registre dedup incident : paire vide ou réflexive")
            return
        if row["Pair_Key"] != expected:
            problems.append(f"Registre dedup incident : Pair_Key invalide {row['Pair_Key']}")
            return
        if row["Decision"] not in {SAME, DIFFERENT}:
            problems.append(f"Registre dedup incident : décision invalide {row['Decision']}")
            return
        if current_item_ids is not None and (
            left_id not in current_item_ids or right_id not in current_item_ids
        ):
            return
        row["Left_Item_ID"], row["Right_Item_ID"] = left_id, right_id
        previous = by_pair.get(expected)
        if previous and not replace:
            problems.append(f"Registre dedup incident : paire dupliquée {expected}")
            return
        if previous and replace and previous.get("First_Seen"):
            stable_columns = (
                "Decision",
                "Confidence",
                "Evidence",
                "Reason",
                "Matched_Facts_JSON",
                "Conflicting_Facts_JSON",
                "Model",
                "Prompt_Version",
                "Input_Hash",
            )
            if all(previous.get(column, "") == row.get(column, "") for column in stable_columns):
                return
            row["First_Seen"] = previous["First_Seen"]
        by_pair[expected] = row

    for row in existing:
        accept(row, replace=False)
    for row in proposals:
        accept(row, replace=True)

    return [by_pair[key] for key in sorted(by_pair)], problems


def validate_registry(
    rows: Iterable[Mapping[str, object]], item_ids: set[str] | None = None,
) -> list[str]:
    """Valide les invariants persistants sans modifier les lignes."""
    normalized = list(rows)
    _, problems = merge_rows(normalized, (), current_item_ids=None)
    if item_ids is not None:
        for raw in normalized:
            row = _normalise(raw)
            missing = sorted({
                item_id
                for item_id in (row["Left_Item_ID"], row["Right_Item_ID"])
                if item_id and item_id not in item_ids
            })
            if missing:
                problems.append(
                    "Registre dedup incident : item(s) absent(s) " + ", ".join(missing)
                )
    return problems
