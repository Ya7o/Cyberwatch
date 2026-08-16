"""Corrections manuelles minimales de qualité, versionnées dans Git.

Les overrides ne concernent que Threat/Sector/Location. Ils sont appliqués en
dernier recours avant la reconstruction des incidents et ne modifient jamais
l'identité d'un Item.
"""

from __future__ import annotations

from pathlib import Path

from . import config, store
from .model import Item

DEFAULT_PATH = store.DATA_DIR / "quality_overrides.csv"

_FIELD_CHOICES = {
    "Threat": frozenset(config.THREATS),
    "Sector": frozenset(config.SECTORS),
    "Location": frozenset(config.LOCATIONS),
}


def load_overrides(path: Path | None = None) -> dict[str, dict[str, str]]:
    """Charge et valide les overrides indexés par ``Item_ID``.

    Un fichier absent ou réduit à son en-tête est valide. Les valeurs métier
    non vides doivent appartenir aux taxonomies fermées de ``config.py`` et un
    même ``Item_ID`` ne peut apparaître qu'une fois.
    """
    rows = store.read_csv(path or DEFAULT_PATH)
    result: dict[str, dict[str, str]] = {}

    for line_number, row in enumerate(rows, start=2):
        item_id = (row.get("Item_ID") or "").strip()
        values = {
            field: (row.get(field) or "").strip()
            for field in _FIELD_CHOICES
        }

        if not item_id:
            if any(values.values()) or (row.get("Reason") or "").strip() or (row.get("Evidence_URL") or "").strip():
                raise ValueError(f"quality override sans Item_ID ligne {line_number}")
            continue
        if item_id in result:
            raise ValueError(f"quality override dupliqué pour Item_ID={item_id}")

        for field, value in values.items():
            if value and value not in _FIELD_CHOICES[field]:
                raise ValueError(
                    f"quality override invalide ligne {line_number}: {field}={value!r}"
                )

        result[item_id] = {
            **values,
            "Reason": (row.get("Reason") or "").strip(),
            "Evidence_URL": (row.get("Evidence_URL") or "").strip(),
        }

    return result


def apply_overrides(
    items: list[Item], overrides: dict[str, dict[str, str]] | None = None
) -> dict[str, int]:
    """Applique les corrections présentes pour les items du snapshot.

    Les références devenues orphelines sont ignorées : un override historique
    ne doit pas empêcher un CREATE/MAJ si l'item n'est pas présent dans le
    snapshot courant. Seules les cellules non vides remplacent une valeur.
    """
    overrides = load_overrides() if overrides is None else overrides
    changes = {
        "quality_override_items": 0,
        "quality_override_threat": 0,
        "quality_override_sector": 0,
        "quality_override_location": 0,
    }

    for item in items:
        override = overrides.get(item.Item_ID)
        if override is None:
            continue

        changed_item = False
        for field, counter in (
            ("Threat", "quality_override_threat"),
            ("Sector", "quality_override_sector"),
            ("Location", "quality_override_location"),
        ):
            value = override.get(field, "")
            if value and getattr(item, field) != value:
                setattr(item, field, value)
                changes[counter] += 1
                changed_item = True

        if changed_item:
            changes["quality_override_items"] += 1

    return changes
