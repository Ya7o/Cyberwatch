"""Résolution déterministe d'identité organisationnelle pour la déduplication.

La normalisation historique de :mod:`cyberwatch.normalize` reste la source de
vérité générale. Cette couche ajoute uniquement des équivalences structurelles
fortes pour les collectivités françaises dont l'identité est portée par un code
officiel (département/région).

Une organisation inconnue n'est jamais bloquée ni rapprochée approximativement :
si aucune identité territoriale exacte n'est reconnue, sa clé normalisée actuelle
est conservée telle quelle.
"""

from __future__ import annotations

import csv
import re
from pathlib import Path

from .normalize import _base_organisation_key, organisation_key


DEPARTMENT = "departement"
REGION = "region"
_ALLOWED_KINDS = frozenset({DEPARTMENT, REGION})

_ARTICLE_PREFIXES = (
    "de la ", "de l ", "du ", "des ", "de ", "d ",
    "la ", "le ", "les ", "l ",
)

# `_base_organisation_key` recolle volontairement les lettres et nombres
# (`CD 33` -> `cd33`, `département 974` -> `departement974`). Les motifs
# acceptent donc un code accolé, mais exigent une correspondance sur le libellé
# entier afin que « Region 11 Consulting » ne soit jamais pris pour une région.
_DEPARTMENT_PATTERNS = (
    re.compile(r"^conseil departemental(?:\s+(.+)|(2a|2b|\d{1,3}))$"),
    re.compile(r"^departement(?:\s+(.+)|(2a|2b|\d{1,3}))$"),
    re.compile(r"^cd(2a|2b|\d{1,3})$"),
)
_REGION_PATTERNS = (
    re.compile(r"^conseil regional(?:\s+(.+)|(\d{1,2}))$"),
    re.compile(r"^region(?:\s+(.+)|(\d{1,2}))$"),
    re.compile(r"^cr(\d{1,2})$"),
)


def _strip_leading_article(value: str) -> str:
    value = value.strip()
    for prefix in _ARTICLE_PREFIXES:
        if value.startswith(prefix):
            return value[len(prefix):].strip()
    return value


def _territory_value_key(value: str) -> str:
    return _strip_leading_article(_base_organisation_key(value))


def load_territorial_identities(path: Path | None = None) -> dict[tuple[str, str], str]:
    """Charge les noms/codes officiels et refuse les collisions silencieuses."""
    reference_path = (
        path
        or Path(__file__).resolve().parents[1] / "data" / "territorial_identities.csv"
    )
    identities: dict[tuple[str, str], str] = {}

    with reference_path.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            kind = str(row.get("kind", "")).strip().lower()
            code = str(row.get("code", "")).strip().lower()
            name = _territory_value_key(row.get("name", ""))
            if kind not in _ALLOWED_KINDS or not code or not name:
                raise ValueError(f"Identité territoriale invalide : {row}")

            canonical = f"{kind} {code}"
            keys = {name, code}
            if code.isdigit():
                keys.add(str(int(code)))

            for key in keys:
                index_key = (kind, key)
                previous = identities.get(index_key)
                if previous and previous != canonical:
                    raise ValueError(
                        f"Identité territoriale conflictuelle : {index_key}"
                    )
                identities[index_key] = canonical

    return identities


TERRITORIAL_IDENTITIES = load_territorial_identities()


def _matched_value(text: str, patterns: tuple[re.Pattern[str], ...]) -> str:
    for pattern in patterns:
        match = pattern.fullmatch(text)
        if not match:
            continue
        for value in match.groups():
            if value:
                return value
    return ""


def territorial_organisation_key(value: str) -> str:
    """Retourne une identité territoriale forte, ou une chaîne vide.

    Exemples reconnus : ``Département de la Gironde``, ``CD33``,
    ``Conseil départemental 974``, ``Région Île-de-France`` et ``CR11``.
    Un code seul n'est jamais reconnu : le type de collectivité est obligatoire.
    """
    text = _base_organisation_key(value)
    if not text:
        return ""

    department_value = _matched_value(text, _DEPARTMENT_PATTERNS)
    if department_value:
        key = _territory_value_key(department_value)
        return TERRITORIAL_IDENTITIES.get((DEPARTMENT, key), "")

    region_value = _matched_value(text, _REGION_PATTERNS)
    if region_value:
        key = _territory_value_key(region_value)
        return TERRITORIAL_IDENTITIES.get((REGION, key), "")

    return ""


def effective_organisation_key(raw: str, stored_key: str = "") -> str:
    """Clé d'identité canonique utilisée par la déduplication, sans mutation.

    Les deux entrées sont toujours repassées par ``organisation_key``. Cela
    empêche une clé persistée avant l'ajout d'un alias de contourner le
    référentiel courant lors d'un rebuild ou d'une mise à jour incrémentale.
    Les équivalences territoriales fortes restent prioritaires.
    """
    canonical_raw = organisation_key(raw) if raw else ""
    canonical_stored = organisation_key(stored_key) if stored_key else ""

    for candidate in (canonical_raw, raw, canonical_stored, stored_key):
        territorial = territorial_organisation_key(candidate)
        if territorial:
            return territorial

    return canonical_raw or canonical_stored
