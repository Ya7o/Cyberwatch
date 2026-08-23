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
    Ordre de résolution (§Lot 7) : normalisation + aliases statiques (déjà
    appliqués par ``organisation_key``) -> identités territoriales fortes ->
    registre d'identité organisationnelle validé (équivalences LLM
    confirmées, persistées, §Lot 6) -> clé canonique. Le registre ne peut
    jamais court-circuiter une identité territoriale forte.
    """
    canonical_raw = organisation_key(raw) if raw else ""
    canonical_stored = organisation_key(stored_key) if stored_key else ""

    for candidate in (canonical_raw, raw, canonical_stored, stored_key):
        territorial = territorial_organisation_key(candidate)
        if territorial:
            return territorial

    for candidate in (canonical_raw, canonical_stored):
        registry_target = ORGANISATION_IDENTITY_REGISTRY.get(candidate, "") if candidate else ""
        if registry_target:
            return registry_target

    return canonical_raw or canonical_stored


# --------------------------------------------------------------------------
# Registre d'identité organisationnelle validé (§Lot 6/7)
# --------------------------------------------------------------------------
#
# `organisation_aliases.csv` reste le référentiel statique, versionné et
# curé à la main (§Lot 6 : "ne pas remplacer organisation_aliases.csv"). Ce
# registre représente uniquement des décisions dynamiques déjà validées
# (typiquement par le filet LLM quotidien, §Lot 5) : Decision=SAME est la
# seule valeur qui influence `effective_organisation_key`. Une entrée
# Alias_Key -> Canonical_Key ne peut jamais pointer vers deux cibles
# différentes (collision) ni former de cycle : les deux sont des erreurs de
# qualité explicites, jamais résolues arbitrairement.

ORGANISATION_IDENTITY_REGISTRY_COLUMNS = [
    "Alias_Key",
    "Canonical_Key",
    "Alias_Raw",
    "Canonical_Raw",
    "Decision",
    "Origin",
    "Confidence",
    "Evidence",
    "First_Seen",
    "Last_Validated",
    "Model",
    "Prompt_Version",
    "Input_Hash",
]

DECISION_SAME = "SAME"

ORIGIN_LLM_CONFIRMED = "LLM_CONFIRMED"
ORIGIN_DETERMINISTIC_CONFIRMED = "DETERMINISTIC_CONFIRMED"
ORIGIN_MANUAL = "MANUAL"
_ALLOWED_REGISTRY_ORIGINS = frozenset({
    ORIGIN_LLM_CONFIRMED, ORIGIN_DETERMINISTIC_CONFIRMED, ORIGIN_MANUAL,
})


def _default_organisation_identity_registry_path() -> Path:
    return Path(__file__).resolve().parents[1] / "data" / "organisation_identity_registry.csv"


def _organisation_identity_rows_by_alias(
    rows: list[dict[str, str]], *, strict: bool,
) -> tuple[dict[str, dict[str, str]], list[str]]:
    """Indexe les lignes ``Decision=SAME`` valides par ``Alias_Key``.

    En mode ``strict`` (chargement du fichier canonique), toute ligne
    invalide est une erreur — le fichier sur disque est censé être déjà
    validé. En mode non strict (fusion de nouvelles décisions candidates en
    cours de run), une ligne invalide est simplement ignorée sans faire
    échouer le run : le pipeline déterministe ne doit jamais dépendre de la
    qualité d'une décision LLM (§Lot 15).
    """
    by_alias: dict[str, dict[str, str]] = {}
    problems: list[str] = []
    for row in rows:
        alias = str(row.get("Alias_Key", "")).strip()
        canonical = str(row.get("Canonical_Key", "")).strip()
        decision = str(row.get("Decision", "")).strip()
        if decision != DECISION_SAME:
            continue
        if not alias or not canonical or alias == canonical:
            if strict:
                problems.append(f"Registre identité organisation : ligne invalide {row}")
            continue
        if alias in by_alias and by_alias[alias]["Canonical_Key"] != canonical:
            problems.append(f"Registre identité organisation : collision sur {alias}")
            continue
        by_alias[alias] = dict(row)
    return by_alias, problems


def _flatten_organisation_identity_rows(
    by_alias: dict[str, dict[str, str]],
) -> tuple[dict[str, dict[str, str]], list[str]]:
    """Résout chaque alias vers sa cible ultime ; rejette tout cycle (A→B→A)."""
    resolved: dict[str, dict[str, str]] = {}
    problems: list[str] = []
    for alias, row in by_alias.items():
        target = row["Canonical_Key"]
        seen = {alias}
        while target in by_alias and target not in seen:
            seen.add(target)
            target = by_alias[target]["Canonical_Key"]
        if target in seen:
            problems.append(f"Registre identité organisation : cycle détecté autour de {alias}")
            continue
        flattened = dict(row)
        flattened["Canonical_Key"] = target
        resolved[alias] = flattened
    return resolved, problems


def load_organisation_identity_registry(path: Path | None = None) -> dict[str, str]:
    """Charge le registre versionné : toute incohérence est une erreur explicite.

    Contrairement à ``merge_organisation_identity_rows`` (tolérant, pour
    appliquer de nouvelles décisions candidates en cours de run), le
    chargement du fichier canonique est strict, à l'image de
    ``normalize.load_organisation_aliases`` : ce fichier est censé être déjà
    validé, donc toute incohérence détectée ici est une corruption réelle.
    """
    registry_path = path or _default_organisation_identity_registry_path()
    if not registry_path.exists():
        return {}
    with registry_path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    by_alias, problems = _organisation_identity_rows_by_alias(rows, strict=True)
    if problems:
        raise ValueError("; ".join(problems))
    resolved, flatten_problems = _flatten_organisation_identity_rows(by_alias)
    if flatten_problems:
        raise ValueError("; ".join(flatten_problems))
    return {alias: row["Canonical_Key"] for alias, row in resolved.items()}


ORGANISATION_IDENTITY_REGISTRY: dict[str, str] = load_organisation_identity_registry()


def reload_organisation_identity_registry(path: Path | None = None) -> None:
    """Recharge le registre en mémoire (à appeler après une persistance en run).

    ``effective_organisation_key`` lit un singleton de module, au même titre
    qu'``ORGANISATION_ALIASES``/``TERRITORIAL_IDENTITIES``. Ceux-ci ne varient
    jamais en cours de process ; le registre d'identité, lui, peut être
    enrichi *pendant* un run par le filet LLM quotidien (§Lot 9) — d'où ce
    point de rechargement explicite, appelé par ``runner.execute`` juste
    avant ``qualify`` afin que la reconstruction des incidents du même run
    voie déjà la décision validée.
    """
    global ORGANISATION_IDENTITY_REGISTRY
    ORGANISATION_IDENTITY_REGISTRY = load_organisation_identity_registry(path)


def merge_organisation_identity_rows(
    existing_rows: list[dict[str, str]],
    new_rows: list[dict[str, str]],
) -> tuple[list[dict[str, str]], list[str]]:
    """Fusionne des décisions candidates dans le registre (§Lot 5/6).

    Chaque ``new_row`` conflictuelle (collision, cycle, champ manquant,
    origine non reconnue) est rejetée individuellement et journalisée dans la
    liste de problèmes renvoyée, sans jamais faire échouer la fusion des
    autres lignes valides ni le run courant. Aucune décision n'est appliquée
    par surprise : le registre résultant est toujours trié, sans collision ni
    cycle, prêt à être persisté tel quel.
    """
    combined, _ = _organisation_identity_rows_by_alias(existing_rows, strict=False)
    problems: list[str] = []

    for row in new_rows:
        alias = str(row.get("Alias_Key", "")).strip()
        canonical = str(row.get("Canonical_Key", "")).strip()
        origin = str(row.get("Origin", "")).strip()
        decision = str(row.get("Decision", "")).strip()

        if decision != DECISION_SAME or not alias or not canonical or alias == canonical:
            problems.append(f"Décision d'identité organisation ignorée (invalide) : {row}")
            continue
        if origin not in _ALLOWED_REGISTRY_ORIGINS:
            problems.append(f"Décision d'identité organisation ignorée (Origin invalide) : {row}")
            continue

        target = canonical
        seen = {alias}
        while target in combined and target not in seen:
            seen.add(target)
            target = combined[target]["Canonical_Key"]
        if target in seen:
            problems.append(
                f"Décision d'identité organisation ignorée (cycle) : {alias} -> {canonical}"
            )
            continue

        existing = combined.get(alias)
        if existing and existing["Canonical_Key"] != target:
            problems.append(
                f"Décision d'identité organisation ignorée (collision) : {alias} déjà -> "
                f"{existing['Canonical_Key']}, {target} proposé"
            )
            continue

        merged_row = dict(row)
        merged_row["Canonical_Key"] = target
        if existing and existing.get("First_Seen"):
            merged_row["First_Seen"] = existing["First_Seen"]
        combined[alias] = merged_row

    resolved, flatten_problems = _flatten_organisation_identity_rows(combined)
    problems.extend(flatten_problems)
    merged_rows = sorted(
        resolved.values(),
        key=lambda row: (row.get("Alias_Key", ""), row.get("Canonical_Key", "")),
    )
    return merged_rows, problems


def validate_organisation_identity_registry(rows: list[dict[str, str]]) -> list[str]:
    """Contrôles structurels du registre, pour les gates qualité (§Lot 16)."""
    by_alias, problems = _organisation_identity_rows_by_alias(rows, strict=True)
    _, flatten_problems = _flatten_organisation_identity_rows(by_alias)
    problems.extend(flatten_problems)
    return problems
