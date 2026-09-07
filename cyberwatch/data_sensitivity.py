"""Classification déterministe et multidimensionnelle des données exposées."""
from __future__ import annotations

from typing import Any

from .normalize import searchable


_PERSONAL_MARKERS = (
    "donnees personnelles", "nom", "prenom", "identite", "civilite",
    "adresse", "email", "e mail", "telephone", "mobile", "naissance",
    "identifiant", "compte", "client", "utilisateur", "photo", "genre",
    "nationalite", "profession", "emploi", "salaire", "iban", "rib",
    "bancair", "paiement", "sante", "medical", "nir", "securite sociale",
    "passeport", "piece d identite", "biometr", "permis de conduire",
)
_HIGH_MARKERS = (
    "iban", "rib", "bancair", "carte de paiement", "paiement",
    "sante", "medical", "patient", "diagnostic", "patholog", "nir",
    "securite sociale", "passeport", "piece d identite", "biometr",
    "permis de conduire",
)
_CREDENTIAL_MARKERS = (
    "mot de passe", "mots de passe", "password", "hash", "token", "secret",
    "cle api", "identifiant de connexion", "identifiants de connexion", "otp",
    "code de recuperation",
)
_VULNERABLE_MARKERS = ("mineur", "enfant", "eleve")


def _contains(text: str, markers: tuple[str, ...]) -> bool:
    padded = f" {searchable(text)} "
    return any(f" {marker}" in padded for marker in markers)


def _context(detail: dict[str, Any]) -> str:
    parts = [str(detail.get("display_summary") or "")]
    for entry in detail.get("claims", []) if isinstance(detail.get("claims"), list) else []:
        if isinstance(entry, dict):
            parts.extend((str(entry.get("value") or ""), str(entry.get("evidence") or "")))
    for value in (detail.get("fields") or {}).values():
        if isinstance(value, dict):
            parts.extend((str(value.get("value") or ""), str(value.get("evidence") or "")))
    for collection in ("timeline", "datasets", "systems"):
        for entry in detail.get(collection, []) if isinstance(detail.get(collection), list) else []:
            if isinstance(entry, dict):
                parts.extend((
                    str(entry.get("value") or entry.get("event") or ""),
                    str(entry.get("evidence") or ""),
                ))
    return " ".join(parts)


def classify(detail: dict[str, Any] | None) -> dict[str, Any]:
    detail = detail or {}
    values = [
        str(entry.get("value") or "").strip()
        for entry in detail.get("data_types", [])
        if isinstance(entry, dict) and str(entry.get("value") or "").strip()
    ]
    personal_types = [value for value in values if _contains(value, _PERSONAL_MARKERS)]
    high_types = [value for value in values if _contains(value, _HIGH_MARKERS)]
    credential_types = [value for value in values if _contains(value, _CREDENTIAL_MARKERS)]
    vulnerable = _contains(_context(detail), _VULNERABLE_MARKERS)
    personal = bool(personal_types or high_types or credential_types or vulnerable)
    high = bool(high_types or vulnerable)
    sensitive_types = list(dict.fromkeys(high_types + credential_types))
    return {
        "personal_data_exposed": personal,
        "high_sensitivity_data_exposed": high,
        "credentials_or_secrets_exposed": bool(credential_types),
        "vulnerable_people_data_exposed": vulnerable,
        # Compatibilité du contrat historique : « sensible » signifie ici
        # haute sensibilité ou secrets d'authentification, pas toute donnée
        # personnelle ordinaire.
        "sensitive_data_exposed": bool(high or credential_types),
        "sensitive_data_types": sensitive_types,
        "personal_data_types": personal_types,
    }


def consistency_alerts(exposure: dict[str, Any]) -> list[dict[str, str]]:
    """Contrôle le contrat entre les indicateurs dérivés publiés."""
    alerts: list[dict[str, str]] = []
    expected_sensitive = bool(
        exposure.get("high_sensitivity_data_exposed")
        or exposure.get("credentials_or_secrets_exposed")
    )
    if bool(exposure.get("sensitive_data_exposed")) != expected_sensitive:
        alerts.append({
            "code": "SENSITIVE_FLAG_INCONSISTENT",
            "field": "sensitive_data_exposed",
            "severity": "error",
        })
    if bool(exposure.get("high_sensitivity_data_exposed")) and not bool(
        exposure.get("personal_data_exposed")
    ):
        alerts.append({
            "code": "PERSONAL_DATA_FLAG_INCONSISTENT",
            "field": "personal_data_exposed",
            "severity": "error",
        })
    return alerts
