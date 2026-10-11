"""Diagnostics de disponibilité du fournisseur, sans contenu de réponse privé."""
from __future__ import annotations

import datetime as dt
import math
from email.utils import parsedate_to_datetime

QUOTA_ERRORS = {"insufficient_quota", "billing_hard_limit_reached"}
ERROR_CODES = QUOTA_ERRORS | {
    "rate_limit_exceeded", "invalid_api_key", "model_not_found",
    "invalid_request_error", "server_error",
}


def retry_after_seconds(response) -> float:
    value = str((getattr(response, "headers", None) or {}).get("Retry-After", ""))
    try:
        delay = float(value)
    except ValueError:
        try:
            until = parsedate_to_datetime(value)
            if until.tzinfo is None:
                until = until.replace(tzinfo=dt.UTC)
            delay = (until - dt.datetime.now(dt.UTC)).total_seconds()
        except (TypeError, ValueError, OverflowError):
            return 0.0
    return max(0.0, delay) if math.isfinite(delay) else 0.0


def error_diagnostic(response) -> tuple[str, str]:
    """Ne conserve que des catégories prédéfinies, jamais le message ni le corps."""
    try:
        payload = response.json()
    except (ValueError, TypeError):
        return "unknown_provider_error", "non_json"
    error = payload.get("error") if isinstance(payload, dict) else None
    if not isinstance(error, dict):
        return "unknown_provider_error", "json_without_error"
    # Certains fournisseurs livrent un code non reconnu mais un type standard.
    for value in (error.get("code"), error.get("type")):
        if isinstance(value, str) and value in ERROR_CODES:
            return value, "structured_error"
    return "unknown_provider_error", "unrecognized_error"


def qualification_reasons(transport: dict) -> list[str]:
    blocked = transport.get("provider_blocked_reason")
    reasons = []
    if isinstance(blocked, str) and blocked in QUOTA_ERRORS:
        reasons.append("quota API LLM épuisé : " + str(blocked))
    elif transport.get("http_429"):
        reasons.append(f"{transport['http_429']} refus HTTP 429 de l'API LLM")
    if blocked == "repeated_http_429":
        reasons.append("appels LLM suspendus pour ce run après des refus HTTP 429 répétés")
    formats = transport.get("provider_error_formats")
    if isinstance(formats, dict) and formats.get("non_json"):
        reasons.append("réponse d'erreur LLM non JSON : origine du refus non déterminée")
    if transport.get("calls_provider_blocked"):
        reasons.append(f"{transport['calls_provider_blocked']} appel(s) LLM différé(s) pour indisponibilité")
    return reasons
