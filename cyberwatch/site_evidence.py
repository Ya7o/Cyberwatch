"""Liens publics : publications sur l'incident et sites d'organisation distincts."""
from __future__ import annotations

from urllib.parse import urlsplit

_PUBLISHERS = {
    "la1ere.franceinfo.fr": "Réunion La 1ère",
    "franceinfo.fr": "Franceinfo",
    "linfo.re": "Linfo.re",
    "imazpress.com": "Imaz Press",
    "cyberattaque.org": "Cyberattaque.org",
    "frenchbreaches.com": "FrenchBreaches",
    "bonjourlafuite.eu.org": "BonjourLaFuite",
    "ransomware.live": "Ransomware.live",
}


def _url(value: object) -> str:
    text = str(value or "").strip()
    try:
        parsed = urlsplit(text)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return ""
        if parsed.username or parsed.password:
            return ""
    except ValueError:
        return ""
    return text


def _key(url: str) -> tuple[str, str]:
    parsed = urlsplit(url)
    path = parsed.path.rstrip("/") + ("?" + parsed.query if parsed.query else "")
    return (parsed.hostname or "").lower().removeprefix("www."), path


def publisher(url: str) -> str:
    host, _ = _key(url)
    return _PUBLISHERS.get(host, host)


def decorate(row: dict, facts: list[dict]) -> None:
    """Conserve les références explicites, sans fabriquer une URL de preuve."""
    websites = list(dict.fromkeys(
        url for fact in facts if (url := _url(fact.get("victim_website")))
    ))
    website_keys = {_key(url) for url in websites}
    candidates = list(row.get("source_links") or [])
    for fact in facts:
        candidates.extend(
            {"source": fact.get("source", ""), "url": url}
            for url in fact.get("evidence_urls") or []
        )
    publications = []
    seen: set[tuple[str, str]] = set()
    for candidate in candidates:
        url = _url(candidate.get("url"))
        if not url:
            continue
        key = _key(url)
        # Une page d'accueil ne documente pas un incident. Un site victime
        # identifié par les faits n'est jamais une publication de source.
        if key in seen or key in website_keys or not key[1]:
            continue
        seen.add(key)
        publications.append({
            "source": str(candidate.get("source") or ""),
            "url": url,
            "label": publisher(url),
        })
    row["source_links"] = publications
    row["organisation_links"] = websites
