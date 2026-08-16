"""Collecteur ransomware.live — API JSON publique et gratuite.

Cette source était désactivée dans la méthode d'origine faute d'accès
opérationnel en conversation. En code c'est une simple API JSON, et la méthode
la désigne elle-même comme prioritaire (§21) : les sources françaises actuelles
sont fortement orientées « fuite de données », alors que cette API fournit des
victimes de rançongiciel avec organisation, pays, groupe et date.

L'API ayant connu plusieurs versions, plusieurs formes d'URL sont essayées et
celle qui répond est enregistrée dans `RUN_SOURCES`.
"""

from __future__ import annotations

import re
import time

from .. import config, status
from ..normalize import parse_date
from .base import CollectResult, Collector, RawEntry, SourceSpec, Window

COUNTRY_TO_LOCATION = {
    "FR": config.LOC_FRANCE,
    "RE": config.LOC_REUNION,
    "YT": config.LOC_MAYOTTE,
    "MU": config.LOC_MAURICE,
    "MG": config.LOC_MADAGASCAR,
    "SC": config.LOC_SEYCHELLES,
    "KM": config.LOC_COMORES,
}

ENDPOINT_TEMPLATES = [
    "https://api.ransomware.live/v2/countryvictims/{country}",
    "https://api.ransomware.live/countryvictims/{country}",
]

FIELD_ALIASES = {
    "organisation": ["victim", "post_title", "company", "name", "title"],
    "date": ["discovered", "published", "attackdate", "attack_date", "date",
             "publishedDate", "discovered_date"],
    "group": ["group_name", "group", "gang", "ransomware_group"],
    "country": ["country", "country_code", "victim_country"],
    "sector": ["activity", "sector", "industry"],
    "url": ["post_url", "url", "link", "website", "claim_url"],
}


def _first_field(record: dict, aliases: list[str]) -> str:
    for key in aliases:
        value = record.get(key)
        if value:
            return str(value).strip()
    return ""


def _victim_name(value: str) -> str:
    raw = (value or "").strip()
    lowered = raw.lower().removeprefix("www.")
    labels = lowered.split(".")
    if len(labels) == 2 and labels[-1] in {"fr", "com", "net", "org", "eu", "io", "co", "re"}:
        return labels[0]
    raw = re.sub(r"\s*-\s*(?:leaked data|data leak|claimed)\s*$", "", raw, flags=re.I)
    return raw.replace("-", " ").replace("_", " ").strip()


def _normalise_url(value: str) -> str:
    value = (value or "").strip()
    if value and not value.startswith(("http://", "https://")) and "." in value:
        return f"https://{value}"
    return value


class RansomwareLiveCollector(Collector):
    name = "ransomware_live"

    def collect(self, client, spec: SourceSpec, window: Window) -> CollectResult:
        budget = client.source_budget()
        result = CollectResult(access_method="ransomware.live")

        countries = spec.params.get("countries") or list(COUNTRY_TO_LOCATION)
        result.units_expected = len(countries)

        working_template = None
        seen: set[tuple[str, str]] = set()
        recognized = 0
        rate_limit_retries = 0

        for country in countries:
            if budget.exhausted:
                result.reason_code = status.REASON_BUDGET_SOURCE
                break

            templates = [working_template] if working_template else ENDPOINT_TEMPLATES
            fetched = False
            empty_country = False

            for template in templates:
                url = template.format(country=country)
                response = client.fetch(url, budget)
                if response.reason_code == status.REASON_HTTP_429:
                    rate_limit_retries += 1
                    time.sleep(config.RANSOMWARE_LIVE_RATE_LIMIT_SECONDS)
                    response = client.fetch(url, budget)
                if not response.ok:
                    if working_template and response.status_code == 404:
                        empty_country = True
                    else:
                        result.reason_code = response.reason_code
                    continue

                payload = response.json()
                records = _records_from(payload)
                if records is None:
                    continue

                working_template = template
                result.access_method = template.split("{")[0]
                fetched = True

                for record in records:
                    entry = _entry_from_record(record, spec, country)
                    if entry is None:
                        continue
                    signature = (entry.organisation.lower(), entry.published)
                    if signature in seen:
                        continue
                    seen.add(signature)
                    recognized += 1
                    if window.contains(entry.published):
                        result.entries.append(entry)
                break

            if fetched or empty_country:
                result.units_done += 1
            elif working_template is None:
                result.reason_code = status.REASON_HTTP_ERROR
                result.comment = "Aucun point d'entrée de l'API ransomware.live n'a répondu"
                break

            if working_template and "{country}" not in working_template:
                result.units_done = result.units_expected
                break

        result.reached_boundary = (
            result.units_done >= result.units_expected
            and result.reason_code == status.REASON_OK
        )
        result.calls = budget.requests_made
        result.items_seen = recognized
        result.items_in_window = len(result.entries)
        result.status_override = status.OK if result.units_done == result.units_expected else status.FAIL
        result.comment = f"items_seen={recognized}; items_in_window={result.items_in_window}"
        if rate_limit_retries:
            result.comment += f"; rate_limit_retries={rate_limit_retries}"
        return result


def _records_from(payload):
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ("victims", "data", "results", "items"):
            if isinstance(payload.get(key), list):
                return payload[key]
    return None


def _entry_from_record(record, spec: SourceSpec, country: str) -> RawEntry | None:
    if not isinstance(record, dict):
        return None

    organisation = _victim_name(_first_field(record, FIELD_ALIASES["organisation"]))
    if organisation.strip().lower() in {"[redacted]", "redacted", "unknown", "n/a"}:
        return None
    published = parse_date(_first_field(record, FIELD_ALIASES["date"]))
    if not organisation or not published:
        return None

    group = _first_field(record, FIELD_ALIASES["group"])
    record_country = (_first_field(record, FIELD_ALIASES["country"]) or country).upper()[:2]
    location = COUNTRY_TO_LOCATION.get(record_country, spec.location_rule)
    title = f"{organisation} revendiqué par {group}" if group else organisation

    source_metadata = {
        "group": group,
        "discovered": _first_field(record, ["discovered", "discovered_date"]),
        # Une date de publication n'est pas une date d'attaque : seuls les
        # champs explicitement sémantisés attackdate/attack_date sont retenus.
        "attackdate": _first_field(record, ["attackdate", "attack_date"]),
        "website": _first_field(record, ["website"]),
        "claim_url": _first_field(record, ["post_url", "claim_url"]),
        "sector_raw": _first_field(record, FIELD_ALIASES["sector"]),
    }

    return RawEntry(
        title=title,
        url=_normalise_url(_first_field(record, FIELD_ALIASES["url"])),
        published=published,
        summary=f"Groupe : {group}" if group else "",
        organisation=organisation,
        sector=_first_field(record, FIELD_ALIASES["sector"]),
        location=location,
        threat=config.THREAT_RANSOMWARE,
        source_metadata=source_metadata,
    )
