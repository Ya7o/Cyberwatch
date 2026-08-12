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

from .. import config, status
from ..normalize import parse_date
from .base import CollectResult, Collector, RawEntry, SourceSpec, Window

#: Codes pays du périmètre, tels qu'ils apparaissent dans l'API.
COUNTRY_TO_LOCATION = {
    "FR": config.LOC_FRANCE,
    "RE": config.LOC_REUNION,
    "YT": config.LOC_MAYOTTE,
    "MU": config.LOC_MAURICE,
    "MG": config.LOC_MADAGASCAR,
    "SC": config.LOC_SEYCHELLES,
    "KM": config.LOC_COMORES,
}

#: Modèles d'URL essayés, du plus précis au plus général.
ENDPOINT_TEMPLATES = [
    "https://api.ransomware.live/v2/countryvictims/{country}",
    "https://api.ransomware.live/countryvictims/{country}",
    "https://api.ransomware.live/v2/recentvictims",
    "https://api.ransomware.live/recentvictims",
]

#: Noms de champs rencontrés selon les versions de l'API.
FIELD_ALIASES = {
    "organisation": ["victim", "post_title", "company", "name", "title"],
    "date": ["attackdate", "attack_date", "published", "discovered", "date",
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


class RansomwareLiveCollector(Collector):
    """Énumère les victimes de rançongiciel des pays du périmètre."""

    name = "ransomware_live"

    def collect(self, client, spec: SourceSpec, window: Window) -> CollectResult:
        budget = client.source_budget()
        result = CollectResult(access_method="ransomware.live")

        countries = spec.params.get("countries") or list(COUNTRY_TO_LOCATION)
        result.units_expected = len(countries)

        working_template = None
        seen: set[tuple[str, str]] = set()

        for country in countries:
            if budget.exhausted:
                result.reason_code = status.REASON_BUDGET_SOURCE
                break

            templates = (
                [working_template] if working_template else ENDPOINT_TEMPLATES
            )
            fetched = False
            empty_country = False

            for template in templates:
                url = template.format(country=country)
                response = client.fetch(url, budget)
                if not response.ok:
                    # Une fois le bon point d'entrée connu, un 404 sur un pays
                    # signifie « aucune victime enregistrée », pas un échec de
                    # protocole : le pays a bien été interrogé.
                    if working_template and response.status_code == 404:
                        empty_country = True
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
                    if not window.contains(entry.published):
                        continue
                    signature = (entry.organisation.lower(), entry.published)
                    if signature in seen:
                        continue
                    seen.add(signature)
                    result.entries.append(entry)
                break

            if fetched or empty_country:
                result.units_done += 1
            elif working_template is None:
                # Aucun modèle d'URL ne répond : l'API n'est pas joignable.
                result.reason_code = status.REASON_HTTP_ERROR
                result.comment = "Aucun point d'entrée de l'API ransomware.live n'a répondu"
                break

            # Un point d'entrée global renvoie déjà toutes les victimes.
            if working_template and "{country}" not in working_template:
                result.units_done = result.units_expected
                break

        result.reached_boundary = (
            result.units_done >= result.units_expected
            and result.reason_code == status.REASON_OK
        )
        result.calls = budget.requests_made
        return result


def _records_from(payload):
    """Liste d'enregistrements, quelle que soit l'enveloppe renvoyée."""
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

    organisation = _first_field(record, FIELD_ALIASES["organisation"])
    published = parse_date(_first_field(record, FIELD_ALIASES["date"]))
    if not organisation or not published:
        return None

    group = _first_field(record, FIELD_ALIASES["group"])
    record_country = (
        _first_field(record, FIELD_ALIASES["country"]) or country
    ).upper()[:2]
    location = COUNTRY_TO_LOCATION.get(record_country, spec.location_rule)

    title = f"{organisation} revendiqué par {group}" if group else organisation

    return RawEntry(
        title=title,
        url=_first_field(record, FIELD_ALIASES["url"]),
        published=published,
        summary=f"Groupe : {group}" if group else "",
        organisation=organisation,
        sector=_first_field(record, FIELD_ALIASES["sector"]),
        location=location,
        threat=config.THREAT_RANSOMWARE,
    )
