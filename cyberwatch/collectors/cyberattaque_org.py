"""Collecteur WordPress dédié à Cyberattaque.org."""
from __future__ import annotations
import re
from .. import status
from ..normalize import clean_organisation
from .wordpress import WordPressCollector

_ORG_PREFIX = re.compile(
    r"^(.+?)\s+(?:touch[ée]e?|victime|cibl[ée]e?|frapp[ée]e?|pirat[ée]e?|"
    r"conteste|alerte|au cœur|sous la menace)\b", re.I
)

def organisation_from_title(title: str) -> str:
    head = (title or "").split(":", 1)[0].strip()
    match = _ORG_PREFIX.match(head)
    return clean_organisation(match.group(1) if match else head)

class CyberattaqueOrgCollector(WordPressCollector):
    name = "cyberattaque_org"
    def collect(self, client, spec, window):
        result = super().collect(client, spec, window)
        for entry in result.entries:
            entry.organisation = organisation_from_title(entry.title) or "Inconnu"
        result.items_seen = len(result.entries)
        result.units_done = len(result.entries)
        result.status_override = status.OK if result.entries else status.FAIL
        if not result.entries and result.reason_code == status.REASON_OK:
            result.reason_code = status.REASON_PARSE_ERROR
        result.comment = f"items_seen={result.items_seen}; items_in_window={len(result.entries)}"
        return result
