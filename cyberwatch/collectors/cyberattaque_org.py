"""Collecteur WordPress dédié à Cyberattaque.org."""
from __future__ import annotations
from .. import status
from ..normalize import clean_organisation
from .wordpress import WordPressCollector

class CyberattaqueOrgCollector(WordPressCollector):
    name = "cyberattaque_org"
    def collect(self, client, spec, window):
        result = super().collect(client, spec, window)
        for entry in result.entries:
            entry.organisation = clean_organisation(entry.title.split(":", 1)[0]) or "Inconnu"
        result.items_seen = len(result.entries)
        result.units_done = len(result.entries)
        result.status_override = status.OK if result.entries else status.FAIL
        if not result.entries and result.reason_code == status.REASON_OK:
            result.reason_code = status.REASON_PARSE_ERROR
        result.comment = f"items_seen={result.items_seen}; items_in_window={len(result.entries)}"
        return result
