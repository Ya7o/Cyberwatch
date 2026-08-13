"""Collecteur WordPress dédié à la rubrique Numérique de Kwezi."""
from __future__ import annotations
from .. import status
from .wordpress import WordPressCollector

class KweziCollector(WordPressCollector):
    name = "kwezi"
    def collect(self, client, spec, window):
        result = super().collect(client, spec, window)
        result.items_seen = len(result.entries)
        result.units_done = len(result.entries)
        result.status_override = status.OK if result.entries else status.FAIL
        if not result.entries and result.reason_code == status.REASON_OK:
            result.reason_code = status.REASON_PARSE_ERROR
        result.comment = f"articles_seen={result.items_seen}; items_in_window={len(result.entries)}"
        return result
