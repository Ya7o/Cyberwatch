"""Collecteur WordPress dédié à la rubrique Numérique de Kwezi."""
from __future__ import annotations
from .. import status
from .wordpress import WordPressCollector

class KweziCollector(WordPressCollector):
    name = "kwezi"
    def collect(self, client, spec, window):
        result = super().collect(client, spec, window)
        if result.items_seen is None:
            result.items_seen = len(result.entries)
        if result.items_in_window is None:
            result.items_in_window = len(result.entries)
        # Une réponse WordPress valide mais vide est un zéro vérifié, pas une
        # indisponibilité de la source.
        result.status_override = status.OK if result.reason_code == status.REASON_OK else status.FAIL
        result.comment = (
            f"articles_seen={result.items_seen}; "
            f"articles_in_window={result.items_in_window}"
        )
        return result
