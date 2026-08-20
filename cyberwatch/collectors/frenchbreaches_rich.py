"""FrenchBreaches collector using the generic rich-facts platform.

The source stays RSS-based; only semantic publication is enriched. We deliberately
reuse the conservative deterministic extractor already exercised on Cyberattaque.org
instead of adding FrenchBreaches-specific truth rules.
"""
from __future__ import annotations

from .editorial_rich import EditorialRichFeedCollector
from .cyberattaque_rich import extract_rich_facts_from_text


class FrenchBreachesRichCollector(EditorialRichFeedCollector):
    name = "frenchbreaches_rich"
    source_id = "FRENCHBREACHES"

    def extract_rich_facts(self, text: str) -> dict | None:
        rich = extract_rich_facts_from_text(text)
        if not rich:
            return None
        rich = dict(rich)
        rich["engine"] = "generic-rich-facts"
        rich["source_adapter"] = "frenchbreaches"
        return rich
