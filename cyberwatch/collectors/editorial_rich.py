"""Generic collector adapter that adds evidence-first rich facts to editorial sources."""
from __future__ import annotations

from ..rich_facts import enrich_provenance
from .feed import FeedCollector


def apply_rich_extractor(entry, extractor, *, source_id: str) -> None:
    text = "\n".join(part for part in (entry.title, entry.summary, entry.content) if part)
    rich = extractor(text)
    if not rich:
        return
    item_id = str(getattr(entry, "source_item_id", "") or getattr(entry, "native_id", "") or "")
    metadata = dict(entry.source_metadata or {})
    metadata["rich_facts"] = enrich_provenance(rich, source_id=source_id, item_id=item_id)
    entry.source_metadata = metadata


class EditorialRichFeedCollector(FeedCollector):
    """Feed collector with an overridable rich-facts extraction hook."""

    source_id = ""

    def extract_rich_facts(self, text: str) -> dict | None:
        return None

    def collect(self, client, spec, window):
        result = super().collect(client, spec, window)
        source_id = self.source_id or getattr(spec, "source_id", "")
        for entry in result.entries:
            apply_rich_extractor(entry, self.extract_rich_facts, source_id=source_id)
        return result
