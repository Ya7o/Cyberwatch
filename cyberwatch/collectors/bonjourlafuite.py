"""Collecteur dédié à BonjourLaFuite — contrat fonctionnel V0."""

from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin

from .. import status
from ..normalize import clean_organisation, leading_decorative_marker, parse_date
from .base import CollectResult, Collector, RawEntry, SourceSpec, Window

_VIA_RE = re.compile(r"^via\b[:\s]*(.*)$", re.I)
_DATA_TYPES_RE = re.compile(r"^donn[ée]es?\s+concern[ée]es?\b[:\s]*(.*)$", re.I)


class _RecognizedEntries(list):
    def __init__(self, in_window: list[RawEntry], total_seen: int):
        super().__init__(in_window)
        self.total_seen = total_seen

    def __len__(self) -> int:
        return self.total_seen


class _BonjourHtmlParser(HTMLParser):
    """Parse la timeline sans dépendre des classes CSS.

    Les libellés ``Via`` et ``Données concernées`` peuvent être séparés de
    leur valeur par des balises HTML. Pour ``Données concernées``, la page
    expose aussi des listes de bulles successives : elles sont conservées
    individuellement jusqu'à la fin du bloc (source, date ou incident suivant)
    afin de ne jamais perdre les valeurs après la première bulle.
    """

    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.entries: list[RawEntry] = []
        self.pending_date = ""
        self.current: RawEntry | None = None
        self._in_h2 = False
        self._h2_parts: list[str] = []
        self._anchor_href = ""
        self._anchor_parts: list[str] = []
        self._extra_parts: list[str] = []
        self._pending_field: str | None = None
        self._collecting_data_types = False
        self._data_type_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs):
        lowered = tag.lower()
        if lowered == "h2":
            self._flush_data_types()
            self._in_h2 = True
            self._h2_parts = []
            self._pending_field = None
        elif lowered == "a":
            # Sur BonjourLaFuite, le lien « Source » clôt le bloc de bulles.
            self._flush_data_types()
            self._anchor_href = ""
            self._anchor_parts = []
            self._pending_field = None
            for key, value in attrs:
                if key.lower() == "href" and value:
                    self._anchor_href = value
                    break

    def handle_endtag(self, tag: str):
        lowered = tag.lower()
        if lowered == "h2":
            self._finish_heading()
        elif lowered == "a":
            self._finish_anchor()

    def handle_data(self, data: str):
        text = " ".join((data or "").replace("\xa0", " ").split())
        if not text:
            return
        if self._in_h2:
            self._h2_parts.append(text)
            return

        in_anchor = bool(self._anchor_href)
        if in_anchor:
            self._anchor_parts.append(text)

        parsed = parse_date(text)
        if parsed:
            self._flush_data_types()
            self.pending_date = parsed
            self._pending_field = None
            return
        if in_anchor or self.current is None:
            return

        self._extra_parts.append(text)

        via = _VIA_RE.match(text)
        if via:
            self._flush_data_types()
            value = via.group(1).strip()
            if value:
                self.current.source_metadata["via_raw"] = value
                self._pending_field = None
            else:
                self._pending_field = "via_raw"
            return

        data_types = _DATA_TYPES_RE.match(text)
        if data_types:
            self._flush_data_types()
            value = data_types.group(1).strip()
            if value:
                # Compatibilité avec l'ancien format sur une seule ligne :
                # source_facts applique alors le découpage historique.
                self.current.source_metadata["data_types_raw"] = value
                self._pending_field = None
            else:
                # Le site actuel rend chaque type dans une bulle distincte.
                self._collecting_data_types = True
                self._data_type_parts = []
                self._pending_field = None
            return

        if self._pending_field:
            self.current.source_metadata[self._pending_field] = text
            self._pending_field = None
            return

        if self._collecting_data_types:
            self._data_type_parts.append(text)

    def _flush_data_types(self) -> None:
        if not self._collecting_data_types:
            return
        if self.current is not None and self._data_type_parts:
            values: list[str] = []
            for value in self._data_type_parts:
                cleaned = " ".join(value.split()).strip(" .")
                if cleaned and cleaned not in values:
                    values.append(cleaned)
            if values:
                # Plusieurs valeurs successives correspondent au format en
                # bulles du site actuel : leurs limites sont significatives.
                # Une valeur unique reste sur le chemin historique via
                # data_types_raw afin de conserver la compatibilité des
                # anciens blocs textuels « noms, emails, téléphones ».
                if len(values) > 1:
                    self.current.source_metadata["data_types"] = values
                self.current.source_metadata["data_types_raw"] = " ; ".join(values)
        self._collecting_data_types = False
        self._data_type_parts = []

    def _finish_heading(self) -> None:
        self._flush_data_types()
        raw = " ".join(self._h2_parts).strip()
        self._in_h2 = False
        self._h2_parts = []
        self._pending_field = None
        self._flush_extra()

        organisation = clean_organisation(raw)
        if not self.pending_date or not organisation:
            self.current = None
            return

        entry = RawEntry(
            title=organisation,
            organisation=organisation,
            published=self.pending_date,
        )
        claim_status_raw = leading_decorative_marker(raw)
        if claim_status_raw:
            entry.source_metadata["claim_status_raw"] = claim_status_raw
        self.entries.append(entry)
        self.current = entry
        self.pending_date = ""

    def _flush_extra(self) -> None:
        if self.current is not None and self._extra_parts:
            self.current.summary = " ".join(self._extra_parts).strip()
        self._extra_parts = []
        self._pending_field = None

    def finalize(self) -> None:
        self._flush_data_types()
        self._flush_extra()

    def _finish_anchor(self) -> None:
        label = " ".join(self._anchor_parts).strip().lower()
        if self.current is not None and self._anchor_href and label.startswith("source"):
            resolved = urljoin(self.base_url, self._anchor_href)
            if not self.current.url:
                self.current.url = resolved
            urls = self.current.source_metadata.setdefault("source_urls", [])
            if resolved not in urls:
                urls.append(resolved)
        self._anchor_href = ""
        self._anchor_parts = []


def parse_timeline(html: str, base_url: str) -> list[RawEntry]:
    parser = _BonjourHtmlParser(base_url)
    parser.feed(html or "")
    parser.close()
    parser.finalize()
    return parser.entries


class BonjourLaFuiteCollector(Collector):
    name = "bonjourlafuite"

    def collect(self, client, spec: SourceSpec, window: Window) -> CollectResult:
        budget = client.source_budget()
        result = CollectResult(access_method="bonjourlafuite-html-v0")
        response = client.fetch(spec.start_url, budget)
        result.calls = budget.requests_made

        if not response.ok:
            result.status_override = status.FAIL
            result.reason_code = response.reason_code
            result.comment = (
                f"Lecture impossible: {response.reason_code}"
                + (f" (HTTP {response.status_code})" if response.status_code else "")
            )
            return result

        recognized = parse_timeline(response.text, spec.start_url)
        seen = len(recognized)
        if seen == 0:
            result.status_override = status.FAIL
            result.reason_code = status.REASON_PARSE_ERROR
            result.comment = "Page récupérée mais aucun bloc date + organisation reconnu"
            return result

        in_window = [entry for entry in recognized if window.contains(entry.published)]
        result.status_override = status.OK
        result.reason_code = status.REASON_OK
        result.entries = _RecognizedEntries(in_window, seen)
        result.items_seen = seen
        result.items_in_window = len(in_window)
        result.units_done = 1
        result.units_expected = 1
        result.comment = f"items_in_window={len(in_window)}"
        return result
