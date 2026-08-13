"""Collecteur déterministe de l'archive FrenchBreaches."""
from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urljoin

from .. import status
from ..normalize import clean_organisation, parse_date
from .base import CollectResult, Collector, RawEntry, SourceSpec, Window


class _ArchiveParser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url, self.entries, self.date = base_url, [], ""
        self.in_time = False; self.time = []; self.href = ""; self.label = []
        self.in_h2 = False; self.heading = []; self.alert_section = False

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "h2": self.in_h2, self.heading = True, []
        elif tag.lower() == "time": self.in_time, self.time = True, []
        elif tag.lower() == "a":
            self.href = next((v for k, v in attrs if k.lower() == "href"), "") or ""
            self.label = []

    def handle_data(self, data):
        if self.in_h2: self.heading.append(data)
        elif self.in_time: self.time.append(data)
        elif self.href: self.label.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "h2":
            self.in_h2 = False
            title = " ".join(self.heading).lower()
            if "alertes" in title and "fuite" in title: self.alert_section = True
            elif "blog" in title: self.alert_section = False
        elif tag.lower() == "time":
            self.in_time = False; self.date = parse_date(" ".join(self.time))
        elif tag.lower() == "a":
            title = " ".join(self.label).strip()
            org = clean_organisation(title)
            if self.alert_section and self.date and org:
                self.entries.append(RawEntry(title=title, organisation=org,
                    published=self.date, url=urljoin(self.base_url, self.href)))
            self.href = ""; self.label = []


def parse_archive(html: str, base_url: str) -> list[RawEntry]:
    parser = _ArchiveParser(base_url); parser.feed(html or ""); parser.close()
    return parser.entries


class FrenchBreachesCollector(Collector):
    name = "frenchbreaches"
    def collect(self, client, spec: SourceSpec, window: Window) -> CollectResult:
        budget = client.source_budget(); result = CollectResult(access_method="frenchbreaches-archive")
        response = client.fetch(spec.start_url, budget); result.calls = budget.requests_made
        if not response.ok:
            result.status_override = status.FAIL; result.reason_code = response.reason_code; return result
        seen = parse_archive(response.text, spec.start_url)
        if not seen:
            result.status_override = status.FAIL; result.reason_code = status.REASON_PARSE_ERROR; return result
        result.entries = [entry for entry in seen if window.contains(entry.published)]
        result.units_done = len(result.entries); result.status_override = status.OK
        result.comment = f"items_seen={len(seen)}; items_in_window={len(result.entries)}"
        # runner reads this explicit number, unlike the iterable population.
        result.items_seen = len(seen)
        return result
