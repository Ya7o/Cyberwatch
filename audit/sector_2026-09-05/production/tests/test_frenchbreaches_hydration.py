from cyberwatch import config, status
from cyberwatch.collectors.base import SourceSpec, Window
from cyberwatch.collectors.feed import FeedCollector
from cyberwatch.http import Budget, FetchResult


RSS = """<?xml version="1.0"?><rss version="2.0"><channel>
<item><title>Exemple SA</title><link>https://frenchbreaches.test/alerte/x</link>
<guid>x</guid><pubDate>Sun, 16 Aug 2026 10:00:00 +0000</pubDate>
<description>Fuite signalée.</description></item></channel></rss>"""


class Client:
    def __init__(self, detail_ok=True):
        self.detail_ok = detail_ok
        self.budget = Budget(10, 60, "test")

    def source_budget(self):
        return self.budget

    def fetch(self, url, budget=None, headers=None):
        target = budget or self.budget
        target.consume()
        if "feed.xml" in url:
            return FetchResult(True, url, status_code=200, text=RSS)
        if self.detail_ok:
            return FetchResult(True, url, status_code=200, text="<html><body>Secteur Transport 1 023 victimes Données compromises emails</body></html>")
        return FetchResult(False, url, status_code=503, reason_code=status.REASON_HTTP_ERROR)


def _spec():
    return SourceSpec(
        source_id="FRENCHBREACHES", layer=config.LAYER_CORE, zone=config.LOC_FRANCE,
        start_url="https://frenchbreaches.test/", collector="feed",
        default_threat=config.THREAT_LEAK,
        params={"feed_url": "https://frenchbreaches.test/feed.xml", "feed_has_no_pagination": True},
    )


def test_detail_frenchbreaches_hydrate_content_sans_changer_enumeration():
    result = FeedCollector().collect(Client(), _spec(), Window("2026-08-01", "2026-08-16"))
    assert result.resolve()[0] == status.OK
    assert len(result.entries) == 1
    assert "1 023 victimes" in result.entries[0].content
    assert "details_hydrates=1/1" in result.comment


def test_echec_detail_reste_non_bloquant():
    result = FeedCollector().collect(Client(detail_ok=False), _spec(), Window("2026-08-01", "2026-08-16"))
    assert result.resolve()[0] == status.OK
    assert len(result.entries) == 1
    assert result.entries[0].content == ""
    assert "details_hydrates=0/1" in result.comment
