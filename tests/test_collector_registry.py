import pytest

from cyberwatch import sources
from cyberwatch.collectors import get_collector
from cyberwatch.collectors.bonjourlafuite import BonjourLaFuiteCollector
from cyberwatch.collectors.cyberattaque_org import CyberattaqueOrgCollector
from cyberwatch.collectors.feed import FeedCollector
from cyberwatch.collectors.kwezi import KweziCollector
from cyberwatch.collectors.ransomware_live import RansomwareLiveCollector


def test_five_active_sources_route_to_their_declared_collector():
    expected = {
        "BONJOURLAFUITE": BonjourLaFuiteCollector,
        "FRENCHBREACHES": FeedCollector,
        "CYBERATTAQUE_ORG": CyberattaqueOrgCollector,
        "RANSOMWARE_LIVE": RansomwareLiveCollector,
        "KWEZI_NUMERIQUE": KweziCollector,
    }
    for spec in sources.active_sources():
        assert type(get_collector(spec.collector)) is expected[spec.source_id]


def test_frenchbreaches_uses_its_explicit_complete_rss_feed():
    spec = sources.by_id("FRENCHBREACHES")
    assert spec is not None
    assert spec.collector == "feed"
    assert spec.start_url == "https://frenchbreaches.com/feed.xml"
    assert spec.params["feed_url"] == spec.start_url


def test_unknown_collector_fails_fast():
    with pytest.raises(ValueError, match="Collecteur inconnu : collecteur_inexistant"):
        get_collector("collecteur_inexistant")
