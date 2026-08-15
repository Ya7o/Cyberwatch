import pytest

from cyberwatch import config, sources
from cyberwatch.collectors import get_collector
from cyberwatch.collectors.bonjourlafuite import BonjourLaFuiteCollector
from cyberwatch.collectors.cyberattaque_org import CyberattaqueOrgCollector
from cyberwatch.collectors.feed import FeedCollector
from cyberwatch.collectors.ransomware_live import RansomwareLiveCollector
from cyberwatch.collectors.wordpress import WordPressCollector
from cyberwatch.collectors.veillellm import VeilleLlmCollector


def test_active_sources_route_to_their_declared_collector():
    expected = {
        "BONJOURLAFUITE": BonjourLaFuiteCollector,
        "FRENCHBREACHES": FeedCollector,
        "CYBERATTAQUE_ORG": CyberattaqueOrgCollector,
        "RANSOMWARE_LIVE": RansomwareLiveCollector,
        "KWEZI_NUMERIQUE": WordPressCollector,
        "MAYOTTE_HEBDO_NUMERIQUE": WordPressCollector,
        "JOURNAL_DE_MAYOTTE": WordPressCollector,
        "MAYOTTE_FM": WordPressCollector,
        "VEILLE_LLM": VeilleLlmCollector,
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


def test_source_ids_are_unique():
    ids = [spec.source_id for spec in sources.ALL_SOURCES]
    assert len(ids) == len(set(ids))


def test_every_source_declares_a_known_layer():
    known_layers = {layer for group in config.LAYER_GROUPS.values() for layer in group} | {
        config.LAYER_DISABLED
    }
    for spec in sources.ALL_SOURCES:
        assert spec.layer in known_layers, f"{spec.source_id}: couche inconnue ({spec.layer})"


def test_every_active_source_documents_protocol_and_success_test():
    for spec in sources.active_sources():
        assert spec.protocol, f"{spec.source_id}: protocole non documenté"
        assert spec.success_test, f"{spec.source_id}: test de succès non documenté"


def test_full_scan_budget_stays_within_run_limit():
    budget = sum(sources.expected_units(spec) for spec in sources.active_sources())
    assert budget <= config.MAX_REQUESTS_PER_RUN
