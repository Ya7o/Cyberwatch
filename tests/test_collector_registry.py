import pytest

from cyberwatch import sources
from cyberwatch.collectors import get_collector
from cyberwatch.collectors.bonjourlafuite import BonjourLaFuiteCollector
from cyberwatch.collectors.cyberattaque_org import CyberattaqueOrgCollector
from cyberwatch.collectors.frenchbreaches import FrenchBreachesCollector
from cyberwatch.collectors.kwezi import KweziCollector
from cyberwatch.collectors.ransomware_live import RansomwareLiveCollector


def test_five_active_sources_route_to_their_dedicated_collector():
    expected = {
        "BONJOURLAFUITE": BonjourLaFuiteCollector,
        "FRENCHBREACHES": FrenchBreachesCollector,
        "CYBERATTAQUE_ORG": CyberattaqueOrgCollector,
        "RANSOMWARE_LIVE": RansomwareLiveCollector,
        "KWEZI_NUMERIQUE": KweziCollector,
    }
    for spec in sources.active_sources():
        assert type(get_collector(spec.collector)) is expected[spec.source_id]


def test_unknown_collector_fails_fast():
    with pytest.raises(ValueError, match="Collecteur inconnu : collecteur_inexistant"):
        get_collector("collecteur_inexistant")
