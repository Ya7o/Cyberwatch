"""Contrat fonctionnel V0 spécifique à BonjourLaFuite."""

from types import SimpleNamespace

from cyberwatch import config, runner, status
from cyberwatch.collectors.base import SourceSpec, Window
from cyberwatch.collectors.bonjourlafuite import BonjourLaFuiteCollector, parse_timeline


SPEC = SourceSpec(
    source_id="BONJOURLAFUITE",
    layer=config.LAYER_CORE,
    zone=config.LOC_FRANCE,
    start_url="https://bonjourlafuite.eu.org/",
    collector="autodetect",
    default_threat=config.THREAT_LEAK,
    location_rule=config.LOC_FRANCE,
    params={"title_is_organisation": True},
)


class FakeBudget:
    def __init__(self):
        self.requests_made = 0


class FakeClient:
    def __init__(self, *, html="", ok=True, status_code=200, reason_code=status.REASON_OK):
        self.budget = FakeBudget()
        self.response = SimpleNamespace(
            ok=ok,
            text=html,
            status_code=status_code,
            reason_code=reason_code,
        )

    def source_budget(self):
        return self.budget

    def fetch(self, url, budget):
        budget.requests_made += 1
        return self.response


HTML_TWO_ITEMS = """
<html><body>
  <section>
    <p>10 août 2026</p>
    <h2>🟢 Intermarché</h2>
    <p>Des données ont été exposées.</p>
    <a href="https://example.test/intermarche">Source</a>
  </section>
  <section>
    <p>9 août 2026</p>
    <h2>🔴 Société Exemple</h2>
    <a href="/source-exemple">Source</a>
  </section>
</body></html>
"""


def collect(html=HTML_TWO_ITEMS, start="2026-08-01", end="2026-08-31"):
    client = FakeClient(html=html)
    result = BonjourLaFuiteCollector().collect(client, SPEC, Window(start, end))
    return result


class TestRecognition:
    def test_bloc_reconnu_exige_date_valide_et_organisation_non_vide(self):
        html = """
        <p>10 août 2026</p><h2>🟢 Intermarché</h2>
        <p>date inconnue</p><h2>Organisation sans date</h2>
        <p>9 août 2026</p><h2></h2>
        """
        entries = parse_timeline(html, SPEC.start_url)

        assert len(entries) == 1
        assert entries[0].published == "2026-08-10"
        assert entries[0].organisation == "Intermarché"

    def test_source_associee_si_disponible(self):
        entries = parse_timeline(HTML_TWO_ITEMS, SPEC.start_url)
        assert entries[0].url == "https://example.test/intermarche"
        assert entries[1].url == "https://bonjourlafuite.eu.org/source-exemple"


class TestStatusV0:
    def test_items_seen_positif_donne_ok(self):
        result = collect()
        source_status, _ = result.resolve()

        assert source_status == status.OK
        assert len(result.entries) == 2
        assert result.units_done == 1
        assert result.units_expected == 1
        assert result.items_seen == 2
        assert result.items_in_window == 2
        assert result.reached_boundary is False

    def test_aucun_item_dans_la_fenetre_reste_ok(self):
        result = collect(start="2026-09-01", end="2026-09-30")
        source_status, _ = result.resolve()

        assert source_status == status.OK
        assert len(result.entries) == 2  # Items_seen : toute la page reconnue
        assert list(result.entries) == []  # rien à matérialiser hors fenêtre
        assert result.units_done == 1
        assert result.items_in_window == 0

    def test_page_lue_sans_item_reconnu_donne_fail(self):
        result = collect("<html><body><h1>Bonjour</h1></body></html>")
        source_status, _ = result.resolve()

        assert source_status == status.FAIL
        assert len(result.entries) == 0
        assert result.reason_code == status.REASON_PARSE_ERROR

    def test_erreur_http_donne_fail(self):
        client = FakeClient(
            ok=False,
            status_code=503,
            reason_code=status.REASON_HTTP_ERROR,
        )
        result = BonjourLaFuiteCollector().collect(
            client, SPEC, Window("2026-08-01", "2026-08-31")
        )
        source_status, _ = result.resolve()

        assert source_status == status.FAIL
        assert result.reason_code == status.REASON_HTTP_ERROR
        assert "HTTP 503" in result.comment

    def test_statut_ne_peut_jamais_etre_partial(self):
        cases = [
            collect(),
            collect(start="2026-09-01", end="2026-09-30"),
            collect("<html><body>aucun bloc</body></html>"),
        ]
        assert {case.resolve()[0] for case in cases} <= {status.OK, status.FAIL}


class TestRunnerMetrics:
    def test_items_seen_et_items_in_window_restent_distincts(self):
        client = FakeClient(html=HTML_TWO_ITEMS)
        context = runner.make_run_context(
            runner.MODE_CREATE,
            as_of="2026-08-13T12:00:00+04:00",
            target_start="2026-08-10",
            layers=[config.LAYER_CORE],
        )
        outcome, items, _ = runner.run_source(client, SPEC, context, {}, {}, {})

        assert outcome.status == status.OK
        assert outcome.items_seen == 2
        assert outcome.units_done == 1  # unité technique : lecture de timeline
        assert outcome.items_in_window == 1
        assert outcome.items_collected == 1
        assert len(items) == 1

    def test_item_reconnu_mais_non_collecte_reste_ok(self, monkeypatch):
        client = FakeClient(html=HTML_TWO_ITEMS)
        context = runner.make_run_context(
            runner.MODE_CREATE,
            as_of="2026-08-13T12:00:00+04:00",
            target_start="2026-08-01",
            layers=[config.LAYER_CORE],
        )
        monkeypatch.setattr(runner, "entry_to_item", lambda *args, **kwargs: None)

        outcome, items, _ = runner.run_source(client, SPEC, context, {}, {}, {})

        assert outcome.items_seen == 2
        assert outcome.items_collected == 0
        assert items == []
        assert outcome.status == status.OK
