import datetime as dt
import json

from cyberwatch import production, store
from cyberwatch.model import Incident


def test_corpus_metier_est_versionne_diversifie_et_au_vert():
    payload = json.loads(production.BUSINESS_CORPUS_PATH.read_text(encoding="utf-8"))
    kinds = {case["kind"] for case in payload["cases"]}

    assert payload["version"]
    assert len(payload["cases"]) >= 15
    assert kinds == {"scope", "location", "sector"}
    assert production.evaluate_business_corpus()["passed"] is True
    assert production.evaluate_dedup_corpus()["known_nonduplicate_false_merge_count"] == 0


def test_fiabilite_planifiee_ignore_les_runs_manuels_et_compte_la_serie():
    rows = [
        {"Trigger": "workflow_dispatch", "Overall_Status": "OK"},
        *({"Trigger": "schedule", "Overall_Status": "OK"} for _ in range(7)),
    ]
    result = production.scheduled_reliability(rows)

    assert result["observed"] == 7
    assert result["success_rate_pct"] == 100.0
    assert result["consecutive_successes"] == 7
    assert result["seven_run_proof_ready"] is True


def test_un_echec_planifie_casse_la_serie_et_le_taux():
    rows = [
        {"Trigger": "schedule", "Overall_Status": "OK"},
        {"Trigger": "schedule", "Overall_Status": "FAIL"},
        {"Trigger": "schedule", "Overall_Status": "OK"},
    ]
    result = production.scheduled_reliability(rows)

    assert result["success_rate_pct"] == 66.67
    assert result["consecutive_successes"] == 1
    assert result["seven_run_proof_ready"] is False


def test_fraicheur_est_strictement_inferieure_a_36_heures(monkeypatch):
    monkeypatch.setattr(store, "load_snapshot", lambda: {"As_Of": "2026-09-01T00:00:00+00:00"})
    monkeypatch.setattr(store, "load_production_metrics", lambda: [])
    monkeypatch.setattr(store, "load_run_log", lambda: [])

    just_before = production.health_payload(
        now=dt.datetime(2026, 9, 2, 11, 59, 59, tzinfo=dt.timezone.utc)
    )
    at_limit = production.health_payload(
        now=dt.datetime(2026, 9, 2, 12, 0, 0, tzinfo=dt.timezone.utc)
    )

    assert just_before["freshness"]["ok"] is True
    assert at_limit["freshness"]["ok"] is False
    assert at_limit["alert"] is True


def test_cibles_qualite_declenchent_une_alerte_sans_fausser_les_valeurs(monkeypatch):
    monkeypatch.setattr(store, "load_snapshot", lambda: {"As_Of": "2026-09-01T00:00:00+00:00"})
    monkeypatch.setattr(store, "load_run_log", lambda: [])
    monkeypatch.setattr(store, "load_incidents", lambda: [
        Incident(Secteur="Inconnu" if index < 4 else "Santé", Localisation="Inconnu" if index == 0 else "France métropolitaine")
        for index in range(20)
    ])
    monkeypatch.setattr(store, "load_production_metrics", lambda: [{
        "Published": "true",
        "Sector_Unknown_Pct": "20.00",
        "Location_Unknown_Pct": "5.00",
        "Potential_Duplicate_Pairs": "2",
        "Potential_Duplicate_Rate_Pct": "7.41",
        "Corpus_False_Positive_Rate_Pct": "0",
        "Corpus_False_Negatives": "0",
        "Corpus_Classification_Errors": "0",
        "Dedup_Known_False_Merges": "0",
        "Duration_s": "12.3",
        "Requests": "9",
        "LLM_Calls": "1",
        "LLM_Cost_USD": "0.001",
    }])

    result = production.health_payload(
        now=dt.datetime(2026, 9, 1, 1, 0, tzinfo=dt.timezone.utc)
    )

    assert result["quality"]["sector_unknown_pct"] == 20.0
    assert result["quality"]["location_unknown_pct"] == 5.0
    assert len(result["alert_reasons"]) == 2
    assert result["performance"]["llm_cost_usd"] == 0.001


def test_upsert_metrique_est_idempotent(tmp_path):
    path = tmp_path / "production_metrics.csv"
    store.upsert_production_metric({"Run_ID": "RUN-1", "Duration_s": "1"}, path)
    store.upsert_production_metric({"Run_ID": "RUN-1", "Duration_s": "2"}, path)

    assert store.load_production_metrics(path) == [{
        column: ("RUN-1" if column == "Run_ID" else "2" if column == "Duration_s" else "")
        for column in store.PRODUCTION_METRIC_COLUMNS
    }]


def test_payload_dashboard_reste_deterministe_et_lie_au_run(monkeypatch):
    monkeypatch.setattr(store, "load_production_metrics", lambda: [
        {"Run_ID": "OLD", "Published": "true", "Sector_Unknown_Pct": "1"},
        {
            "Run_ID": "RUN-2", "Published": "true",
            "Sector_Unknown_Pct": "18.5", "Location_Unknown_Pct": "4.5",
            "Duration_s": "12", "LLM_Cost_USD": "0.002",
        },
    ])
    monkeypatch.setattr(store, "load_incidents", lambda: [Incident(Secteur="Santé", Localisation="France métropolitaine")])
    run_log = [{"Run_ID": "RUN-2", "Trigger": "schedule", "Overall_Status": "OK"}]

    payload = production.snapshot_payload(run_log, "RUN-2")

    assert payload["quality"]["sector_unknown_pct"] == 0.0
    assert payload["quality"]["location_unknown_pct"] == 0.0
    assert payload["performance"]["llm_cost_usd"] == 0.002
    assert payload["scheduled_reliability"]["observed"] == 1
    assert "age_hours" not in payload
    assert payload["quality"]["missed_duplicate_candidate_pairs"] is None


def test_dedup_quality_counts_separe_les_quatre_categories(make_item):
    weak_left = make_item(source="A", org="Weak Org", published="2026-08-01", url="https://w/a")
    weak_right = make_item(source="B", org="Weak Org", published="2026-08-01", url="https://w/b")
    weak = production.dedup_quality_counts([weak_left, weak_right])
    assert weak["weak_merge_review_pairs"] == 1
    assert weak["missed_duplicate_candidate_pairs"] == 0

    missed_left = make_item(source="A", org="Frères Toque", published="2026-08-01", url="https://m/a")
    missed_right = make_item(source="B", org="FrèresToque", published="2026-08-01", url="https://m/b")
    missed = production.dedup_quality_counts([missed_left, missed_right])
    assert missed["missed_duplicate_candidate_pairs"] == 1
    assert missed["weak_merge_review_pairs"] == 0

    veto_left = make_item(source="A", source_item_id="one", org="Veto Org",
                          published="2026-08-01", url="https://v/a")
    veto_right = make_item(source="A", source_item_id="two", org="Veto Org",
                           published="2026-08-01", url="https://v/b")
    pair = "|".join(sorted((veto_left.Item_ID, veto_right.Item_ID)))
    unresolved = production.dedup_quality_counts(
        [veto_left, veto_right],
        incident_decision_rows=[{
            "Pair_Key": pair,
            "Left_Item_ID": veto_left.Item_ID,
            "Right_Item_ID": veto_right.Item_ID,
            "Decision": "SAME",
        }],
        dedup_review_rows=[{
            "pair_key": pair,
            "left": veto_left.Item_ID,
            "right": veto_right.Item_ID,
            "status": "SAME_NOT_GROUPED",
        }],
    )
    assert unresolved["validated_same_not_grouped_pairs"] == 1
    assert unresolved["pending_review_pairs"] == 1


def test_metric_row_publie_les_nouveaux_compteurs(make_item):
    left = make_item(source="A", org="Frères Toque", published="2026-08-01", url="https://a")
    right = make_item(source="B", org="FrèresToque", published="2026-08-01", url="https://b")

    row = production.metric_row(
        run_id="RUN-DEDUP", as_of="2026-08-01T00:00:00+00:00", trigger="schedule",
        overall_status="OK", published=True, items=[left, right], incidents=[],
        duration_seconds=1, requests=0, llm_calls=0, llm_cost_usd=0,
    )

    assert row["Missed_Duplicate_Candidate_Pairs"] == 1
    assert row["Weak_Merge_Review_Pairs"] == 0
    assert row["Validated_Same_Not_Grouped_Pairs"] == 0
    assert row["Pending_Review_Pairs"] == 0


def test_metric_row_suit_les_nouvelles_qualifications_et_la_file(make_item):
    known = make_item(source="A", org="Connu", url="https://a")
    unknown = make_item(
        source="B", org="Nouveau", url="https://b",
        sector="Inconnu", threat="Inconnu", location="Inconnu",
    )
    row = production.metric_row(
        run_id="RUN-Q", as_of="2026-09-07T00:00:00+00:00", trigger="schedule",
        overall_status="OK", published=True, items=[known, unknown], incidents=[],
        duration_seconds=1, requests=0, llm_calls=0, llm_cost_usd=0,
        new_items=[unknown],
        source_facts_retry_summary={"queued_before": 3, "attempted": 2, "queued_after": 1},
    )
    assert row["New_Sector_Unknown_Pct"] == "100.00"
    assert row["New_Threat_Unknown_Pct"] == "100.00"
    assert row["New_Location_Unknown_Pct"] == "100.00"
    assert row["SourceFacts_Retry_Attempted"] == 2
