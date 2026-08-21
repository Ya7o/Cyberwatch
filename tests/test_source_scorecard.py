from cyberwatch.source_scorecard import build_scorecard, markdown


def _item(source, item_id, day, threat="Fuite de données", sector="Santé", location="France métropolitaine"):
    return {
        "Item_ID": item_id,
        "Source_ID": source,
        "Published_Date": day,
        "Event_Date": "",
        "Organisation_Key": item_id,
        "Threat": threat,
        "Sector": sector,
        "Location": location,
    }


def _incident(incident_id, day, sources, sector="Santé", threat="Fuite de données", location="France métropolitaine"):
    return {
        "Incident_ID": incident_id,
        "Date": day,
        "Sources": sources,
        "Secteur": sector,
        "Menace": threat,
        "Localisation": location,
    }


def test_scorecard_measures_reliability_exclusivity_and_unknowns():
    payload = build_scorecard(
        items=[
            _item("A", "a1", "2026-08-20"),
            _item("A", "a2", "2026-08-19", sector="Inconnu"),
            _item("B", "b1", "2026-08-01", location="Inconnu"),
        ],
        incidents=[
            _incident("i1", "2026-08-20", "A"),
            _incident("i2", "2026-08-19", "A | B"),
            _incident("i3", "2026-08-01", "B", location="Inconnu"),
        ],
        run_sources=[
            {"Run_ID": "r1", "As_Of": "2026-08-20", "Source_ID": "A", "Status": "OK", "Calls": "2", "Items_collected": "2", "Duration_s": "4"},
            {"Run_ID": "r2", "As_Of": "2026-08-21", "Source_ID": "A", "Status": "OK", "Calls": "2", "Items_collected": "2", "Duration_s": "6"},
            {"Run_ID": "r2", "As_Of": "2026-08-21", "Source_ID": "B", "Status": "FAIL", "Calls": "4", "Items_collected": "0", "Duration_s": "8"},
        ],
        snapshot={"As_Of": "2026-08-21T12:00:00+04:00", "Run_ID": "r2"},
        active_source_ids=["A", "B"],
        recent_runs=10,
    )

    rows = {row["source_id"]: row for row in payload["sources"]}
    assert rows["A"]["reliability_pct"] == 100.0
    assert rows["A"]["exclusive_incidents"] == 1
    assert rows["A"]["corroborated_incidents"] == 1
    assert rows["A"]["sector_unknown_pct"] == 50.0
    assert rows["A"]["freshness_days"] == 1
    assert rows["B"]["reliability_pct"] == 0.0
    assert "reliability_below_80pct" in rows["B"]["warnings"]
    assert rows["B"]["location_unknown_pct"] == 100.0
    assert payload["coverage"]["unknown_location_pct"] == 33.3


def test_scorecard_is_order_independent():
    items = [_item("A", "a1", "2026-08-20"), _item("A", "a2", "2026-08-19")]
    incidents = [_incident("i1", "2026-08-20", "A"), _incident("i2", "2026-08-19", "A")]
    runs = [
        {"Run_ID": "r1", "As_Of": "2026-08-20", "Source_ID": "A", "Status": "OK", "Calls": "1", "Items_collected": "1", "Duration_s": "1"},
        {"Run_ID": "r2", "As_Of": "2026-08-21", "Source_ID": "A", "Status": "OK", "Calls": "1", "Items_collected": "1", "Duration_s": "1"},
    ]
    kwargs = dict(snapshot={"As_Of": "2026-08-21", "Run_ID": "r2"}, active_source_ids=["A"], recent_runs=10)
    left = build_scorecard(items=items, incidents=incidents, run_sources=runs, **kwargs)
    right = build_scorecard(items=list(reversed(items)), incidents=list(reversed(incidents)), run_sources=list(reversed(runs)), **kwargs)
    assert left == right


def test_markdown_is_compact_and_explains_index():
    payload = build_scorecard(
        items=[_item("A", "a1", "2026-08-20")],
        incidents=[_incident("i1", "2026-08-20", "A")],
        run_sources=[],
        snapshot={"As_Of": "2026-08-21", "Run_ID": "r1"},
        active_source_ids=["A"],
    )
    text = markdown(payload)
    assert "### Source scorecard" in text
    assert "| A |" in text
    assert "ne certifie" in text
