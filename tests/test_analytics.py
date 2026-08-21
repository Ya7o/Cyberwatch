from cyberwatch.analytics import build_analytics


def _incident(day, *, ident, threat="Ransomware", sector="Santé", location="France métropolitaine", sources=None, org="Org"):
    return {
        "id": ident,
        "date": day,
        "threat": threat,
        "sector": sector,
        "location": location,
        "sources": sources or ["A"],
        "org": org,
    }


def test_acceleration_requires_real_delta_and_minimum_sample():
    rows = [
        _incident("2026-08-20", ident="a1"),
        _incident("2026-08-19", ident="a2"),
        _incident("2026-08-18", ident="a3"),
        _incident("2026-08-17", ident="a4"),
        _incident("2026-07-25", ident="b1"),
    ]
    payload = build_analytics(rows, as_of="2026-08-21")
    assert any(s["dimension"] == "threat" and s["label"] == "Ransomware" for s in payload["signals"])


def test_two_events_never_become_trend():
    rows = [_incident("2026-08-20", ident="a1"), _incident("2026-08-19", ident="a2")]
    payload = build_analytics(rows, as_of="2026-08-21")
    assert payload["signals"] == []


def test_new_threat_sector_pair_requires_two_observations():
    rows = [
        _incident("2026-08-20", ident="a1", threat="DDoS", sector="Public"),
        _incident("2026-08-19", ident="a2", threat="DDoS", sector="Public"),
    ]
    payload = build_analytics(rows, as_of="2026-08-21")
    assert any(s["kind"] == "new_pair" and "DDoS" in s["label"] for s in payload["signals"])


def test_confidence_improves_with_corroboration_and_complete_fields():
    rows = [
        _incident(f"2026-08-{20-i:02d}", ident=f"a{i}", sources=["A", "B"])
        for i in range(6)
    ]
    payload = build_analytics(rows, as_of="2026-08-21")
    signal = next(s for s in payload["signals"] if s["dimension"] == "threat")
    assert signal["confidence"]["score"] >= 50


def test_windows_are_deterministic_and_include_period_comparison():
    rows = [_incident("2026-08-20", ident="a"), _incident("2026-07-20", ident="b")]
    first = build_analytics(rows, as_of="2026-08-21")
    second = build_analytics(list(reversed(rows)), as_of="2026-08-21")
    assert first == second
    assert set(first["windows"]) == {"7", "30", "90", "365"}
