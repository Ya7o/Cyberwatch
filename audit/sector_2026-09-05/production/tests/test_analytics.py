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


def test_new_threat_sector_pair_requires_three_observations():
    rows = [
        _incident("2026-08-20", ident="a1", threat="DDoS", sector="Public"),
        _incident("2026-08-19", ident="a2", threat="DDoS", sector="Public"),
        _incident("2026-08-18", ident="a3", threat="DDoS", sector="Public"),
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


def _window(day_offsets, **kwargs):
    """Incidents datés en jours avant le 21/08/2026."""
    from datetime import date, timedelta
    anchor = date(2026, 8, 21)
    return [
        _incident((anchor - timedelta(days=offset)).isoformat(), ident=f"i{index}", **kwargs)
        for index, offset in enumerate(day_offsets)
    ]


def test_une_categorie_qui_suit_le_taux_de_base_n_est_pas_un_signal():
    """Une hausse qui suit la croissance globale mesure la couverture.

    Sans cette normalisation, « Fuite de données » (69 % de la fenêtre, +55 %
    pour un taux de base de +48 %) et « France métropolitaine » (93 %)
    ressortaient en tête des signaux avec une confiance élevée.
    """
    # Fenêtre courante : 40 incidents ; précédente : 20. Taux de base +100 %.
    rows = _window(range(0, 30), threat="Fuite de données")           # 30 courants
    rows += _window(range(0, 10), threat="Ransomware")                # 10 courants
    rows += _window(range(30, 45), threat="Fuite de données")         # 15 précédents
    rows += _window(range(30, 35), threat="Ransomware")               # 5 précédents
    for index, row in enumerate(rows):
        row["id"] = f"x{index}"
    payload = build_analytics(rows, as_of="2026-08-21")
    labels = {signal["label"] for signal in payload["signals"] if signal["window_days"] == 30}
    # « Fuite de données » pèse 75 % de la fenêtre : c'est la fenêtre elle-même.
    assert "Fuite de données" not in labels


def test_la_normalisation_ne_s_applique_pas_sans_taux_de_base_estimable():
    """Sur quelques incidents, l'écart observé est du bruit, pas un taux."""
    rows = _window([1, 2, 3, 4]) + _window([40])
    for index, row in enumerate(rows):
        row["id"] = f"y{index}"
    payload = build_analytics(rows, as_of="2026-08-21")
    assert any(signal["label"] == "Ransomware" for signal in payload["signals"])


def test_les_signaux_publient_leur_part_et_leur_taux_de_base():
    """La part et le taux de base sont la moitié de la lecture d'un signal."""
    rows = _window(range(0, 30), threat="Fuite de données") + _window(range(0, 12), threat="Ransomware")
    rows += _window(range(30, 45), threat="Fuite de données") + _window(range(30, 33), threat="Ransomware")
    for index, row in enumerate(rows):
        row["id"] = f"z{index}"
    payload = build_analytics(rows, as_of="2026-08-21")
    for signal in payload["signals"]:
        assert "share_pct" in signal and "base_rate_pct" in signal and "excess_points" in signal


def test_l_ampleur_ne_publie_jamais_de_somme():
    """Les volumes sont majoritairement revendiqués : une somme est indéfendable.

    Sur le jeu réel, elle vaudrait 1,58 milliard, dominée par une revendication
    à 600 millions sur 264 incidents documentés dont 36 seulement confirmés.
    """
    rows = [
        _incident("2026-08-20", ident="a"),
        _incident("2026-08-19", ident="b"),
        _incident("2026-08-18", ident="c"),
    ]
    rows[0]["facts"] = [{"affected_count": 100, "affected_unit": "people", "claim_status": "claimed"}]
    rows[1]["facts"] = [{"affected_count": 500, "affected_unit": "records", "claim_status": "confirmed"}]
    rows[2]["facts"] = [{"affected_count": 10_000_000, "affected_unit": "people", "claim_status": "unknown"}]
    exposure = build_analytics(rows, as_of="2026-08-21")["exposure"]
    assert exposure["documented"] == 3
    assert exposure["median"] == 500
    assert exposure["evidence"] == {"claimed": 1, "confirmed": 1, "unknown": 1}
    assert not any("sum" in key or "total_value" in key for key in exposure)


def test_le_perimetre_prioritaire_compare_le_silence_a_la_normale_observee():
    """À ~2 incidents/mois, « aucun incident » est l'état normal.

    Sans la normale observée en regard, un écart banal se lirait comme une
    accalmie — ou pire, une panne de collecte comme une absence d'incident.
    """
    rows = [
        _incident("2026-06-01", ident="f1", location="La Réunion"),
        _incident("2026-06-20", ident="f2", location="La Réunion"),
        _incident("2026-07-10", ident="f3", location="Mayotte"),
        _incident("2026-08-20", ident="m1", location="France métropolitaine"),
    ]
    focus = build_analytics(rows, as_of="2026-08-21", focus_locations=("La Réunion", "Mayotte"))["focus"]
    assert focus["incidents"] == 3
    assert focus["by_location"] == {"La Réunion": 2, "Mayotte": 1}
    assert focus["last_date"] == "2026-07-10"
    assert focus["days_since_last"] == 42
    assert focus["max_gap_days"] == 20
    # 42 jours de silence dépassent le maximum observé (20) : c'est signalé.
    assert focus["silence_is_unusual"] is True


def test_un_profil_de_menace_domine_par_une_source_est_marque_non_fiable():
    """Une source mono-thématique produit mécaniquement 100 % de sa thématique.

    Sur le jeu réel, Maurice/Madagascar/Seychelles/Comores affichent 100 % de
    ransomware parce que Ransomware.live est la seule source qui les couvre.
    Publier ce taux sans réserve en ferait un fait.
    """
    rows = [
        _incident(f"2026-08-{20 - index:02d}", ident=f"r{index}", location="Mayotte", sources=["RANSOMWARE_LIVE"])
        for index in range(5)
    ]
    focus = build_analytics(rows, as_of="2026-08-21", focus_locations=("La Réunion", "Mayotte"))["focus"]
    assert focus["profile"]["dominant_source_pct"] == 100.0
    assert focus["profile"]["threat_profile_reliable"] is False
