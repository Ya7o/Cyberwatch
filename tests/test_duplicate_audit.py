from cyberwatch import config
from cyberwatch.duplicate_audit import (
    DUPLICATE_CANDIDATE_CONCATENATION,
    DUPLICATE_CANDIDATE_PERMUTATION,
    RISK_FALSE_MERGE,
    RISK_MISSED_DUPLICATE,
    compute_candidate_signals,
    find_audit_candidates,
    find_daily_llm_candidates,
    find_duplicate_candidates,
)


def test_included_name_is_reported_when_all_strict_conditions_match(make_item):
    items = [
        make_item(source="A", org="Biosynex", published="2026-08-06", url="https://a", threat="Fuite de données"),
        make_item(source="B", org="Biosynex France", published="2026-08-08", url="https://b", threat="Fuite de données"),
    ]
    candidates = find_duplicate_candidates(items)
    assert len(candidates) == 1
    assert candidates[0].days_apart == 2
    assert candidates[0].reason_code == "DUPLICATE_CANDIDATE_NAME_CONTAINMENT"


def test_unknown_threat_is_not_required_for_compatibility(make_item):
    items = [
        make_item(source="A", org="Globex", url="https://a", threat=config.THREAT_UNKNOWN),
        make_item(source="B", org="Globex France", url="https://b", threat="Fuite de données"),
    ]
    assert len(find_duplicate_candidates(items)) == 1


def test_different_known_threats_are_still_reported(make_item):
    items = [
        make_item(source="A", org="Biosynex", url="https://a", threat="Intrusion"),
        make_item(source="B", org="Biosynex France", url="https://b", threat="Fuite de données"),
    ]
    assert len(find_duplicate_candidates(items)) == 1


def test_generic_institutional_names_remain_auditable(make_item):
    items = [
        make_item(source="A", org="Service de santé", url="https://a"),
        make_item(source="B", org="Service de santé de Paris", url="https://b"),
    ]
    candidates = find_duplicate_candidates(items)
    assert len(candidates) == 1
    assert candidates[0].short.Organisation_Raw == "Service de santé"


def test_generic_word_in_long_name_does_not_hide_candidate(make_item):
    items = [
        make_item(source="A", org="Sapeurs pompiers", url="https://a"),
        make_item(source="B", org="Fédération des sapeurs pompiers", url="https://b"),
    ]
    assert len(find_duplicate_candidates(items)) == 1


def test_same_source_or_date_over_fourteen_days_is_excluded(make_item):
    same_source = [
        make_item(source="A", org="Globex", url="https://a"),
        make_item(source="A", org="Globex France", url="https://b"),
    ]
    late = [
        make_item(source="A", org="Globex", published="2026-03-01", url="https://a"),
        make_item(source="B", org="Globex France", published="2026-03-16", url="https://b"),
    ]
    assert find_duplicate_candidates(same_source) == []
    assert find_duplicate_candidates(late) == []


def test_realistic_sub_entities_remain_only_candidates_not_merges(make_item):
    items = [
        make_item(source="A", org="City Pro", url="https://a"),
        make_item(source="B", org="City Pro Marionneau", url="https://b"),
    ]
    candidates = find_duplicate_candidates(items)
    assert len(candidates) == 1
    assert candidates[0].short.Organisation_Raw == "City Pro"


def test_exact_concatenation_is_reported(make_item):
    """Même principe que « france casse » / « francecasse » (désormais
    résolu par un alias, cf. data/organisation_aliases.csv) : mêmes lettres,
    espace en moins, non couvert par l'inclusion de mots (nombre de mots
    différent, pas de sous-séquence contiguë)."""
    items = [
        make_item(source="A", org="Globex Alpha", published="2026-08-16", url="https://a"),
        make_item(source="B", org="GlobexAlpha", published="2026-08-16", url="https://b"),
    ]
    candidates = find_duplicate_candidates(items)
    assert len(candidates) == 1
    assert candidates[0].reason_code == DUPLICATE_CANDIDATE_CONCATENATION


def test_exact_permutation_is_reported(make_item):
    """Même principe que « cravero motoculture » / « motoculture cravero »
    (désormais résolu par un alias) : mêmes mots, ordre différent, non
    couvert par l'inclusion de mots (même longueur)."""
    items = [
        make_item(source="A", org="Solutions Globex", published="2026-08-16", url="https://a"),
        make_item(source="B", org="Globex Solutions", published="2026-08-16", url="https://b"),
    ]
    candidates = find_duplicate_candidates(items)
    assert len(candidates) == 1
    assert candidates[0].reason_code == DUPLICATE_CANDIDATE_PERMUTATION


def test_identical_source_url_is_not_reported_as_false_merge(make_item):
    items = [
        make_item(source="RANSOMWARE_LIVE", org="Voyages Robin", published="2026-02-07", url="https://claim/1"),
        make_item(source="RANSOMWARE_LIVE", org="Voyages Robin", published="2026-02-08", url="https://claim/1"),
    ]
    assert [c for c in find_audit_candidates(items) if c.risk_type == RISK_FALSE_MERGE] == []


def test_same_source_different_urls_remain_auditable(make_item):
    items = [
        make_item(source="BONJOURLAFUITE", org="Relais Colis", published="2026-01-12", url="https://a/1"),
        make_item(source="BONJOURLAFUITE", org="Relais Colis", published="2026-01-15", url="https://a/2"),
    ]
    candidates = [c for c in find_audit_candidates(items) if c.risk_type == RISK_FALSE_MERGE]
    assert len(candidates) == 1


# --------------------------------------------------------------------------
# Filet quotidien LLM (§Lot 1/2/17) : signaux et périmètre de candidats
# --------------------------------------------------------------------------


def test_candidate_generation_typographic(make_item):
    """« Zorglub Consulting » / « ZorglubConsulting » : concaténation exacte,
    pas déjà résolue par un alias statique — doit produire un candidat avec
    `compact_match=True`."""
    new_item = make_item(source="A", org="Zorglub Consulting", published="2026-08-01", url="https://a")
    historical = make_item(source="B", org="ZorglubConsulting", published="2026-01-01", url="https://b")

    candidates = find_daily_llm_candidates([new_item], [new_item, historical])
    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.risk_type == RISK_MISSED_DUPLICATE
    assert candidate.signals.compact_match is True
    assert candidate.signals.fuzzy_score == 1.0


def test_candidate_generation_acronym(make_item):
    """« FFT » / « Fédération Française de Test » : acronyme exact déterministe
    (les mots-outils « de » ne comptent pas), non couvert par un alias."""
    new_item = make_item(source="A", org="FFT", published="2026-08-01", url="https://a")
    historical = make_item(
        source="B", org="Fédération Française de Test", published="2026-01-01", url="https://b",
    )

    candidates = find_daily_llm_candidates([new_item], [new_item, historical])
    assert len(candidates) == 1
    assert candidates[0].signals.acronym_match is True


def test_candidate_generation_fuzzy_false_positive(make_item):
    """Le fuzzy peut générer un candidat entre deux fédérations sportives
    manifestement distinctes (préfixe massif commun) : c'est le comportement
    voulu (§Lot 1, LOT0 FF_VOILE_VS_VOLLEY). Ce signal seul ne doit jamais
    être confondu avec une preuve structurelle forte : aucun `strong_signal`
    n'est levé, seul `fuzzy_score` l'est — la décision d'identité reste
    entièrement du ressort du LLM (jamais de cette fonction)."""
    left = make_item(source="A", org="Fédération Française de Voile", published="2026-08-01", url="https://a")
    right = make_item(source="B", org="Fédération Française de Volley", published="2026-01-01", url="https://b")

    signals = compute_candidate_signals(left, right)
    assert signals.fuzzy_score > 0.5
    assert signals.strong_signal_count == 0
    assert signals.compact_match is False
    assert signals.token_permutation is False
    assert signals.containment is False
    assert signals.acronym_match is False

    candidates = find_daily_llm_candidates([left], [left, right])
    assert len(candidates) == 1
    assert candidates[0].signals.strong_signal_count == 0


def test_candidate_generation_skips_pairs_already_resolved_deterministically(make_item):
    """Une paire déjà unifiée par un alias statique (`organisation_aliases.csv`)
    n'a aucune raison d'être envoyée au LLM : le moteur déterministe reste la
    première ligne (§Lot 2)."""
    new_item = make_item(source="A", org="DGFiP", published="2026-08-01", url="https://a")
    historical = make_item(
        source="B", org="Direction générale des Finances publiques",
        published="2026-01-01", url="https://b",
    )
    assert find_daily_llm_candidates([new_item], [new_item, historical]) == []


def test_candidate_generation_bounded_per_new_item(make_item):
    """Au plus `max_candidates_per_item` candidats retenus par nouvel item,
    même si beaucoup de paires plausibles existent (§Lot 1)."""
    new_item = make_item(source="A", org="Globex Holding", published="2026-08-10", url="https://new")
    historical = [
        make_item(
            source="B", org=f"Globex Holding {suffix}",
            published="2026-01-01", url=f"https://h{index}",
        )
        for index, suffix in enumerate(["Alpha", "Beta", "Gamma", "Delta", "Epsilon", "Zeta", "Eta"])
    ]
    candidates = find_daily_llm_candidates(
        [new_item], [new_item, *historical], max_candidates_per_item=3,
    )
    assert len(candidates) <= 3


def test_candidate_generation_no_candidate_for_unrelated_items(make_item):
    left = make_item(source="A", org="Globex Corp", published="2026-08-01", url="https://a")
    right = make_item(source="B", org="Ministère de la Culture", published="2026-08-01", url="https://b")
    assert find_daily_llm_candidates([left], [left, right]) == []


def test_dedup_identity_benchmark_on_regression_corpus():
    """§Lot 0/16 — critère d'acceptation #12 : 0 faux merge sur le corpus."""
    import json
    from pathlib import Path

    from cyberwatch.duplicate_audit import dedup_identity_benchmark

    corpus_path = Path(__file__).resolve().parent / "fixtures" / "dedup_identity_cases.json"
    cases = json.loads(corpus_path.read_text(encoding="utf-8"))["cases"]

    result = dedup_identity_benchmark(cases)
    assert result["known_nonduplicate_false_merge_count"] == 0, result["known_nonduplicate_false_merge_cases"]
    assert result["known_duplicate_recall_total"] > 0
    assert result["known_duplicate_recall_hits"] == result["known_duplicate_recall_total"]
