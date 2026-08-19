from scripts import enrich_legal_identity as worker


def test_zero_limit_processes_entire_legal_identity_queue():
    candidates = [("a", "A"), ("b", "B"), ("c", "C")]
    assert worker._select_candidates(candidates, 0) == candidates


def test_positive_limit_keeps_bounded_batches():
    candidates = [("a", "A"), ("b", "B"), ("c", "C")]
    assert worker._select_candidates(candidates, 2) == candidates[:2]


def test_worker_count_is_bounded(monkeypatch):
    monkeypatch.setenv("LEGAL_IDENTITY_WORKERS", "99")
    assert worker._workers() == 8
    monkeypatch.setenv("LEGAL_IDENTITY_WORKERS", "0")
    assert worker._workers() == 1


def test_duplicate_weak_siren_without_name_relation_is_rejected():
    rows = {
        "banque-alimentaire": {
            "Company_ID": "424761419",
            "Query_Name": "Banque Alimentaire",
            "Matched_Name": "VRANKEN POMMERY MONOPOLE",
            "Validated_Via": "legal_identity",
        },
        "vranken-pommery": {
            "Company_ID": "424761419",
            "Query_Name": "Vranken-Pommery",
            "Matched_Name": "VRANKEN POMMERY MONOPOLE",
            "Validated_Via": "legal_identity",
        },
        "ademi": {
            "Company_ID": "424761419",
            "Query_Name": "ADEMI",
            "Matched_Name": "VRANKEN POMMERY MONOPOLE",
            "Validated_Via": "legal_identity",
        },
    }

    kept, rejected = worker._filter_suspicious_duplicate_sirens(rows)

    assert rejected == 2
    assert set(kept) == {"vranken-pommery"}


def test_duplicate_siren_keeps_strong_siret_resolution_even_without_name_overlap():
    rows = {
        "brand-a": {
            "Company_ID": "123456789",
            "Query_Name": "Brand A",
            "Matched_Name": "LEGAL ENTITY XYZ",
            "Validated_Via": "legal_identity_siret",
        },
        "entity": {
            "Company_ID": "123456789",
            "Query_Name": "Legal Entity",
            "Matched_Name": "LEGAL ENTITY XYZ",
            "Validated_Via": "legal_identity",
        },
    }

    kept, rejected = worker._filter_suspicious_duplicate_sirens(rows)

    assert rejected == 0
    assert set(kept) == {"brand-a", "entity"}
