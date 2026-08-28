"""Invariants de l'audit offline de qualité des ITEMS."""

import importlib.util
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "audit_data_quality.py"
spec = importlib.util.spec_from_file_location("audit_data_quality", SCRIPT)
audit = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(audit)


def row(source_item_id: str, threat="Inconnu"):
    return {
        "Source_ID": "TEST", "Source_Item_ID": source_item_id, "URL": "", "Published_Date": "2026-08-14",
        "Organisation_Raw": "Organisation", "Organisation_Key": "organisation", "Threat": threat,
        "Sector": "Inconnu", "Location": "Inconnu", "Title": "Titre",
    }


def test_audit_est_independant_de_l_ordre_des_items():
    rows = [row("2"), row("1", "Fuite de données")]
    assert audit.canonical(audit.run_audit(rows)) == audit.canonical(audit.run_audit(list(reversed(rows))))


def test_audit_diff_ne_suit_que_les_champs_de_qualification():
    before = [row("1")]
    after = [row("1", "Fuite de données")]
    result = audit.run_audit(after, before)
    assert result["changed_rows"] == 1
    assert result["changed_threat"] == 1
    assert result["changes"][0]["field"] == "Threat"


def test_audit_diff_signale_ajouts_et_suppressions():
    result = audit.run_audit([row("2")], [row("1")])
    assert result["added_rows"] == 1
    assert result["removed_rows"] == 1
    assert result["added"][0]["status"] == "ADDED"
    assert result["removed"][0]["status"] == "REMOVED"


def test_audit_signale_les_agregats_numeriques_simples():
    rows = [row("1"), row("2")]
    rows[0]["Organisation_Raw"] = "4 SDIS"
    rows[1]["Organisation_Raw"] = "11 agences"
    assert audit.summary(rows)["aggregates"] == ["11 agences", "4 SDIS"]


def test_audit_ne_prend_pas_une_esperluette_legale_pour_un_agregat():
    rows = [row("1")]
    rows[0]["Organisation_Raw"] = "OTEIS Conseil & Ingénierie"

    assert audit.summary(rows)["aggregates"] == []


def fact_row(item_id: str, source_id: str, threat_actor: str) -> dict:
    return {"Item_ID": item_id, "Source_ID": source_id, "Threat_Actor": threat_actor}


def test_actor_sentinel_candidates_detecte_les_mots_generiques():
    """§stabilisation pré-release : "ransomware" comme Threat_Actor est un
    faux positif bloquant, un vrai nom de groupe non."""
    rows = [
        fact_row("ITM-1", "FRENCHBREACHES", "Ransomware"),
        fact_row("ITM-2", "CYBERATTAQUE_ORG", "LockBit"),
    ]
    candidates = audit.actor_sentinel_candidates(rows)
    assert [c["item_id"] for c in candidates] == ["ITM-1"]


def test_actor_sentinel_candidates_est_independant_de_l_ordre():
    rows = [
        fact_row("ITM-2", "S2", "LockBit"),
        fact_row("ITM-1", "S1", "Ransomware"),
    ]
    assert audit.actor_sentinel_candidates(rows) == audit.actor_sentinel_candidates(list(reversed(rows)))


def test_duplicate_high_confidence_candidates_detecte_permutation_et_concatenation(make_item):
    items = [
        make_item(source="A", org="Globex Alpha", published="2026-08-16", url="https://a"),
        make_item(source="B", org="GlobexAlpha", published="2026-08-16", url="https://b"),
        make_item(source="C", org="Solutions Globex", published="2026-08-16", url="https://c"),
        make_item(source="D", org="Globex Solutions", published="2026-08-16", url="https://d"),
    ]
    candidates = audit.duplicate_high_confidence_candidates(items)
    reason_codes = {c["reason_code"] for c in candidates}
    assert "DUPLICATE_CANDIDATE_CONCATENATION" in reason_codes
    assert "DUPLICATE_CANDIDATE_PERMUTATION" in reason_codes


def test_duplicate_high_confidence_candidates_exclut_le_containment(make_item):
    """L'inclusion de mots (containment) reste volontairement hors du
    sous-ensemble haute confiance — trop de faux positifs institutionnels
    légitimes pour être bloquante."""
    items = [
        make_item(source="A", org="Biosynex", published="2026-08-16", url="https://a"),
        make_item(source="B", org="Biosynex France", published="2026-08-16", url="https://b"),
    ]
    assert audit.duplicate_high_confidence_candidates(items) == []


def test_duplicate_high_confidence_candidates_est_independant_de_l_ordre(make_item):
    items = [
        make_item(source="A", org="Globex Alpha", published="2026-08-16", url="https://a"),
        make_item(source="B", org="GlobexAlpha", published="2026-08-16", url="https://b"),
    ]
    assert audit.duplicate_high_confidence_candidates(items) == audit.duplicate_high_confidence_candidates(
        list(reversed(items))
    )
