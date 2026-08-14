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
