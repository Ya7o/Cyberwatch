"""Contrats de la collecte quotidienne du prototype."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _workflow() -> str:
    return (ROOT / ".github/workflows/collect.yml").read_text(encoding="utf-8")


def test_collecte_planifiee_a_un_seul_passage_quotidien():
    workflow = _workflow()
    assert 'cron: "0 7 * * *"' in workflow
    assert workflow.count("cron:") == 1


def test_collecte_planifiee_ne_reconstruit_plus_l_historique():
    workflow = _workflow()
    assert "if: github.event_name == 'workflow_dispatch'" not in workflow
    assert "COLLECTION_EPOCH" not in workflow
    assert "python -m cyberwatch maj" in workflow
    assert "create" not in workflow
    assert "corpus_coverage.needs_backfill" not in workflow
