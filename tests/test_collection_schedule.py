"""Contrats de la collecte planifiée après le reset du 28 août 2026."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _workflow() -> str:
    return (ROOT / ".github/workflows/collect.yml").read_text(encoding="utf-8")


def test_collecte_planifiee_a_un_seul_passage_quotidien():
    workflow = _workflow()
    assert 'cron: "0 7 * * *"' in workflow
    assert workflow.count("cron:") == 1


def test_collecte_planifiee_utilise_toujours_l_epoque_du_corpus():
    workflow = _workflow()
    assert "if: github.event_name == 'workflow_dispatch'" not in workflow
    assert 'COLLECTION_EPOCH: "2026-08-28"' in workflow
    assert '--start "$COLLECTION_EPOCH"' in workflow
    assert "corpus_coverage.needs_backfill" not in workflow
