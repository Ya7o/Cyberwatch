"""Contrats de la collecte planifiée après le reset du 28 août 2026."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _workflow() -> str:
    return (ROOT / ".github/workflows/collect.yml").read_text(encoding="utf-8")


def test_collecte_planifiee_a_un_passage_nominal_et_un_filet():
    workflow = _workflow()
    assert 'cron: "0 7 * * *"' in workflow
    assert 'cron: "0 9 * * *"' in workflow
    assert "github.event.schedule" in workflow
    assert "HAS_TODAY_OK" in workflow
    assert "skip=1" in workflow


def test_collecte_planifiee_n_est_plus_bloquee_sur_workflow_dispatch():
    workflow = _workflow()
    assert "if: github.event_name == 'workflow_dispatch'" not in workflow
    assert 'COLLECTION_EPOCH: "2026-08-28"' in workflow
    assert 'corpus_coverage.needs_backfill(store.load_run_log(), os.environ["COLLECTION_EPOCH"])' in workflow
    assert 'echo "start=$COLLECTION_EPOCH"' in workflow
