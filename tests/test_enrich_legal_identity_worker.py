import runpy
import subprocess
import sys
from pathlib import Path

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


def test_direct_script_bootstraps_repository_import_path(tmp_path):
    script = Path(worker.__file__).resolve()
    command = [
        sys.executable,
        "-c",
        (
            "import runpy; "
            f"runpy.run_path({str(script)!r}, run_name='cyberwatch_worker_smoke')"
        ),
    ]
    completed = subprocess.run(
        command,
        cwd=tmp_path,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
