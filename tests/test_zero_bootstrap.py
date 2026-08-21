"""Un vrai départ de zéro doit rester bootable.

Ces contrats vérifient l'invariant central du mode `zero` : après purge, le
staging contient exactement les référentiels statiques nécessaires — ni plus
(aucun état historique n'a survécu), ni moins (Cyberwatch démarre et se
contrôle). Tout est hors ligne : aucun appel réseau ni LLM.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from cyberwatch import cold_reset
from cyberwatch.zero_reset import (
    PRESERVED_DATA_PATHS,
    REQUIRED_BOOTSTRAP_PATHS,
    purge,
    validate_zero_bootstrap,
    verify_zero,
)

ROOT = Path(__file__).resolve().parents[1]
_IGNORED = shutil.ignore_patterns(
    ".git", "__pycache__", "*.pyc", ".pytest_cache", ".venv", "venv", "node_modules"
)


@pytest.fixture(scope="module")
def purged_staging(tmp_path_factory) -> Path:
    """Reproduit l'étape « préparer le staging » du workflow, puis purge."""
    staging = tmp_path_factory.mktemp("zero") / "cyberwatch"
    shutil.copytree(ROOT, staging, ignore=_IGNORED)
    purge(staging)
    return staging


def _run(staging: Path, *args: str, script: str | None = None) -> subprocess.CompletedProcess:
    """Exécute un sous-processus isolé dont la racine est le staging purgé."""
    env = {k: v for k, v in os.environ.items() if k not in {"PYTHONPATH", "PYTHONSTARTUP"}}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    command = [sys.executable, *args] if script is None else [sys.executable, "-c", script]
    return subprocess.run(
        command, cwd=staging, env=env, capture_output=True, text=True, timeout=300
    )


def test_purged_staging_is_zero_and_bootstrap_ready(purged_staging):
    assert verify_zero(purged_staging)["verdict"] == "ZERO"
    bootstrap = validate_zero_bootstrap(purged_staging)
    assert bootstrap["verdict"] == "READY", bootstrap["detail"]
    assert bootstrap["missing"] == []


def test_bootstrap_allowlist_is_exactly_the_preserved_allowlist():
    """Rien ne survit qui ne soit requis, rien n'est requis qui ne survive."""
    assert REQUIRED_BOOTSTRAP_PATHS == frozenset(f"data/{n}" for n in PRESERVED_DATA_PATHS)
    assert set(cold_reset.BOOTSTRAP_REFERENCE_FILES) == set(PRESERVED_DATA_PATHS)


def test_validate_zero_bootstrap_detects_missing_referential(tmp_path):
    data = tmp_path / "data"
    data.mkdir(parents=True)
    for name in PRESERVED_DATA_PATHS:
        (data / name).write_text("static", encoding="utf-8")
    (data / "organisation_aliases.csv").unlink()

    result = validate_zero_bootstrap(tmp_path)
    assert result["verdict"] == "MISSING"
    assert result["missing"] == ["data/organisation_aliases.csv"]
    assert "organisation_aliases.csv" in result["detail"]


def test_validate_zero_bootstrap_rejects_an_empty_referential(tmp_path):
    data = tmp_path / "data"
    data.mkdir(parents=True)
    for name in PRESERVED_DATA_PATHS:
        (data / name).write_text("static", encoding="utf-8")
    (data / "territorial_identities.csv").write_text("", encoding="utf-8")

    result = validate_zero_bootstrap(tmp_path)
    assert result["verdict"] == "MISSING"
    assert result["missing"] == ["data/territorial_identities.csv"]


def test_every_module_imports_after_purge(purged_staging):
    """Aucun module ne doit exiger un fichier détruit par la purge."""
    script = """
import importlib, json, pkgutil, sys
import cyberwatch

failures = []
for info in pkgutil.walk_packages(cyberwatch.__path__, "cyberwatch."):
    try:
        importlib.import_module(info.name)
    except Exception as error:
        failures.append(f"{info.name}: {type(error).__name__}: {error}")
print(json.dumps(failures))
"""
    result = _run(purged_staging, script=script)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout.strip().splitlines()[-1]) == []


def test_no_module_reads_unallowlisted_data_at_import(purged_staging):
    """Une lecture de `data/` à l'import doit être couverte par l'allowlist.

    C'est le contrat qui a manqué lors du premier zero-reset : un module lisait
    `organisation_aliases.csv` à l'import sans que la purge le sache.
    """
    script = """
import importlib, json, pkgutil, sys
from pathlib import Path

ROOT = Path.cwd().resolve()
DATA = ROOT / "data"
touched = set()

def hook(event, args):
    if event not in ("open", "os.open"):
        return
    raw = args[0]
    if isinstance(raw, int) or not raw:
        return
    try:
        path = Path(os.fsdecode(raw))
    except Exception:
        return
    path = path if path.is_absolute() else (ROOT / path)
    try:
        relative = path.resolve().relative_to(DATA)
    except ValueError:
        return
    touched.add(str(relative))

import os
sys.addaudithook(hook)

import cyberwatch
for info in pkgutil.walk_packages(cyberwatch.__path__, "cyberwatch."):
    try:
        importlib.import_module(info.name)
    except Exception:
        pass
print(json.dumps(sorted(touched)))
"""
    result = _run(purged_staging, script=script)
    assert result.returncode == 0, result.stderr
    touched = set(json.loads(result.stdout.strip().splitlines()[-1]))
    assert touched <= set(PRESERVED_DATA_PATHS), sorted(touched - set(PRESERVED_DATA_PATHS))


def test_check_allow_uninitialized_passes_after_purge(purged_staging):
    result = _run(purged_staging, "-m", "cyberwatch", "check", "--allow-uninitialized")
    assert result.returncode == 0, result.stdout + result.stderr


def test_cold_reset_preflight_accepts_a_purged_staging_in_zero_mode(purged_staging):
    """Le préflight ne doit pas réclamer l'état d'identité détruit à dessein."""
    zero = _run(purged_staging, "-m", "cyberwatch.cold_reset", "preflight", "--mode", "zero")
    assert zero.returncode == 0, zero.stdout + zero.stderr
    payload = json.loads(zero.stdout)
    assert payload["verdict"] == "GO"
    assert set(payload["purged_state_files"]) == {
        f"data/{name}" for name in cold_reset.IDENTITY_STATE_FILES
    }

    rebuild = _run(purged_staging, "-m", "cyberwatch.cold_reset", "preflight", "--mode", "rebuild")
    assert rebuild.returncode == 2, "un rebuild sans état d'identité doit rester NO-GO"
