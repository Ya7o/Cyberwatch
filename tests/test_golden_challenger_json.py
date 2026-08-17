import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "evaluate_golden_challengers.py"


def _module():
    spec = importlib.util.spec_from_file_location("evaluate_golden_challengers", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_json_challenger_loader_accepts_repository_shape(tmp_path):
    path = tmp_path / "challenger.json"
    path.write_text(
        json.dumps(
            {
                "metadata": {"schema": "test"},
                "incidents": [
                    {
                        "date": "2026-08-17",
                        "organisation": "Example",
                        "territoire": "France",
                        "secteur": "Inconnu",
                        "type_menace": "Fuite de données",
                        "sources": ["https://example.test/a", "https://example.test/b"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    rows = _module()._load_records(str(path))
    assert len(rows) == 1
    assert rows[0]["source_urls"] == "https://example.test/a | https://example.test/b"
