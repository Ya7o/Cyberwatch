from __future__ import annotations

import json
import os
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

from cyberwatch import cyberattaque_semantic_backfill as backfill
from cyberwatch.model import Item


def _post(native_id: str, title: str) -> dict:
    return {
        "id": int(native_id),
        "date": "2026-08-20T10:00:00",
        "link": f"https://cyberattaque.org/{native_id}",
        "title": {"rendered": title},
        "excerpt": {"rendered": "Résumé riche"},
        "content": {"rendered": "Contenu suffisamment ambigu pour le test."},
    }


def test_direct_cli_starts_with_repository_on_pythonpath():
    root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    env["PYTHONPATH"] = str(root)
    completed = subprocess.run(
        [sys.executable, "scripts/backfill_cyberattaque_semantic.py", "--help"],
        cwd=root,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=20,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert "--max-calls" in completed.stdout


def test_budgeted_resume_matches_full_run(monkeypatch, tmp_path: Path):
    items = [
        Item(Item_ID="I1", Source_ID="CYBERATTAQUE_ORG", Source_Item_ID="1", URL="https://cyberattaque.org/1"),
        Item(Item_ID="I2", Source_ID="CYBERATTAQUE_ORG", Source_Item_ID="2", URL="https://cyberattaque.org/2"),
    ]
    initial_facts = [
        {"Item_ID": "I1", "Source_ID": "CYBERATTAQUE_ORG", "Source_Metadata_JSON": "{}"},
        {"Item_ID": "I2", "Source_ID": "CYBERATTAQUE_ORG", "Source_Metadata_JSON": "{}"},
    ]
    posts = [_post("1", "Article un"), _post("2", "Article deux")]

    state = {"facts": deepcopy(initial_facts), "cache": {}}
    monkeypatch.setattr(backfill.store, "load_items", lambda: items)
    monkeypatch.setattr(backfill.store, "load_source_facts", lambda: deepcopy(state["facts"]))
    monkeypatch.setattr(backfill.store, "save_source_facts", lambda rows: state.__setitem__("facts", deepcopy(rows)))
    monkeypatch.setattr(backfill, "fetch_posts", lambda endpoint, start, timeout=30: deepcopy(posts))
    monkeypatch.setattr(backfill.cyberattaque_semantic, "should_use_llm", lambda text, deterministic: True)
    monkeypatch.setattr(backfill.cyberattaque_semantic, "_load_cache", lambda: state["cache"])

    def fake_enrich(entry):
        text = "\n".join(part for part in (entry.title, entry.summary, entry.content) if part)
        rich = {"version": "2", "title": entry.title}
        if os.getenv("CYBERATTAQUE_SEMANTIC_ENABLED") == "1":
            key = backfill.semantic_key(text)
            state["cache"][key] = {"claims": [{"type": "statement", "status": "reported", "value": entry.title, "evidence": entry.title}]}
            rich["semantic"] = {"used": True, "key": key}
        else:
            rich["semantic"] = {"used": False}
        entry.source_metadata = {"rich_facts": rich}

    monkeypatch.setattr(backfill, "enrich_entry_metadata", fake_enrich)

    first = backfill.run(
        max_calls=1,
        progress_path=tmp_path / "progress-1.json",
        backlog_path=tmp_path / "backlog-1.json",
    )
    assert first["llm_calls"] == 1
    assert first["pending"] == 1
    assert first["backlog_remaining"] == 1
    backlog1 = json.loads((tmp_path / "backlog-1.json").read_text(encoding="utf-8"))
    assert [row["status"] for row in backlog1["states"]].count("pending") == 1

    second = backfill.run(
        max_calls=1,
        progress_path=tmp_path / "progress-2.json",
        backlog_path=tmp_path / "backlog-2.json",
    )
    resumed_facts = deepcopy(state["facts"])
    assert second["cache_hits"] == 1
    assert second["llm_calls"] == 1
    assert second["backlog_remaining"] == 0

    state["facts"] = deepcopy(initial_facts)
    state["cache"] = {}
    full = backfill.run(
        max_calls=2,
        progress_path=tmp_path / "progress-full.json",
        backlog_path=tmp_path / "backlog-full.json",
    )
    assert full["llm_calls"] == 2
    assert full["backlog_remaining"] == 0
    assert state["facts"] == resumed_facts


def test_zero_budget_still_reuses_cache(monkeypatch, tmp_path: Path):
    item = Item(Item_ID="I1", Source_ID="CYBERATTAQUE_ORG", Source_Item_ID="1", URL="https://cyberattaque.org/1")
    post = _post("1", "Article un")
    facts = [{"Item_ID": "I1", "Source_ID": "CYBERATTAQUE_ORG", "Source_Metadata_JSON": "{}"}]
    text = "\n".join(("Article un", "Résumé riche", "Contenu suffisamment ambigu pour le test."))
    cache = {backfill.semantic_key(text): {"claims": []}}
    saved = {}

    monkeypatch.setattr(backfill.store, "load_items", lambda: [item])
    monkeypatch.setattr(backfill.store, "load_source_facts", lambda: deepcopy(facts))
    monkeypatch.setattr(backfill.store, "save_source_facts", lambda rows: saved.setdefault("rows", deepcopy(rows)))
    monkeypatch.setattr(backfill, "fetch_posts", lambda endpoint, start, timeout=30: [deepcopy(post)])
    monkeypatch.setattr(backfill.cyberattaque_semantic, "should_use_llm", lambda text, deterministic: True)
    monkeypatch.setattr(backfill.cyberattaque_semantic, "_load_cache", lambda: cache)

    def fake_enrich(entry):
        entry.source_metadata = {"rich_facts": {"version": "2", "semantic": {"used": os.getenv("CYBERATTAQUE_SEMANTIC_ENABLED") == "1"}}}

    monkeypatch.setattr(backfill, "enrich_entry_metadata", fake_enrich)
    stats = backfill.run(max_calls=0, progress_path=tmp_path / "p.json", backlog_path=tmp_path / "b.json")
    assert stats["cache_hits"] == 1
    assert stats["llm_calls"] == 0
    assert stats["backlog_remaining"] == 0
    assert saved["rows"]
