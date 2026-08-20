"""Moteur de backfill sémantique borné pour Cyberattaque.org.

Cette couche ne modifie que `SOURCE_FACTS.Source_Metadata_JSON.rich_facts` et le
cache sémantique. Les items/incidents canoniques ne sont jamais reconstruits ici.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from urllib.parse import urlencode

import requests

from . import store
from .collectors import cyberattaque_semantic
from .collectors.base import SourceSpec
from .collectors.cyberattaque_rich import enrich_entry_metadata
from .collectors.wordpress import entry_from_post

SOURCE_ID = "CYBERATTAQUE_ORG"
DEFAULT_ENDPOINT = "https://cyberattaque.org/wp-json/wp/v2"
BACKLOG_VERSION = "1"


def _metadata(row: dict) -> dict:
    try:
        value = json.loads(row.get("Source_Metadata_JSON") or "{}")
        return value if isinstance(value, dict) else {}
    except (TypeError, ValueError):
        return {}


def semantic_key(text: str) -> str:
    model = os.getenv("CYBERATTAQUE_SEMANTIC_MODEL", cyberattaque_semantic.DEFAULT_MODEL).strip() or cyberattaque_semantic.DEFAULT_MODEL
    return f"{cyberattaque_semantic.PROMPT_VERSION}:{model}:{cyberattaque_semantic.content_hash(text)}"


def fetch_posts(endpoint: str, start: str, timeout: int = 30) -> list[dict]:
    posts: list[dict] = []
    page = 1
    while True:
        query = {
            "per_page": "100",
            "page": str(page),
            "orderby": "date",
            "order": "desc",
            "after": f"{start}T00:00:00",
            "_fields": "id,date,link,title,excerpt,content",
        }
        response = requests.get(f"{endpoint}/posts?{urlencode(query)}", timeout=timeout)
        if response.status_code == 400 and page > 1:
            break
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, list) or not payload:
            break
        posts.extend(value for value in payload if isinstance(value, dict))
        total_pages = int(response.headers.get("X-WP-TotalPages") or page)
        if page >= total_pages:
            break
        page += 1
    return posts


def _write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def run(
    *,
    endpoint: str = DEFAULT_ENDPOINT,
    start: str = "2026-01-01",
    max_calls: int = 30,
    http_timeout: int = 30,
    progress_path: Path = Path("data/quality/cyberattaque_semantic_progress.json"),
    backlog_path: Path = Path("data/quality/cyberattaque_semantic_backlog.json"),
) -> dict:
    started = time.monotonic()
    items = [item for item in store.load_items() if item.Source_ID == SOURCE_ID]
    by_native = {str(item.Source_Item_ID): item for item in items if item.Source_Item_ID}
    by_url = {item.URL: item for item in items if item.URL}
    facts = store.load_source_facts()
    facts_by_id = {row.get("Item_ID", ""): dict(row) for row in facts}
    initial_cache = cyberattaque_semantic._load_cache()
    spec = SourceSpec(source_id=SOURCE_ID, layer="core", zone="FR", params={"include_content": True})
    posts = fetch_posts(endpoint, start, http_timeout)

    stats = {
        "version": BACKLOG_VERSION,
        "source": SOURCE_ID,
        "posts_fetched": len(posts),
        "matched_items": 0,
        "not_candidates": 0,
        "cache_hits": 0,
        "llm_calls": 0,
        "updated": 0,
        "pending": 0,
        "failed_retryable": 0,
        "completed": 0,
        "max_calls": max(0, max_calls),
    }
    states: list[dict] = []
    candidates: list[tuple[object, str, dict, str]] = []
    updates: list[tuple[str, dict]] = []
    original_enabled = os.getenv("CYBERATTAQUE_SEMANTIC_ENABLED")

    try:
        # Base déterministe identique au collecteur, sans possibilité d'appel LLM.
        os.environ["CYBERATTAQUE_SEMANTIC_ENABLED"] = "0"
        for post in posts:
            item = by_native.get(str(post.get("id") or "")) or by_url.get(str(post.get("link") or ""))
            if item is None:
                continue
            stats["matched_items"] += 1
            entry = entry_from_post(post, spec)
            if entry is None:
                continue
            enrich_entry_metadata(entry)
            deterministic = (entry.source_metadata or {}).get("rich_facts") or {}
            text = "\n".join(part for part in (entry.title, entry.summary, entry.content) if part)
            os.environ["CYBERATTAQUE_SEMANTIC_ENABLED"] = "1"
            candidate = cyberattaque_semantic.should_use_llm(text, deterministic)
            os.environ["CYBERATTAQUE_SEMANTIC_ENABLED"] = "0"
            key = semantic_key(text)
            base_state = {
                "item_id": item.Item_ID,
                "source_item_id": item.Source_Item_ID,
                "url": item.URL,
                "content_hash": cyberattaque_semantic.content_hash(text),
                "semantic_key": key,
            }
            if not candidate:
                stats["not_candidates"] += 1
                states.append({**base_state, "status": "not_candidate"})
                updates.append((item.Item_ID, deterministic))
                continue
            if key in initial_cache:
                stats["cache_hits"] += 1
            candidates.append((item, text, post, key))

        os.environ["CYBERATTAQUE_SEMANTIC_ENABLED"] = "1"
        calls_left = max(0, max_calls)
        for item, text, post, key in candidates:
            cached_before = key in cyberattaque_semantic._load_cache()
            base_state = {
                "item_id": item.Item_ID,
                "source_item_id": item.Source_Item_ID,
                "url": item.URL,
                "content_hash": cyberattaque_semantic.content_hash(text),
                "semantic_key": key,
            }
            if not cached_before and calls_left <= 0:
                stats["pending"] += 1
                states.append({**base_state, "status": "pending"})
                continue
            entry = entry_from_post(post, spec)
            if entry is None:
                stats["failed_retryable"] += 1
                states.append({**base_state, "status": "failed_retryable", "reason": "entry_parse"})
                continue
            enrich_entry_metadata(entry)
            cache_after = cyberattaque_semantic._load_cache()
            if not cached_before:
                calls_left -= 1
                stats["llm_calls"] += 1
                if key not in cache_after:
                    stats["failed_retryable"] += 1
                    states.append({**base_state, "status": "failed_retryable", "reason": "semantic_no_cache"})
                    continue
            rich = (entry.source_metadata or {}).get("rich_facts")
            if not isinstance(rich, dict):
                stats["failed_retryable"] += 1
                states.append({**base_state, "status": "failed_retryable", "reason": "rich_facts_missing"})
                continue
            updates.append((item.Item_ID, rich))
            stats["completed"] += 1
            states.append({**base_state, "status": "completed_cache" if cached_before else "completed_llm"})
    finally:
        if original_enabled is None:
            os.environ.pop("CYBERATTAQUE_SEMANTIC_ENABLED", None)
        else:
            os.environ["CYBERATTAQUE_SEMANTIC_ENABLED"] = original_enabled

    for item_id, rich in updates:
        row = facts_by_id.get(item_id)
        if row is None:
            continue
        meta = _metadata(row)
        previous = meta.get("rich_facts")
        meta["rich_facts"] = rich
        row["Source_Metadata_JSON"] = json.dumps(meta, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        facts_by_id[item_id] = row
        if previous != rich:
            stats["updated"] += 1

    store.save_source_facts([facts_by_id[key] for key in sorted(facts_by_id)])
    stats["backlog_remaining"] = stats["pending"] + stats["failed_retryable"]
    stats["duration_s"] = round(time.monotonic() - started, 3)
    stats["cache_entries"] = len(cyberattaque_semantic._load_cache())
    _write_json(progress_path, stats)
    _write_json(backlog_path, {"version": BACKLOG_VERSION, "source": SOURCE_ID, "states": states})
    return stats
