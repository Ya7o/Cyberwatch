#!/usr/bin/env python3
"""Backfill sémantique Cyberattaque.org borné, reprenable et non canonique.

Le script relit uniquement les articles WordPress correspondant aux items déjà
connus, enrichit `Source_Metadata_JSON.rich_facts`, et s'arrête volontairement
quand le budget de nouveaux appels LLM est atteint. Le cache sémantique est
écrit après chaque appel par `cyberattaque_semantic`, donc un rerun reprend sans
rejouer les articles déjà traités.
"""
from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path
from urllib.parse import urlencode

import requests

from cyberwatch import store
from cyberwatch.collectors.base import SourceSpec
from cyberwatch.collectors.wordpress import entry_from_post
from cyberwatch.collectors.cyberattaque_rich import enrich_entry_metadata
from cyberwatch.collectors import cyberattaque_semantic

SOURCE_ID = "CYBERATTAQUE_ORG"
DEFAULT_ENDPOINT = "https://cyberattaque.org/wp-json/wp/v2"


def _metadata(row: dict) -> dict:
    try:
        value = json.loads(row.get("Source_Metadata_JSON") or "{}")
        return value if isinstance(value, dict) else {}
    except (TypeError, ValueError):
        return {}


def _cache_key(text: str) -> str:
    model = os.getenv("CYBERATTAQUE_SEMANTIC_MODEL", cyberattaque_semantic.DEFAULT_MODEL).strip() or cyberattaque_semantic.DEFAULT_MODEL
    return f"{cyberattaque_semantic.PROMPT_VERSION}:{model}:{cyberattaque_semantic.content_hash(text)}"


def _fetch_posts(endpoint: str, start: str, timeout: int) -> list[dict]:
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


def run(*, endpoint: str, start: str, max_calls: int, http_timeout: int, progress_path: Path) -> dict:
    started = time.monotonic()
    items = [item for item in store.load_items() if item.Source_ID == SOURCE_ID]
    by_native = {str(item.Source_Item_ID): item for item in items if item.Source_Item_ID}
    by_url = {item.URL: item for item in items if item.URL}
    facts = store.load_source_facts()
    facts_by_id = {row.get("Item_ID", ""): dict(row) for row in facts}
    cache = cyberattaque_semantic._load_cache()

    spec = SourceSpec(source_id=SOURCE_ID, layer="core", zone="FR", params={"include_content": True})
    posts = _fetch_posts(endpoint, start, http_timeout)

    stats = {
        "source": SOURCE_ID,
        "posts_fetched": len(posts),
        "matched_items": 0,
        "not_candidates": 0,
        "cache_hits": 0,
        "llm_calls": 0,
        "updated": 0,
        "backlog_remaining": 0,
        "failed": 0,
        "max_calls": max_calls,
    }

    updates: list[tuple[str, dict]] = []
    backlog: list[tuple[object, str, dict]] = []
    original_enabled = os.getenv("CYBERATTAQUE_SEMANTIC_ENABLED")
    try:
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
            if not candidate:
                stats["not_candidates"] += 1
                updates.append((item.Item_ID, deterministic))
                continue
            key = _cache_key(text)
            if key in cache:
                stats["cache_hits"] += 1
            backlog.append((item, text, post))

        os.environ["CYBERATTAQUE_SEMANTIC_ENABLED"] = "1"
        calls_left = max(0, max_calls)
        for item, text, post in backlog:
            key = _cache_key(text)
            is_hit = key in cyberattaque_semantic._load_cache()
            if not is_hit and calls_left <= 0:
                stats["backlog_remaining"] += 1
                continue
            entry = entry_from_post(post, spec)
            if entry is None:
                stats["failed"] += 1
                continue
            before = key in cyberattaque_semantic._load_cache()
            enrich_entry_metadata(entry)
            after_cache = cyberattaque_semantic._load_cache()
            if not before:
                calls_left -= 1
                stats["llm_calls"] += 1
                if key not in after_cache:
                    stats["failed"] += 1
                    stats["backlog_remaining"] += 1
                    continue
            rich = (entry.source_metadata or {}).get("rich_facts")
            if isinstance(rich, dict):
                updates.append((item.Item_ID, rich))
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
    stats["duration_s"] = round(time.monotonic() - started, 3)
    progress_path.parent.mkdir(parents=True, exist_ok=True)
    progress_path.write_text(json.dumps(stats, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(stats, ensure_ascii=False, sort_keys=True))
    return stats


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    parser.add_argument("--start", default="2026-01-01")
    parser.add_argument("--max-calls", type=int, default=int(os.getenv("CYBERATTAQUE_SEMANTIC_MAX_CALLS_PER_RUN", "30") or 30))
    parser.add_argument("--http-timeout", type=int, default=30)
    parser.add_argument("--progress", default="data/quality/cyberattaque_semantic_progress.json")
    args = parser.parse_args()
    run(endpoint=args.endpoint, start=args.start, max_calls=args.max_calls, http_timeout=args.http_timeout, progress_path=Path(args.progress))


if __name__ == "__main__":
    main()
