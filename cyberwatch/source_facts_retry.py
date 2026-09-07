"""File persistante et bornée des extractions sémantiques différées."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from dataclasses import asdict
from pathlib import Path

from . import store
from .collectors.base import RawEntry
from .model import Item

QUEUE_VERSION = 1
MAX_ENTRIES = 200


def queue_path() -> Path:
    configured = os.getenv("SOURCE_FACTS_RETRY_QUEUE_PATH", "").strip()
    return Path(configured) if configured else store.DATA_DIR / "source_facts_retry_queue.json"


def _context_hash(entry: RawEntry) -> str:
    context = "\n\n".join(
        part.strip() for part in (entry.title, entry.summary, entry.content) if (part or "").strip()
    )
    return hashlib.sha256(context.encode("utf-8")).hexdigest()


def _key(item: Item, entry: RawEntry) -> str:
    return f"{item.Item_ID}:{_context_hash(entry)}"


def load() -> list[dict]:
    path = queue_path()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return []
    entries = payload.get("entries", []) if isinstance(payload, dict) else []
    return [entry for entry in entries if isinstance(entry, dict) and entry.get("key")]


def save(entries: list[dict]) -> None:
    ordered = sorted(entries, key=lambda row: (row.get("first_queued_at", ""), row["key"]))
    store.write_json(queue_path(), {"version": QUEUE_VERSION, "entries": ordered[-MAX_ENTRIES:]})


def enqueue(item: Item, entry: RawEntry, fields: set[str], reason: str) -> None:
    """Conserve le contexte public nécessaire à une reprise hors fenêtre."""
    if not fields:
        return
    now = dt.datetime.now(dt.UTC).isoformat()
    key = _key(item, entry)
    entries = load()
    previous = next((row for row in entries if row["key"] == key), None)
    pending = set(previous.get("pending_fields", [])) if previous else set()
    pending.update(fields)
    record = {
        "key": key,
        "item": item.to_row(),
        "entry": asdict(entry),
        "pending_fields": sorted(pending),
        "reason": reason,
        "first_queued_at": previous.get("first_queued_at", now) if previous else now,
        "last_queued_at": now,
        "attempts": int(previous.get("attempts", 0)) if previous else 0,
    }
    save([row for row in entries if row["key"] != key] + [record])


def resolve(item: Item, entry: RawEntry, fields: set[str]) -> None:
    key = _key(item, entry)
    entries = load()
    changed = False
    kept: list[dict] = []
    for row in entries:
        if row["key"] != key:
            kept.append(row)
            continue
        pending = set(row.get("pending_fields", [])) - fields
        changed = True
        if pending:
            row = {**row, "pending_fields": sorted(pending)}
            kept.append(row)
    if changed:
        save(kept)


def mark_attempt(key: str) -> None:
    entries = load()
    for row in entries:
        if row["key"] == key:
            row["attempts"] = int(row.get("attempts", 0)) + 1
            row["last_attempt_at"] = dt.datetime.now(dt.UTC).isoformat()
            break
    save(entries)


def restore(record: dict) -> tuple[Item, RawEntry]:
    return Item.from_row(record.get("item", {})), RawEntry(**record.get("entry", {}))
