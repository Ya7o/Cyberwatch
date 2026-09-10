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

QUEUE_VERSION = 2
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
    # `[-MAX_ENTRIES:]` conserve la fin du tri : les dossiers encore à traiter
    # passent donc devant ceux qui n'ont plus que de la visibilité à offrir.
    ordered = sorted(entries, key=lambda row: (
        bool(row.get("pending_fields")), row.get("first_queued_at", ""), row["key"],
    ))
    store.write_json(queue_path(), {"version": QUEUE_VERSION, "entries": ordered[-MAX_ENTRIES:]})


def enqueue(item: Item, entry: RawEntry, fields: set[str], reason: str,
            *, reasons: dict[str, str] | None = None) -> None:
    """Conserve le contexte public nécessaire à une reprise hors fenêtre."""
    if not fields:
        return
    now = dt.datetime.now(dt.UTC).isoformat()
    key = _key(item, entry)
    entries = load()
    previous = next((row for row in entries if row["key"] == key), None)
    pending = set(previous.get("pending_fields", [])) if previous else set()
    pending.update(fields)
    field_reasons = dict(previous.get("field_reasons", {})) if previous else {}
    field_reasons.update({field: str(value) for field, value in (reasons or {}).items()})
    record = {
        "key": key,
        "item": item.to_row(),
        "entry": asdict(entry),
        "pending_fields": sorted(pending),
        # Le motif scalaire reste écrit tel quel : les lecteurs anciens ne
        # connaissent que lui. Le détail par champ vient en plus.
        "reason": reason,
        "field_reasons": field_reasons,
        "exhausted_fields": dict(previous.get("exhausted_fields", {})) if previous else {},
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
        row = {**row, "pending_fields": sorted(pending),
               "exhausted_fields": {k: v for k, v in row.get("exhausted_fields", {}).items()
                                    if k not in fields},
               "field_reasons": {k: v for k, v in row.get("field_reasons", {}).items()
                                 if k not in fields}}
        # Un dossier dont tous les champs sont résolus disparaît ; celui qui
        # garde un rejet persistant reste visible sans être rejouable.
        if pending or row.get("exhausted_fields"):
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


def mark_exhausted(item: Item, entry: RawEntry, fields: set[str],
                   reasons: dict[str, str] | None = None) -> None:
    """Retire des champs de la reprise sans effacer le dossier.

    Un rejet persistant n'est ni une résolution ni une abstention : plus aucun
    appel automatique ne part, mais le dossier reste lisible dans la file et
    continue d'alimenter l'alerte de production.
    """
    if not fields:
        return
    now = dt.datetime.now(dt.UTC).isoformat()
    key = _key(item, entry)
    entries = load()
    changed = False
    for row in entries:
        if row["key"] != key:
            continue
        changed = True
        exhausted = dict(row.get("exhausted_fields", {}))
        for field in sorted(fields):
            exhausted[field] = {"reason": str((reasons or {}).get(field, "")), "at": now}
        row["exhausted_fields"] = exhausted
        row["pending_fields"] = sorted(set(row.get("pending_fields", [])) - fields)
    if changed:
        save(entries)


def pending_for(record: dict, scope: set[str] | None = None) -> set[str] | None:
    """Champs de ce dossier à rejouer, restreints au périmètre demandé.

    Rend ``None`` pour une ligne antérieure au suivi par champ : le dossier
    entier est alors à reprendre, comme avant l'introduction de la portée.
    """
    pending = record.get("pending_fields")
    if pending is None:
        return set(scope) if scope else None
    fields = {str(field) for field in pending}
    return fields & scope if scope else fields


def archive(run_id: str, root: Path | None = None, *,
            sector_qualification: dict | None = None) -> Path | None:
    """Fige la file telle qu'elle est à la fin de ce run.

    Les rapports historiques cessent ainsi de dépendre de la file courante,
    qui est globale et ne peut décrire que le dernier run.
    """
    name = "".join(c for c in str(run_id or "") if c.isalnum() or c in "-_")
    if not name:
        return None
    # Même convention que `_Runtime._run_history_dir` : le répertoire de run
    # suit le chemin de la file, donc une redirection de test n'écrit jamais
    # dans le `data/` du dépôt.
    directory = (root or queue_path().parent) / "llm_runs" / name
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError:
        return None
    path = directory / "source_facts_retry_queue.json"
    store.write_json(path, {
        "version": QUEUE_VERSION,
        "run_id": str(run_id),
        "archived_at": dt.datetime.now(dt.UTC).isoformat(),
        "entries": load(),
        "sector_qualification": sector_qualification,
    })
    return path
