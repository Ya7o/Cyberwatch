#!/usr/bin/env python3
"""Inventaire en lecture seule de la taille et des références Git."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _git(*args: str) -> str:
    return subprocess.check_output(
        ["git", *args], cwd=ROOT, text=True, encoding="utf-8"
    ).strip()


def _lines(value: str) -> list[str]:
    return [line for line in value.splitlines() if line]


def audit() -> dict[str, object]:
    count_objects = {}
    for line in _lines(_git("count-objects", "-v")):
        key, value = line.split(":", 1)
        count_objects[key] = int(value.strip())
    tags = _lines(_git("tag", "--list"))
    branches = _lines(
        _git("for-each-ref", "--format=%(refname:short)", "refs/heads")
    )
    return {
        "main_commits": int(_git("rev-list", "main", "--count")),
        "all_reachable_commits": int(_git("rev-list", "--all", "--count")),
        "local_tags": len(tags),
        "archive_tags": sum(tag.startswith("archive/") for tag in tags),
        "version_tags": sum(tag.startswith("v") for tag in tags),
        "local_branches": branches,
        "packs": count_objects.get("packs", 0),
        "pack_size_kib": count_objects.get("size-pack", 0),
        "loose_objects": count_objects.get("count", 0),
        "garbage_objects": count_objects.get("garbage", 0),
    }


def main() -> int:
    print(json.dumps(audit(), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
