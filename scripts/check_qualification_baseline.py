#!/usr/bin/env python3
"""Bloque une requalification qui dégrade la baseline publiée."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cyberwatch.qualification_baseline import compare_reports


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: check_qualification_baseline.py BEFORE.json AFTER.json")
    before = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    after = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
    failures = compare_reports(before, after)
    if failures:
        raise SystemExit("régression qualification:\n- " + "\n- ".join(failures))
    print("QUALIFICATION QUALITY GATE: PASS")


if __name__ == "__main__":
    main()
