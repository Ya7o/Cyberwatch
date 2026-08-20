#!/usr/bin/env python3
"""Audit generic rich-facts coverage across editorial sources."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from cyberwatch import store
from cyberwatch.rich_facts_observability import summarize_source_fact_rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="")
    args = parser.parse_args()
    payload = summarize_source_fact_rows(store.load_source_facts())
    text = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
    print(text)
    if args.output:
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
