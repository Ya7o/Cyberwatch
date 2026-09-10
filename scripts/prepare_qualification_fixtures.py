"""Promeut les preuves figées de l'audit du 10 septembre 2026 en fixtures.

Les textes sont ceux reconstitués par l'audit, pas les versions actuelles des
sites : une régression doit rester reproductible même si l'article change.
"""

from __future__ import annotations

import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "audit" / "latest_collection_2026-09-10"
TARGET = ROOT / "tests" / "fixtures" / "tampon_20260910"

CONTEXTS = (
    "ITM-0c085da888611a12-context.txt",  # FrenchBreaches — « Ville du Tampon »
    "ITM-f2c9b54af4eae1da-context.txt",  # Cyberattaque.org — « Le Tampon »
)


def main() -> int:
    TARGET.mkdir(parents=True, exist_ok=True)
    for name in CONTEXTS:
        origin = SOURCE / name
        if not origin.exists():
            print(f"ABSENT : {origin}")
            return 1
        shutil.copyfile(origin, TARGET / name)
        print(f"OK : {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
