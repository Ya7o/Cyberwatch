"""Capture the pre-existing workspace before the sector/dedup repair."""
from pathlib import Path
import hashlib
import json
import tarfile

root = Path(__file__).resolve().parents[1]
out = root / "validation" / "sector_dedup_2026-09-06"
out.mkdir(parents=True, exist_ok=True)
archive = out / "before.tar.gz"
if archive.exists():
    raise SystemExit("Backup already exists; refusing to overwrite")
paths = sorted(p for folder in ("cyberwatch", "tests", "data", "assets/data", ".github", "scripts")
               for p in (root / folder).rglob("*")
               if p.is_file() and "__pycache__" not in p.parts)
hashes = {}
with tarfile.open(archive, "w:gz") as tar:
    for path in paths:
        name = path.relative_to(root).as_posix()
        hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        tar.add(path, arcname=name)
(out / "before_hashes.json").write_text(json.dumps(hashes, indent=2) + "\n")
print(f"Saved {len(paths)} files to {archive}")
