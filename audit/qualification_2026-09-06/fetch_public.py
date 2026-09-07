"""Capture en lecture seule du code distant et des JSON publics pour cet audit."""
import concurrent.futures
import datetime
import hashlib
import json
from pathlib import Path
import urllib.request
import urllib.error

COMMIT = "d664601c6b14777fba725c0c9c7606ed49c97631"
OUT = Path(__file__).resolve().parent / "public"
OUT.mkdir(exist_ok=True)
FILES = ["cyberwatch/enrichment.py", "cyberwatch/sector_resolution.py", "cyberwatch/threat_resolution.py",
         "cyberwatch/runner.py", "cyberwatch/normalize.py", ".github/workflows/collect.yml",
         "cyberwatch/source_facts_ai.py", "data/incidents.csv", "data/sector_resolution.csv"]
requests = [("https://raw.githubusercontent.com/Ya7o/Cyberwatch/" + COMMIT + "/" + name, "main/" + name) for name in FILES]
requests += [("https://ya7o.github.io/Cyberwatch/assets/data/" + name, "pages/" + name)
             for name in ("incidents.json", "status.json")]

def fetch(pair):
    url, filename = pair
    record = {"url": url, "path": filename, "fetched_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "Cyberwatch-readonly-audit"}), timeout=30) as response:
            content = response.read()
            record.update(status=response.status, date=response.headers.get("Date"), sha256=hashlib.sha256(content).hexdigest())
        path = OUT / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    except (urllib.error.URLError, TimeoutError) as exc:
        record.update(error=str(exc), status=getattr(exc, "code", None))
    return record

with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
    manifest = list(pool.map(fetch, requests))
(OUT / "manifest.json").write_text(json.dumps({"remote_main": COMMIT, "files": manifest}, indent=2) + "\n")
print(json.dumps(manifest, indent=2))
