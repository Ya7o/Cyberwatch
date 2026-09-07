"""Fixtures partagées : construction d'items de test."""

import os
import tempfile

# La télémétrie LLM et performance s'écrit par défaut dans data/, canonique.
# llm_runtime._write_stats() est enregistrée via atexit, donc posée après le
# teardown des fixtures pytest : la redirection doit être faite ici, au niveau
# module, avant tout import de cyberwatch, et jamais retirée. setdefault()
# laisse un override explicite de l'opérateur prendre le dessus.
_TELEMETRY_DIR = tempfile.mkdtemp(prefix="cyberwatch-tests-")
os.environ.setdefault("LLM_USAGE_PATH", os.path.join(_TELEMETRY_DIR, "llm_usage.json"))
os.environ.setdefault(
    "CYBERWATCH_PERFORMANCE_LOG_PATH", os.path.join(_TELEMETRY_DIR, "performance_runs.json")
)

import pytest

from cyberwatch.identity import item_id
from cyberwatch.model import Item
from cyberwatch.normalize import organisation_key


@pytest.fixture
def make_item():
    """Fabrique un item cohérent, identifiant calculé comme en production."""

    def _make(
        source="FRENCHBREACHES",
        source_item_id="",
        published="2026-03-01",
        org="CHU de La Réunion",
        url="https://example.org/a",
        event="",
        threat="Fuite de données",
        sector="Santé",
        location="La Réunion",
        collected="2026-08-12T00:00:00+04:00",
        title="Titre",
    ) -> Item:
        key = organisation_key(org)
        return Item(
            Item_ID=item_id(source, published, key, url, source_item_id),
            Source_ID=source,
            Source_Item_ID=source_item_id,
            Published_Date=published,
            Event_Date=event,
            Organisation_Raw=org,
            Organisation_Key=key,
            Threat=threat,
            Sector=sector,
            Location=location,
            Title=title,
            URL=url,
            Collected_As_Of=collected,
        )

    return _make
