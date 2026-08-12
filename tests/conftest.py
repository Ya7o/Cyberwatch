"""Fixtures partagées : construction d'items de test."""

import pytest

from cyberwatch.identity import item_id
from cyberwatch.model import Item
from cyberwatch.normalize import organisation_key


@pytest.fixture
def make_item():
    """Fabrique un item cohérent, identifiant calculé comme en production."""

    def _make(
        source="FRENCHBREACHES",
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
            Item_ID=item_id(source, published, key, url),
            Source_ID=source,
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
