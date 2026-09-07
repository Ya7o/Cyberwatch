"""Identifiants, tri canonique, empreintes et répétabilité (§7, §27, §28)."""

import random

from cyberwatch.dedup import build_incidents
from cyberwatch.identity import (
    incident_id,
    incidents_hash,
    item_id,
    items_hash,
    sort_incidents,
    sort_items,
)


class TestIdentifiers:
    def test_item_id_deterministe(self):
        first = item_id("SRC", "2026-01-01", "org", "https://a")
        second = item_id("SRC", "2026-01-01", "org", "https://a")
        assert first == second
        assert first.startswith("ITM-")
        assert len(first) == 20  # « ITM- » + 16 caractères hexadécimaux

    def test_item_id_sensible_a_chaque_composant(self):
        base = item_id("SRC", "2026-01-01", "org", "https://a")
        assert base != item_id("AUTRE", "2026-01-01", "org", "https://a")
        assert base != item_id("SRC", "2026-01-02", "org", "https://a")
        assert base != item_id("SRC", "2026-01-01", "autre", "https://a")
        assert base != item_id("SRC", "2026-01-01", "org", "https://b")

    def test_incident_id_deterministe_et_majuscule(self):
        value = incident_id("chu de la reunion", "ITM-A")
        assert value == incident_id("chu de la reunion", "ITM-A")
        assert value.startswith("INC-")
        assert len(value) == 16  # « INC- » + 12 caractères
        assert value[4:] == value[4:].upper()

    def test_incidents_same_date_can_have_distinct_deterministic_ids(self):
        assert incident_id("org", "ITM-A") != incident_id("org", "ITM-B")

    def test_separateur_non_ambigu(self):
        """Un découpage différent ne doit pas produire le même identifiant."""
        assert item_id("A", "B", "C", "D") != item_id("A|B", "C", "D", "")


class TestCanonicalSort:
    def test_items_tries_selon_28(self, make_item):
        items = [
            make_item(source="ZINFOS974_CYBER", url="https://z/1"),
            make_item(source="FRENCHBREACHES", url="https://a/1"),
        ]
        assert [i.Source_ID for i in sort_items(items)] == [
            "FRENCHBREACHES",
            "ZINFOS974_CYBER",
        ]

    def test_incidents_tries_par_date_decroissante(self, make_item):
        items = [
            make_item(published="2026-01-01", org="Org A", url="https://a/1"),
            make_item(published="2026-06-01", org="Org B", url="https://b/1"),
            make_item(published="2026-03-01", org="Org C", url="https://c/1"),
        ]
        dates = [i.Date for i in build_incidents(items)]
        assert dates == ["2026-06-01", "2026-03-01", "2026-01-01"]

    def test_incident_sans_date_en_fin(self, make_item):
        items = [
            make_item(published="", org="Sans date", url="https://x/1"),
            make_item(published="2026-01-01", org="Avec date", url="https://y/1"),
        ]
        incidents = sort_incidents(build_incidents(items))
        assert incidents[-1].Organisation == "Sans date"


class TestRepeatability:
    """§27 — quatre égalités quel que soit l'ordre d'entrée."""

    def _dataset(self, make_item):
        return [
            make_item(source="FRENCHBREACHES", published="2026-03-01", url="https://a/1"),
            make_item(source="LINFO_CYBER", published="2026-03-08", url="https://b/1"),
            make_item(source="CYBERATTAQUE_ORG", published="2026-05-20",
                      org="Mairie de Saint-Paul", url="https://c/1"),
            make_item(source="RANSOMWARE_LIVE", published="2026-07-02",
                      org="Air Austral", url="https://d/1", threat="Ransomware"),
        ]

    def test_quatre_egalites(self, make_item):
        items = self._dataset(make_item)
        shuffled = list(items)
        random.Random(20260812).shuffle(shuffled)

        assert len(items) == len(shuffled)
        assert items_hash(items) == items_hash(shuffled)
        assert len(build_incidents(items)) == len(build_incidents(shuffled))
        assert incidents_hash(build_incidents(items)) == incidents_hash(
            build_incidents(shuffled)
        )

    def test_hash_insensible_a_la_date_de_collecte(self, make_item):
        """L'empreinte qualifie le contenu, pas l'horodatage du run."""
        a = [make_item(collected="2026-01-01T00:00:00+04:00")]
        b = [make_item(collected="2026-08-12T00:00:00+04:00")]
        assert items_hash(a) == items_hash(b)

    def test_hash_change_si_contenu_change(self, make_item):
        a = [make_item(org="CHU de La Réunion")]
        b = [make_item(org="Mairie de Saint-Paul")]
        assert items_hash(a) != items_hash(b)

    def test_replay_stable(self, make_item):
        """§26 — à ITEMS identique, Incidents_Hash identique."""
        items = self._dataset(make_item)
        assert incidents_hash(build_incidents(items)) == incidents_hash(
            build_incidents(items)
        )
