"""Déduplication (§11), date du dashboard (§12) et fusion de MAJ (§25)."""

from cyberwatch import config
from cyberwatch.dedup import build_incidents, group_components, merge_items


class TestComponents:
    """§11 — composantes à écart de 14 jours au plus."""

    def test_items_rapproches_forment_un_incident(self, make_item):
        items = [
            make_item(published="2026-03-01", url="https://a/1"),
            make_item(published="2026-03-10", url="https://a/2", source="LINFO_CYBER"),
        ]
        assert len(build_incidents(items)) == 1

    def test_borne_exacte_14_jours_inclus(self, make_item):
        items = [
            make_item(published="2026-01-01", url="https://a/1"),
            make_item(published="2026-01-15", url="https://a/2"),
        ]
        assert len(build_incidents(items)) == 1

    def test_ecart_15_jours_ouvre_un_nouvel_incident(self, make_item):
        items = [
            make_item(published="2026-01-01", url="https://a/1"),
            make_item(published="2026-01-16", url="https://a/2"),
        ]
        assert len(build_incidents(items)) == 2

    def test_chaine_de_proche_en_proche(self, make_item):
        """Trois items espacés de 10 jours forment une seule chaîne."""
        items = [
            make_item(published="2026-01-01", url="https://a/1"),
            make_item(published="2026-01-11", url="https://a/2"),
            make_item(published="2026-01-21", url="https://a/3"),
        ]
        assert len(build_incidents(items)) == 1

    def test_organisations_differentes_jamais_fusionnees(self, make_item):
        """« Un faux doublon est préférable à une fusion non reproductible » (§11)."""
        items = [
            make_item(org="CHU de La Réunion", url="https://a/1"),
            make_item(org="CHU Réunion", url="https://a/2"),
        ]
        assert len(build_incidents(items)) == 2

    def test_item_sans_organisation_ecarte(self, make_item):
        """Pas d'organisation nommée, pas d'incident."""
        items = [make_item(org="", url="https://a/1")]
        assert build_incidents(items) == []


class TestIncidentFields:
    def test_date_basis_event_prioritaire(self, make_item):
        """§12 — si un Event_Date existe, il fait foi."""
        items = [make_item(published="2026-03-10", event="2026-03-05")]
        incident = build_incidents(items)[0]
        assert incident.Date == "2026-03-05"
        assert incident.Date_Basis == config.DATE_BASIS_EVENT

    def test_date_basis_publication_par_defaut(self, make_item):
        incident = build_incidents([make_item(published="2026-03-10")])[0]
        assert incident.Date == "2026-03-10"
        assert incident.Date_Basis == config.DATE_BASIS_PUBLICATION

    def test_menace_la_plus_prioritaire_gagne(self, make_item):
        """Deux sources, deux qualifications : la priorité du §8 tranche."""
        items = [
            make_item(published="2026-03-01", url="https://a/1", threat="Fuite de données"),
            make_item(published="2026-03-05", url="https://a/2", threat="Ransomware"),
        ]
        assert build_incidents(items)[0].Menace == config.THREAT_RANSOMWARE

    def test_sources_et_urls_triees(self, make_item):
        items = [
            make_item(source="ZINFOS974_CYBER", url="https://z/1", published="2026-03-01"),
            make_item(source="FRENCHBREACHES", url="https://a/1", published="2026-03-02"),
        ]
        incident = build_incidents(items)[0]
        assert incident.Sources == "FRENCHBREACHES | ZINFOS974_CYBER"
        assert incident.Source_URLs == "https://a/1 | https://z/1"
        assert incident.Items_Count == 2

    def test_first_et_last_seen(self, make_item):
        items = [
            make_item(url="https://a/1", collected="2026-01-01T00:00:00+04:00"),
            make_item(url="https://a/2", collected="2026-02-01T00:00:00+04:00",
                      published="2026-03-05"),
        ]
        incident = build_incidents(items)[0]
        assert incident.First_seen == "2026-01-01T00:00:00+04:00"
        assert incident.Last_seen == "2026-02-01T00:00:00+04:00"


class TestMergeItems:
    """§25 — ajout/remplacement par Item_ID, aucune suppression automatique."""

    def test_ajout_de_nouveaux_items(self, make_item):
        existing = [make_item(url="https://a/1")]
        incoming = [make_item(url="https://a/2", published="2026-04-01")]
        merged, new_count = merge_items(existing, incoming)
        assert len(merged) == 2
        assert new_count == 1

    def test_item_deja_connu_non_recompte(self, make_item):
        existing = [make_item(url="https://a/1")]
        merged, new_count = merge_items(existing, [make_item(url="https://a/1")])
        assert len(merged) == 1
        assert new_count == 0

    def test_ancien_item_jamais_supprime(self, make_item):
        """§25.6 — un item disparu du Web reste dans la base."""
        existing = [make_item(url="https://disparu/1")]
        merged, _ = merge_items(existing, [make_item(url="https://a/2")])
        assert any(i.URL == "https://disparu/1" for i in merged)

    def test_date_de_premiere_collecte_conservee(self, make_item):
        existing = [make_item(url="https://a/1", collected="2026-01-01T00:00:00+04:00")]
        incoming = [make_item(url="https://a/1", collected="2026-08-01T00:00:00+04:00")]
        merged, _ = merge_items(existing, incoming)
        assert merged[0].Collected_As_Of == "2026-01-01T00:00:00+04:00"
