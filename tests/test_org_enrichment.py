"""Enrichissement gratuit d'entreprise (Sector) : matching prudent, cache, pannes."""

from __future__ import annotations

import json

import pytest

from cyberwatch import org_enrichment, store


@pytest.fixture(autouse=True)
def _isolate_org_enrichment_csv(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "ORG_ENRICHMENT_CACHE_CSV", tmp_path / "org_enrichment_cache.csv")


class _FakeResponse:
    def __init__(self, status_code: int, payload=None, text: str = ""):
        self.status_code = status_code
        self._payload = payload
        self.text = text or json.dumps(payload or {})

    def json(self):
        if self._payload is None:
            raise ValueError("no payload")
        return self._payload


def enabled_state(**overrides) -> org_enrichment.OrgEnrichmentState:
    defaults = dict(enabled=True, max_calls=200)
    defaults.update(overrides)
    return org_enrichment.OrgEnrichmentState(**defaults)


def _result(nom_raison_sociale, siren, code="63.11Z", section="J"):
    """Forme réelle vérifiée le 2026-08-15 (run GitHub Actions `probe-org-schema`,
    domaine hors politique réseau du bac à sable) : `nom_complet` compose
    souvent "Nom commercial (Raison sociale)" (à éviter pour le matching),
    `activite_principale` est un code NAF nu (jamais un objet code/libelle),
    aucun libellé d'activité détaillé n'est renvoyé — seul
    `section_activite_principale` (une lettre) permet d'en dériver un via
    `org_enrichment.NAF_SECTION_LABELS`."""
    return {
        "nom_complet": f"{nom_raison_sociale} ({nom_raison_sociale})",
        "nom_raison_sociale": nom_raison_sociale,
        "siren": siren,
        "activite_principale": code,
        "section_activite_principale": section,
    }


class TestMatching:
    def test_match_exact_est_matched(self, monkeypatch):
        payload = {"results": [_result("Scalingo", "111111111")]}
        monkeypatch.setattr(
            org_enrichment.requests, "get",
            lambda *a, **k: _FakeResponse(200, payload),
        )
        state = enabled_state()

        record = org_enrichment.resolve("scalingo", "Scalingo", "2026-08-15", state)

        assert record.Match_Status == "MATCHED"
        assert record.Activity_Label == "Information et communication"
        assert record.Activity_Code == "63.11Z"
        assert record.Company_ID == "111111111"
        assert state.calls_matched == 1

    def test_nom_complet_avec_parenthese_najamais_appliquee_au_matching(self, monkeypatch):
        """`nom_complet` compose "Nom (Raison sociale)" : matcher dessus
        casserait une correspondance évidente (constaté sur une réponse
        réelle de l'API). `nom_raison_sociale` doit primer."""
        payload = {"results": [{
            "nom_complet": "SCALINGO (SCALINGO)", "nom_raison_sociale": "SCALINGO",
            "siren": "111111111", "activite_principale": "63.11Z",
            "section_activite_principale": "J",
        }]}
        monkeypatch.setattr(
            org_enrichment.requests, "get",
            lambda *a, **k: _FakeResponse(200, payload),
        )
        state = enabled_state()

        record = org_enrichment.resolve("scalingo", "Scalingo", "2026-08-15", state)

        assert record.Match_Status == "MATCHED"

    def test_aucun_resultat_est_not_found(self, monkeypatch):
        monkeypatch.setattr(
            org_enrichment.requests, "get",
            lambda *a, **k: _FakeResponse(200, {"results": []}),
        )
        state = enabled_state()

        record = org_enrichment.resolve("gedimat", "Gédimat", "2026-08-15", state)

        assert record.Match_Status == "NOT_FOUND"
        assert record.Activity_Label == ""
        assert state.calls_not_found == 1

    def test_plusieurs_sirens_distincts_meme_nom_est_ambiguous(self, monkeypatch):
        """Cas Gédimat : plusieurs entités légales franchisées partagent le
        même nom normalisé. Jamais un choix arbitraire."""
        payload = {"results": [
            _result("Gédimat", "111111111"),
            _result("Gédimat", "222222222"),
        ]}
        monkeypatch.setattr(
            org_enrichment.requests, "get",
            lambda *a, **k: _FakeResponse(200, payload),
        )
        state = enabled_state()

        record = org_enrichment.resolve("gedimat", "Gédimat", "2026-08-15", state)

        assert record.Match_Status == "AMBIGUOUS"
        assert record.Activity_Label == ""
        assert state.calls_ambiguous == 1

    def test_meme_siren_duplique_nest_pas_ambigu(self, monkeypatch):
        payload = {"results": [
            _result("Bureau Vallée", "333333333"),
            _result("Bureau Vallée", "333333333"),
        ]}
        monkeypatch.setattr(
            org_enrichment.requests, "get",
            lambda *a, **k: _FakeResponse(200, payload),
        )
        state = enabled_state()

        record = org_enrichment.resolve("bureau vallee", "Bureau Vallée", "2026-08-15", state)

        assert record.Match_Status == "MATCHED"

    def test_candidats_non_exacts_sont_ignores(self, monkeypatch):
        """Jamais le résultat "le plus proche" : seule une égalité exacte
        de nom normalisé compte."""
        payload = {"results": [_result("Scalingo Cloud Services", "444444444")]}
        monkeypatch.setattr(
            org_enrichment.requests, "get",
            lambda *a, **k: _FakeResponse(200, payload),
        )
        state = enabled_state()

        record = org_enrichment.resolve("scalingo", "Scalingo", "2026-08-15", state)

        assert record.Match_Status == "NOT_FOUND"


class TestCache:
    def test_cache_hit_zero_appel_http(self, monkeypatch):
        state = enabled_state()
        state.cache["scalingo"] = {
            "Organisation_Key": "scalingo", "Query_Name": "Scalingo",
            "Matched_Name": "Scalingo", "Company_ID": "111", "Activity_Code": "6311Z",
            "Activity_Label": "Hébergement de données", "Evidence_Source": "test",
            "Evidence_URL": "", "Match_Status": "MATCHED", "Fetched_At": "2026-08-14",
            "Validated_Sector": "Numérique / Technologie", "Validated_Via": "deterministic",
        }
        monkeypatch.setattr(
            org_enrichment.requests, "get",
            lambda *a, **k: pytest.fail("appel HTTP inattendu"),
        )

        record = org_enrichment.resolve("scalingo", "Scalingo", "2026-08-15", state)

        assert record.Match_Status == "MATCHED"
        assert record.Validated_Sector == "Numérique / Technologie"
        assert state.cache_hits == 1
        assert state.calls_attempted == 0


class TestNetworkRobustness:
    def test_timeout_renvoie_none_et_nest_jamais_mis_en_cache(self, monkeypatch):
        def always_timeout(*a, **k):
            raise org_enrichment.requests.Timeout("délai dépassé")

        monkeypatch.setattr(org_enrichment.requests, "get", always_timeout)
        monkeypatch.setattr(org_enrichment.time, "sleep", lambda *_: None)
        state = enabled_state()

        record = org_enrichment.resolve("orgx", "Org X", "2026-08-15", state)

        assert record is None
        assert state.calls_error == 1
        assert "orgx" not in state.cache

    def test_http_500_apres_retries_renvoie_none(self, monkeypatch):
        monkeypatch.setattr(
            org_enrichment.requests, "get",
            lambda *a, **k: _FakeResponse(500, text="boom"),
        )
        monkeypatch.setattr(org_enrichment.time, "sleep", lambda *_: None)
        state = enabled_state()

        record = org_enrichment.resolve("orgx", "Org X", "2026-08-15", state)

        assert record is None
        assert state.calls_error == 1

    def test_json_invalide_ne_crashe_jamais(self, monkeypatch):
        monkeypatch.setattr(
            org_enrichment.requests, "get",
            lambda *a, **k: _FakeResponse(200, payload=None, text="{not json"),
        )
        state = enabled_state()

        record = org_enrichment.resolve("orgx", "Org X", "2026-08-15", state)

        assert record is None
        assert state.calls_error == 1

    def test_erreur_nest_jamais_cachee_ambigu_lest(self, monkeypatch):
        calls = {"n": 0}

        def always_timeout(*a, **k):
            calls["n"] += 1
            raise org_enrichment.requests.Timeout("délai dépassé")

        monkeypatch.setattr(org_enrichment.requests, "get", always_timeout)
        monkeypatch.setattr(org_enrichment.time, "sleep", lambda *_: None)
        state = enabled_state(max_calls=200)

        org_enrichment.resolve("orgx", "Org X", "2026-08-15", state)
        org_enrichment.resolve("orgx", "Org X", "2026-08-15", state)

        # Deux tentatives complètes (avec leurs retries internes) : jamais
        # de cache pour une ERROR, donc deux vrais appels au total.
        assert calls["n"] == (org_enrichment.ORG_ENRICHMENT_MAX_RETRIES + 1) * 2


class TestBudget:
    def test_budget_epuise_ne_fait_aucun_appel_http(self, monkeypatch):
        monkeypatch.setattr(
            org_enrichment.requests, "get",
            lambda *a, **k: pytest.fail("appel HTTP inattendu"),
        )
        state = enabled_state(max_calls=0)

        record = org_enrichment.resolve("orgx", "Org X", "2026-08-15", state)

        assert record is None
        assert state.calls_attempted == 0


class TestDisabled:
    def test_desactive_ne_fait_aucun_appel(self, monkeypatch):
        monkeypatch.setattr(
            org_enrichment.requests, "get",
            lambda *a, **k: pytest.fail("appel HTTP inattendu"),
        )
        state = org_enrichment.OrgEnrichmentState(enabled=False)

        record = org_enrichment.resolve("orgx", "Org X", "2026-08-15", state)

        assert record is None

    def test_org_key_vide_ne_fait_aucun_appel(self, monkeypatch):
        monkeypatch.setattr(
            org_enrichment.requests, "get",
            lambda *a, **k: pytest.fail("appel HTTP inattendu"),
        )
        state = enabled_state()

        assert org_enrichment.resolve("", "", "2026-08-15", state) is None


class TestPersistence:
    def test_save_and_load_cache_roundtrip(self):
        rows = [{
            "Organisation_Key": "scalingo", "Query_Name": "Scalingo",
            "Matched_Name": "Scalingo", "Company_ID": "111", "Activity_Code": "6311Z",
            "Activity_Label": "Hébergement de données", "Evidence_Source": "test",
            "Evidence_URL": "", "Match_Status": "MATCHED", "Fetched_At": "2026-08-14",
            "Validated_Sector": "Numérique / Technologie", "Validated_Via": "deterministic",
        }]
        store.save_org_enrichment_cache(rows)
        loaded = store.load_org_enrichment_cache()

        assert len(loaded) == 1
        assert loaded[0]["Organisation_Key"] == "scalingo"
        assert loaded[0]["Validated_Sector"] == "Numérique / Technologie"

    def test_start_state_charge_le_cache_existant(self, monkeypatch):
        monkeypatch.setenv("ORG_ENRICHMENT_ENABLED", "1")
        store.save_org_enrichment_cache([{
            "Organisation_Key": "scalingo", "Query_Name": "Scalingo",
            "Matched_Name": "Scalingo", "Company_ID": "111", "Activity_Code": "6311Z",
            "Activity_Label": "Hébergement de données", "Evidence_Source": "test",
            "Evidence_URL": "", "Match_Status": "MATCHED", "Fetched_At": "2026-08-14",
            "Validated_Sector": "", "Validated_Via": "",
        }])

        state = org_enrichment.start_state()

        assert state.enabled is True
        assert "scalingo" in state.cache

    def test_start_state_desactive_par_env(self, monkeypatch):
        monkeypatch.setenv("ORG_ENRICHMENT_ENABLED", "0")
        state = org_enrichment.start_state()
        assert state.enabled is False


class TestCacheVersioning:
    """§Sector fiabilité : un `NOT_FOUND`/`AMBIGUOUS` en cache ne doit jamais
    devenir une réponse négative permanente après un changement de logique."""

    def test_not_found_version_perimee_est_ignore(self, monkeypatch):
        monkeypatch.setenv("ORG_ENRICHMENT_ENABLED", "1")
        store.save_org_enrichment_cache([{
            "Organisation_Key": "orgx", "Query_Name": "Org X",
            "Match_Status": "NOT_FOUND", "Fetched_At": "2026-08-10",
            "Cache_Version": "",
        }])

        state = org_enrichment.start_state()

        assert "orgx" not in state.cache

    def test_not_found_meme_version_reste_charge(self, monkeypatch):
        monkeypatch.setenv("ORG_ENRICHMENT_ENABLED", "1")
        store.save_org_enrichment_cache([{
            "Organisation_Key": "orgx", "Query_Name": "Org X",
            "Match_Status": "NOT_FOUND", "Fetched_At": "2026-08-10",
            "Cache_Version": org_enrichment.ORG_ENRICHMENT_CACHE_VERSION,
        }])

        state = org_enrichment.start_state()

        assert "orgx" in state.cache

    def test_matched_version_perimee_conserve_donnees_reinitialise_validation(self, monkeypatch):
        monkeypatch.setenv("ORG_ENRICHMENT_ENABLED", "1")
        store.save_org_enrichment_cache([{
            "Organisation_Key": "scalingo", "Query_Name": "Scalingo",
            "Matched_Name": "Scalingo", "Company_ID": "111", "Activity_Code": "6311Z",
            "Activity_Label": "Information et communication", "Evidence_Source": "test",
            "Evidence_URL": "", "Match_Status": "MATCHED", "Fetched_At": "2026-08-10",
            "Validated_Sector": "Numérique / Technologie", "Validated_Via": "deterministic",
            "Cache_Version": "",
        }])

        state = org_enrichment.start_state()

        assert "scalingo" in state.cache
        row = state.cache["scalingo"]
        assert row["Activity_Label"] == "Information et communication"
        assert row["Company_ID"] == "111"
        assert row["Validated_Sector"] == ""
        assert row["Validated_Via"] == ""
        assert row["Cache_Version"] == org_enrichment.ORG_ENRICHMENT_CACHE_VERSION

    def test_resolve_stampe_la_version_courante(self, monkeypatch):
        monkeypatch.setattr(
            org_enrichment.requests, "get",
            lambda *a, **k: _FakeResponse(200, payload={"results": []}),
        )
        state = enabled_state()

        record = org_enrichment.resolve("orgx", "Org X", "2026-08-15", state)

        assert record.Cache_Version == org_enrichment.ORG_ENRICHMENT_CACHE_VERSION
