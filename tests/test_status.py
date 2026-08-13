"""Modèle de statuts refondu : Status, Coverage, Reason et statut global."""

import pytest

from cyberwatch import config, status
from cyberwatch.collectors.base import CollectResult, RawEntry


def outcome(source_id, layer, st, coverage):
    return status.SourceOutcome(
        source_id=source_id, layer=layer, status=st, coverage=coverage
    )


class TestCoverage:
    @pytest.mark.parametrize(
        "done,expected,result",
        [(120, 176, 68), (176, 176, 100), (0, 176, 0), (5, 0, 100), (200, 176, 100)],
    )
    def test_calcul(self, done, expected, result):
        assert status.compute_coverage(done, expected) == result


class TestResolveStatus:
    """Un statut se lit sans ambiguïté : trois cas seulement."""

    def test_borne_atteinte_donne_ok(self):
        result = CollectResult(reached_boundary=True, units_done=3, units_expected=3)
        assert result.resolve() == (status.OK, 100)

    def test_ok_avec_zero_item_est_un_zero_verifie(self):
        """Remplace l'ancien EMPTY : un zéro sûr, pas une anomalie."""
        result = CollectResult(reached_boundary=True, units_done=1, units_expected=1)
        st, coverage = result.resolve()
        assert (st, coverage) == (status.OK, 100)
        assert result.entries == []

    def test_parcours_interrompu_donne_partial_chiffre(self):
        result = CollectResult(
            entries=[RawEntry()], units_done=120, units_expected=176
        )
        assert result.resolve() == (status.PARTIAL, 68)

    def test_partial_ne_peut_pas_atteindre_100(self):
        """Sans borne atteinte, on ne revendique jamais une couverture pleine."""
        result = CollectResult(entries=[RawEntry()], units_done=50, units_expected=50)
        st, coverage = result.resolve()
        assert st == status.PARTIAL
        assert coverage == 99

    def test_rien_d_exploitable_donne_fail(self):
        result = CollectResult(reason_code=status.REASON_NO_FEED)
        assert result.resolve() == (status.FAIL, 0)

    @pytest.mark.parametrize(
        "reason",
        [status.REASON_ROBOTS, status.REASON_LAYER_NOT_SCHEDULED,
         status.REASON_SOURCE_INACTIVE],
    )
    def test_hors_perimetre_donne_skipped(self, reason):
        """SKIPPED n'est pas une erreur : remplace l'ambigu NOT_RUN."""
        assert CollectResult(reason_code=reason).resolve() == (status.SKIPPED, 0)


class TestZeroIsTrusted:
    def test_zero_fiable_si_ok(self):
        assert status.SourceOutcome("S", config.LAYER_CORE, status.OK, 100).zero_is_trusted

    def test_zero_non_fiable_si_partial(self):
        assert not status.SourceOutcome(
            "S", config.LAYER_CORE, status.PARTIAL, 40
        ).zero_is_trusted

    def test_zero_non_fiable_si_fail(self):
        assert not status.SourceOutcome(
            "S", config.LAYER_CORE, status.FAIL, 0
        ).zero_is_trusted


class TestHealthScore:
    def test_toutes_sources_ok(self):
        outcomes = [
            outcome("A", config.LAYER_CORE, status.OK, 100),
            outcome("B", config.LAYER_REGIONAL_WATCH, status.OK, 100),
        ]
        assert status.health_score(outcomes) == 100

    def test_ponderation_des_couches_centrales(self):
        """Une source centrale pèse trois fois plus qu'une source de veille."""
        outcomes = [
            outcome("core", config.LAYER_CORE, status.OK, 100),
            outcome("watch", config.LAYER_REGIONAL_WATCH, status.FAIL, 0),
        ]
        assert status.health_score(outcomes) == 75

    def test_skipped_exclu_du_calcul(self):
        """Ne pas avoir interrogé une couche non planifiée n'est pas un défaut."""
        outcomes = [
            outcome("A", config.LAYER_CORE, status.OK, 100),
            outcome("B", config.LAYER_ENTITY_WATCH, status.SKIPPED, 0),
        ]
        assert status.health_score(outcomes) == 100


class TestOverallStatus:
    def test_healthy(self):
        outcomes = [
            outcome("A", config.LAYER_CORE, status.OK, 100),
            outcome("B", config.LAYER_ENTITY_WATCH, status.SKIPPED, 0),
        ]
        assert status.overall_status(outcomes) == status.HEALTHY

    def test_degraded_si_source_secondaire_partielle(self):
        outcomes = [
            outcome("A", config.LAYER_CORE, status.OK, 100),
            outcome("B", config.LAYER_CORE, status.OK, 100),
            outcome("C", config.LAYER_REGIONAL_WATCH, status.PARTIAL, 60),
        ]
        assert status.overall_status(outcomes) == status.DEGRADED

    def test_broken_si_source_centrale_en_echec(self):
        outcomes = [
            outcome("A", config.LAYER_CORE, status.FAIL, 0),
            outcome("B", config.LAYER_CORE, status.OK, 100),
            outcome("C", config.LAYER_CORE, status.OK, 100),
        ]
        assert status.overall_status(outcomes) == status.BROKEN

    def test_broken_si_score_trop_bas(self):
        outcomes = [
            outcome("A", config.LAYER_CORE, status.PARTIAL, 20),
            outcome("B", config.LAYER_REGIONAL_WATCH, status.PARTIAL, 20),
        ]
        assert status.overall_status(outcomes) == status.BROKEN

    def test_aucune_source_consideree(self):
        outcomes = [outcome("A", config.LAYER_CORE, status.SKIPPED, 0)]
        assert status.overall_status(outcomes) == status.BROKEN


class TestBlindSpots:
    def test_liste_les_sources_incompletes(self):
        outcomes = [
            outcome("OK_SRC", config.LAYER_CORE, status.OK, 100),
            outcome("PARTIEL", config.LAYER_ENTITY_WATCH, status.PARTIAL, 68),
            outcome("ECHEC", config.LAYER_CORE, status.FAIL, 0),
        ]
        spots = status.blind_spots(outcomes)
        assert [s["source_id"] for s in spots] == ["ECHEC", "PARTIEL"]

    def test_aucun_angle_mort_si_tout_va_bien(self):
        assert status.blind_spots([outcome("A", config.LAYER_CORE, status.OK, 100)]) == []


class TestReasonTexts:
    def test_chaque_code_a_une_phrase(self):
        codes = [
            status.REASON_OK, status.REASON_NO_FEED, status.REASON_HTTP_403,
            status.REASON_HTTP_429, status.REASON_ROBOTS,
            status.REASON_LAYER_NOT_SCHEDULED, status.REASON_BUDGET_RUN,
        ]
        for code in codes:
            assert status.reason_text(code) != code
            assert status.reason_text(code).strip()


class TestReasonCoherence:
    """Un statut dégradé ne doit jamais porter la raison « tout va bien »."""

    def test_fail_ne_porte_jamais_reason_ok(self):
        result = CollectResult(reason_code=status.REASON_OK)
        assert result.resolve() == (status.FAIL, 0)
        assert result.reason_code == status.REASON_NO_RESULT
        assert status.reason_text(result.reason_code) != status.reason_text(
            status.REASON_OK
        )

    def test_partial_ne_porte_jamais_reason_ok(self):
        result = CollectResult(
            entries=[RawEntry()], units_done=5, units_expected=20,
            reason_code=status.REASON_OK,
        )
        source_status, _coverage = result.resolve()
        assert source_status == status.PARTIAL
        # Dire « rien d'exploitable » d'une source partiellement aboutie
        # serait aussi faux que de la dire complète.
        assert result.reason_code == status.REASON_INCOMPLETE
        assert "partiellement" in status.reason_text(result.reason_code)

    def test_cause_reelle_conservee(self):
        result = CollectResult(reason_code=status.REASON_HTTP_429)
        assert result.resolve() == (status.FAIL, 0)
        assert result.reason_code == status.REASON_HTTP_429

    def test_ok_conserve_sa_raison(self):
        result = CollectResult(reached_boundary=True, units_done=1, units_expected=1)
        assert result.resolve() == (status.OK, 100)
        assert result.reason_code == status.REASON_OK
