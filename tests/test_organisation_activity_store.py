"""Référentiel de preuves : TTL, idempotence et invalidation.

Aucun test n'accède au réseau ni n'écrit dans data/ réel.
"""
import pytest
import requests

from cyberwatch import org_identity
from cyberwatch import organisation_activity as oa
from cyberwatch import organisation_activity_store as evidence

QUOTE = "PassPass est un service de vente de titres de transport."
BUDGETS = dict(ttl_days=180, rejected_ttl_days=30, unresolved_ttl_days=14)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(requests.Session, "request",
                        lambda *a, **k: pytest.fail("réseau interdit"))
    monkeypatch.setattr(org_identity, "ORGANISATION_IDENTITY_REGISTRY", {})


def _evidence(**kwargs):
    base = dict(organisation="PassPass", organisation_key="passpass",
                activity_description=QUOTE, evidence_quote=QUOTE,
                evidence_url="https://exemple-passpass.fr/a",
                source_type=oa.SOURCE_OFFICIAL_SITE, provider=oa.PROVIDER_OWNED_URL,
                verified_at="2026-03-01T10:00:00+00:00", content_hash="abc123",
                verification_method=oa.VERIFY_PROSE_LITERAL)
    return oa.VerifiedActivityEvidence(**{**base, **kwargs})


def test_verified_at_n_avance_jamais_sur_une_relecture():
    """Le bug d'idempotence le plus probable : sans colonne séparée, deux runs
    identiques produiraient des faits différents."""
    proof = _evidence()
    row = evidence.from_evidence(proof, run_id="RUN-2",
                                 last_checked_at="2026-09-12T00:00:00+00:00")
    assert row.Verified_At == proof.verified_at
    assert row.Last_Checked_At != proof.verified_at
    assert evidence.to_evidence(row) == proof


def test_le_ttl_se_compte_sur_le_dernier_controle_pas_sur_la_preuve():
    rows = evidence.upsert({}, evidence.from_evidence(_evidence(), run_id="R"))
    assert evidence.lookup(rows, "passpass", now="2026-06-01T00:00:00+00:00",
                           **BUDGETS)[1] == evidence.HIT
    assert evidence.lookup(rows, "passpass", now="2026-09-12T00:00:00+00:00",
                           **BUDGETS)[1] == evidence.EXPIRED


@pytest.mark.parametrize("status,days_ok,days_expired", [
    (evidence.STATUS_REJECTED, 10, 40),
    (evidence.STATUS_UNRESOLVED, 5, 20),
])
def test_un_echec_est_memorise_et_reconsidere_a_son_propre_rythme(status, days_ok, days_expired):
    """Une organisation sans preuve possible n'est pas réinterrogée chaque jour,
    mais un refus n'est pas définitif : un site peut publier la page manquante."""
    row = evidence.outcome_row("PassPass", "passpass", status=status,
                               rejection_code=oa.EXTERNAL_NO_CANDIDATE,
                               last_checked_at="2026-03-01T00:00:00+00:00")
    rows = evidence.upsert({}, row)
    early = f"2026-03-{1 + days_ok:02d}T00:00:00+00:00"
    assert evidence.lookup(rows, "passpass", now=early, **BUDGETS)[1] == evidence.HIT
    late = f"2026-0{3 + days_expired // 30}-{1 + days_expired % 30:02d}T00:00:00+00:00"
    assert evidence.lookup(rows, "passpass", now=late, **BUDGETS)[1] == evidence.EXPIRED


def test_une_panne_de_transport_est_reessayee_au_run_suivant():
    """Un zéro n'est un vrai zéro que si l'on a pu essayer : ERROR n'apprend
    rien, donc n'est jamais mémorisé comme un refus."""
    rows = evidence.upsert({}, evidence.outcome_row(
        "PassPass", "passpass", status=evidence.STATUS_ERROR,
        rejection_code=oa.EXTERNAL_BUDGET_EXHAUSTED,
        last_checked_at="2026-03-01T00:00:00+00:00"))
    assert evidence.lookup(rows, "passpass", now="2026-03-01T12:00:00+00:00",
                           **BUDGETS)[1] == evidence.EXPIRED


def test_une_ligne_retiree_est_collante_et_jamais_rejouee():
    rows = evidence.upsert({}, evidence.outcome_row(
        "PassPass", "passpass", status=evidence.STATUS_WITHDRAWN,
        rejection_code=oa.EXTERNAL_WITHDRAWN,
        last_checked_at="2020-01-01T00:00:00+00:00"))
    row, verdict = evidence.lookup(rows, "passpass", now="2026-09-12T00:00:00+00:00",
                                   **BUDGETS)
    assert verdict == evidence.WITHDRAWN
    assert evidence.to_evidence(row) is None


def test_un_changement_d_alias_invalide_la_ligne(monkeypatch):
    """`effective_organisation_key` peut avoir déplacé l'organisation : la ligne
    ne parle alors plus de la même entité."""
    rows = evidence.upsert({}, evidence.from_evidence(_evidence(), run_id="R"))
    assert evidence.lookup(rows, "passpass", now="2026-03-02T00:00:00+00:00",
                           **BUDGETS)[1] == evidence.HIT
    monkeypatch.setattr(org_identity, "ORGANISATION_IDENTITY_REGISTRY",
                        {"passpass": "mobilite exemple"})
    assert evidence.lookup(rows, "passpass", now="2026-03-02T00:00:00+00:00",
                           **BUDGETS)[1] == evidence.INVALID


@pytest.mark.parametrize("field", ["Activity_Description", "Evidence_Quote",
                                   "Content_Hash", "Verified_At"])
def test_une_preuve_amputee_est_invalide(field):
    row = evidence.from_evidence(_evidence(), run_id="R")
    broken = evidence.EvidenceRow.from_row({**row.to_row(), field: ""})
    assert evidence.invalidation(broken) == evidence.INVALID
    assert evidence.to_evidence(broken) is None


def test_une_methode_de_verification_inconnue_est_invalide():
    row = evidence.from_evidence(_evidence(verification_method="INVENTEE"), run_id="R")
    assert evidence.to_evidence(row) is None


def test_le_referentiel_se_relit_a_l_identique():
    rows = evidence.upsert({}, evidence.from_evidence(_evidence(), run_id="R"))
    serialised = evidence.to_rows(rows)
    assert [row["Organisation_Key"] for row in serialised] == ["passpass"]
    assert evidence.load(serialised) == rows
    # Une clé vide n'écrit rien plutôt que de créer une ligne orpheline.
    assert evidence.upsert(rows, evidence.EvidenceRow()) == rows


def test_il_n_existe_pas_de_statut_shadow():
    """Shadow est une propriété du run, pas de la preuve : c'est ce qui fait de
    l'activation un simple basculement de drapeau, sans une seule requête."""
    assert "SHADOW" not in evidence.STATUSES
    assert evidence.STATUSES == {"VERIFIED", "REJECTED", "UNRESOLVED", "WITHDRAWN", "ERROR"}
