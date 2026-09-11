"""Reprise ciblée du snapshot audité — périmètre, simulation, idempotence.

L'état audité `RUN-20260910T072351` est reconstitué à partir de
`audit/latest_collection_2026-09-10/run_snapshot.json`, qui fige ses 2 nouvelles
observations, leurs faits et son registre d'incidents, et d'un témoin figé. Le test
travaille dans un répertoire de données temporaire et n'écrit jamais dans
`data/` ni dans `assets/data/`.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from cyberwatch import store

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_audited_snapshot as builder  # noqa: E402

FRENCHBREACHES_ITEM = builder.FRENCHBREACHES_ITEM
CYBERATTAQUE_ITEM = builder.CYBERATTAQUE_ITEM
SURVIVING_INCIDENT = builder.SURVIVING_INCIDENT
REDIRECTED_INCIDENT = builder.REDIRECTED_INCIDENT


@pytest.fixture
def audited_snapshot(tmp_path, monkeypatch):
    """Deux observations auditées et un témoin indépendant, figés dans les fixtures."""
    if not builder.available():
        pytest.skip("preuves d'audit absentes de l'arbre")
    data = builder.build(tmp_path, base_data=ROOT / "tests/fixtures/targeted_repair")
    for name, target in builder.store_targets(tmp_path).items():
        monkeypatch.setattr(store, name, target)

    from cyberwatch import editorial_corrections, org_identity, site
    monkeypatch.setattr(
        editorial_corrections, "CORRECTIONS_PATH", data / "editorial_corrections.json"
    )
    # L'état audité porte son propre registre d'identité : `effective_organisation_key`
    # lit un singleton de module, chargé depuis `data/` à l'import.
    monkeypatch.setattr(
        org_identity, "ORGANISATION_IDENTITY_REGISTRY",
        org_identity.load_organisation_identity_registry(
            data / "organisation_identity_registry.csv"
        ),
    )
    monkeypatch.setattr(site, "build", lambda: (0, 0))
    return data


def _repair(*args: str) -> int:
    path = Path(__file__).resolve().parents[1] / "scripts" / "apply_editorial_corrections.py"
    spec = importlib.util.spec_from_file_location("apply_editorial_corrections", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.REPAIR_REPORT_PATH = store.DATA_DIR / "editorial_repair_report.json"
    module.DEDUP_REVIEW_QUEUE_PATH = store.DATA_DIR / "dedup_review_queue.json"
    return module.main(list(args))


SCOPE = ("--items", f"{FRENCHBREACHES_ITEM},{CYBERATTAQUE_ITEM}")


def test_la_simulation_est_le_defaut_et_ne_touche_rien(audited_snapshot, capsys):
    """Sans `--write`, l'état de départ est intact et le rapport est détaillé.

    Le corpus de départ est figé. Aucune observation ne doit disparaître et
    seuls les deux incidents ciblés doivent fusionner.
    """
    items_before = len(store.read_csv(store.ITEMS_CSV))
    incidents_before = len(store.read_csv(store.INCIDENTS_CSV))
    before = (store.ITEMS_CSV.read_bytes(), store.INCIDENTS_CSV.read_bytes())
    assert _repair(*SCOPE) == 0
    assert (store.ITEMS_CSV.read_bytes(), store.INCIDENTS_CSV.read_bytes()) == before

    summary = json.loads(capsys.readouterr().out)
    assert summary["written"] is False
    assert summary["items_before"] == items_before
    assert summary["items_after"] == items_before
    assert summary["incidents_before"] == incidents_before
    assert summary["incidents_after"] == incidents_before - 1
    assert summary["new_redirects"] == {REDIRECTED_INCIDENT: SURVIVING_INCIDENT}

    report = json.loads((store.DATA_DIR / "editorial_repair_report.json").read_text(encoding="utf-8"))
    assert report["changes"]["incidents"][REDIRECTED_INCIDENT]["removed"]
    assert report["changes"]["incidents"][SURVIVING_INCIDENT]["Menace"] == {
        "before": "Fuite de données", "after": "Inconnu",
    }


def test_la_reprise_ciblee_fusionne_et_redirige(audited_snapshot, capsys):
    """Toutes les observations conservées, un incident de moins, redirection valide."""
    items_before = len(store.read_csv(store.ITEMS_CSV))
    incidents_before = len(store.read_csv(store.INCIDENTS_CSV))
    assert _repair(*SCOPE, "--write") == 0
    capsys.readouterr()

    items = store.load_items()
    incidents = store.load_incidents()
    assert len(items) == items_before
    assert len(incidents) == incidents_before - 1

    survivor = next(row for row in incidents if row.Incident_ID == SURVIVING_INCIDENT)
    assert survivor.Items_Count == 2
    assert set(str(survivor.Sources).split(" | ")) == {"FRENCHBREACHES", "CYBERATTAQUE_ORG"}
    assert survivor.Menace == "Inconnu"
    assert survivor.Secteur == "Administration / Collectivité"
    assert survivor.Localisation == "La Réunion"
    assert survivor.Organisation == "Le Tampon"
    assert REDIRECTED_INCIDENT not in {row.Incident_ID for row in incidents}

    registry = {row["Incident_ID"]: row for row in store.load_incident_id_registry()}
    assert registry[REDIRECTED_INCIDENT]["Redirect_To"] == SURVIVING_INCIDENT
    assert registry[SURVIVING_INCIDENT]["Redirect_To"] == ""


def test_la_file_de_dedoublonnage_est_reconciliee_sans_etre_videe(audited_snapshot, capsys):
    """La paire traitée sort de la file ; les demandes non résolues restent."""
    assert _repair(*SCOPE, "--write") == 0
    capsys.readouterr()
    queue = json.loads((store.DATA_DIR / "dedup_review_queue.json").read_text(encoding="utf-8"))
    assert [row["pair_key"] for row in queue] == ["ITM-autre|ITM-encore"]


def test_le_hors_perimetre_est_inchange(audited_snapshot, capsys):
    """Aucune autre observation ni aucun autre incident ne bouge."""
    before_items = {row["Item_ID"]: row for row in store.read_csv(store.ITEMS_CSV)}
    before_incidents = {row["Incident_ID"]: row for row in store.read_csv(store.INCIDENTS_CSV)}
    assert _repair(*SCOPE, "--write") == 0
    capsys.readouterr()

    scope = {FRENCHBREACHES_ITEM, CYBERATTAQUE_ITEM}
    after_items = {row["Item_ID"]: row for row in store.read_csv(store.ITEMS_CSV)}
    for item_id, row in after_items.items():
        if item_id not in scope:
            assert row == before_items[item_id], item_id

    touched = {SURVIVING_INCIDENT, REDIRECTED_INCIDENT}
    after_incidents = {row["Incident_ID"]: row for row in store.read_csv(store.INCIDENTS_CSV)}
    for incident_id, row in after_incidents.items():
        if incident_id not in touched:
            assert row == before_incidents[incident_id], incident_id


def test_deux_reprises_successives_sont_idempotentes(audited_snapshot, capsys):
    """Rejouer la reprise ne change plus rien."""
    assert _repair(*SCOPE, "--write") == 0
    capsys.readouterr()
    first = (store.ITEMS_CSV.read_bytes(), store.INCIDENTS_CSV.read_bytes(),
             store.INCIDENT_ID_REGISTRY_CSV.read_bytes())

    assert _repair(*SCOPE, "--write") == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["changed_items"] == []
    assert summary["changed_incidents"] == []
    assert summary["new_redirects"] == {}
    assert (store.ITEMS_CSV.read_bytes(), store.INCIDENTS_CSV.read_bytes(),
            store.INCIDENT_ID_REGISTRY_CSV.read_bytes()) == first


def test_un_perimetre_trop_etroit_refuse_l_ecriture(audited_snapshot, capsys):
    """Une observation qui bougerait hors périmètre bloque l'écriture."""
    before = store.INCIDENTS_CSV.read_bytes()
    assert _repair("--items", FRENCHBREACHES_ITEM, "--write") == 1
    assert store.INCIDENTS_CSV.read_bytes() == before
    summary = json.loads(capsys.readouterr().out)
    assert summary["written"] is False
    assert summary["problems"]
    # L'observation Cyberattaque.org change aussi — sa menace « Ransomware »
    # n'est pas étayée — mais elle n'est pas dans le périmètre déclaré.
    assert CYBERATTAQUE_ITEM in summary["out_of_scope"]["items"]


def test_une_observation_absente_est_signalee(audited_snapshot, capsys):
    """Un périmètre qui nomme une observation inexistante ne s'exécute pas."""
    assert _repair("--items", "ITM-inexistant", "--write") == 1
    summary = json.loads(capsys.readouterr().out)
    assert any("ITM-inexistant" in problem for problem in summary["problems"])
