"""Régressions issues de l'audit de la collecte du 9 septembre 2026."""
from __future__ import annotations

import json
from pathlib import Path


FIXTURE = Path(__file__).parent / "fixtures" / "latest_collection_20260909.json"


def _payloads():
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    return payload["facts"], {row["id"]: row for row in payload["latest"]}


def test_aroma_zone_ne_publie_que_les_donnees_de_contact():
    details, latest = _payloads()
    incident = latest["INC-2AF4C7544CC3"]
    detail = details["INC-2AF4C7544CC3"]
    assert incident["sector"] == "Commerce / Distribution"
    assert "threat_actor" not in detail["fields"]
    assert {row["value"] for row in detail["data_types"]} == {
        "adresses e-mail", "numéros de téléphone", "noms et prénoms",
    }
    assert detail["vulnerabilities"][0]["relationship"] == "mentioned"


def test_financiere_uzes_reste_une_revendication_sans_donnees_clients():
    details, latest = _payloads()
    incident = latest["INC-09D2AFD7707B"]
    detail = details["INC-09D2AFD7707B"]
    assert incident["threat_status"]["status"] == "claimed"
    assert detail["fields"]["data_volume"]["status"] == "claimed"
    assert "fine_location" not in detail["fields"]
    assert detail["datasets"] == []
    assert "a déclaré avoir subi" not in detail["display_summary"]


def test_proshop_transporte_les_commandes_sans_credentials():
    details, latest = _payloads()
    incident = latest["INC-72E15EC21567"]
    detail = details["INC-72E15EC21567"]
    assert incident["sector"] == "Commerce / Distribution"
    assert incident["threat_status"]["status"] == "claimed"
    assert any(
        row["value"] == 118_000 and row["unit"] == "records" and row["status"] == "claimed"
        for row in detail["affected"]
    )
    assert incident["credentials_or_secrets_exposed"] is False
    assert "références de commande" in {row["value"] for row in detail["data_types"]}


def test_vision2i_separe_identifiants_techniques_et_cve_contextuelles():
    details, latest = _payloads()
    incident = latest["INC-06870EC77814"]
    detail = details["INC-06870EC77814"]
    assert incident["sector"] == "Services aux entreprises"
    assert incident["threat"] == "Fuite de données"
    assert incident["credentials_or_secrets_exposed"] is False
    assert "identifiants techniques" in {row["value"] for row in detail["data_types"]}
    assert {row["relationship"] for row in detail["vulnerabilities"]} == {
        "candidate", "mentioned",
    }
    assert "cvss" not in detail["fields"]
    assert all("**" not in row["event"] for row in detail["timeline"])
