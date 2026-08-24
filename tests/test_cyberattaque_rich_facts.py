from __future__ import annotations

import json

from cyberwatch.collectors.base import RawEntry
from cyberwatch.collectors.cyberattaque_rich import enrich_entry_metadata
from cyberwatch.site import _source_fact_payload


def _dgfip_entry() -> RawEntry:
    return RawEntry(
        title="DGFiP : 1,8 million de comptes compromis après une cyberattaque",
        summary=(
            "La DGFiP confirme que 1,8 million de comptes liés aux données cadastrales "
            "ont été compromis."
        ),
        content=(
            "Le 29 juillet 2026, le groupe ZeroBytes revendique une attaque contre le "
            "Serveur Professionnel de Données Cadastrales (SPDC) et affirme avoir extrait "
            "252 149 lignes. Selon l'attaquant, ces lignes concerneraient 2 041 778 personnes. "
            "Après plusieurs jours d'investigations, la DGFiP confirme que 1,8 million de "
            "comptes liés aux données cadastrales ont été compromis. L'administration "
            "reconnaît également une compromission concernant les successions vacantes."
        ),
    )


def test_rich_metadata_preserves_multiple_counts_and_scopes():
    entry = _dgfip_entry()
    enrich_entry_metadata(entry)

    rich = entry.source_metadata["rich_facts"]
    counts = rich["affected_counts"]

    assert {(row["value"], row["unit"]) for row in counts} >= {
        (1_800_000, "accounts"),
        (252_149, "records"),
        (2_041_778, "people"),
    }
    confirmed = [row for row in counts if row["value"] == 1_800_000][0]
    assert confirmed["status"] == "confirmed"
    assert confirmed["scope"] == "données cadastrales"

    claimed = [row for row in counts if row["value"] == 252_149][0]
    assert claimed["status"] == "claimed"
    assert claimed["scope"] == "SPDC"
    assert claimed["date"] == "2026-07-29"

    assert any(row["value"] == "SPDC" for row in rich["affected_systems"])
    datasets = {row["value"] for row in rich["affected_datasets"]}
    assert "données cadastrales" in datasets
    assert "successions vacantes" in datasets


def test_rich_metadata_keeps_evidence_and_claim_statuses():
    entry = _dgfip_entry()
    enrich_entry_metadata(entry)
    claims = entry.source_metadata["rich_facts"]["claims"]

    assert any(claim["status"] == "claimed" and "ZeroBytes" in claim["evidence"] for claim in claims)
    assert any(claim["status"] == "confirmed" and "DGFiP confirme" in claim["evidence"] for claim in claims)
    assert all(claim.get("evidence") for claim in claims)


def test_data_types_in_bullets_inherit_the_nearby_incident_context():
    entry = RawEntry(
        title="Exemple : fuite de données",
        content="Les données exposées comprennent :\n- des adresses e-mail\n- des adresses postales\n- des contrats\n- des IBAN.",
    )
    enrich_entry_metadata(entry)
    values = {row["value"] for row in entry.source_metadata["rich_facts"]["data_types"]}
    assert {"adresses e-mail", "adresses postales", "contrats", "données bancaires"} <= values


def test_site_payload_publishes_sanitized_rich_facts():
    entry = _dgfip_entry()
    enrich_entry_metadata(entry)
    row = {
        "Item_ID": "item-1",
        "Source_ID": "CYBERATTAQUE_ORG",
        "Affected_Count": "1800000",
        "Affected_Unit": "accounts",
        "Affected_Count_Raw": "1,8 million de comptes",
        "Source_Metadata_JSON": json.dumps(entry.source_metadata, ensure_ascii=False),
    }

    payload = _source_fact_payload(row)

    assert payload is not None
    assert payload["affected_count"] == 1_800_000
    assert payload["rich_facts"]["affected_counts"][0]["status"] == "confirmed"
    assert len(payload["rich_facts"]["affected_counts"]) >= 3
    assert payload["rich_facts"]["affected_systems"][0]["value"] == "SPDC"


def test_site_payload_rejects_malformed_rich_metadata_without_breaking_legacy_fact():
    row = {
        "Item_ID": "item-2",
        "Source_ID": "CYBERATTAQUE_ORG",
        "Affected_Count": "42",
        "Affected_Unit": "accounts",
        "Source_Metadata_JSON": "{not-json",
    }

    payload = _source_fact_payload(row)

    assert payload is not None
    assert payload["affected_count"] == 42
    assert "rich_facts" not in payload
