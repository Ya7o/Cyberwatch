"""Défauts métier observés entre collecte et dashboard le 7 octobre 2026."""
import copy
import json

import pytest

from cyberwatch import config, sector, sector_activity, source_facts, source_facts_ai, threat_resolution


@pytest.mark.parametrize("market", ["l'hôtellerie", "les établissements de santé", "les écoles"])
def test_software_publisher_keeps_its_activity(market):
    assert sector.classify_sector_activity(
        f"Medialog, éditeur français de logiciels de gestion pour {market}."
    ) == config.SECTOR_TECH


def test_incident_notification_does_not_prove_publisher_activity():
    assert not sector_activity.supported_activity(
        "Medialog", "Medialog est un éditeur de logiciels pour les hôtels.",
        "Medialog informe ses clients d’un incident de sécurité ayant permis "
        "d’accéder aux réservations enregistrées dans son logiciel Medialog Hôtel.",
    )
    assert sector_activity.supported_activity(
        "Medialog", "Medialog est un éditeur de logiciels pour les hôtels.",
        "Medialog, éditeur de logiciels pour les hôtels, confirme une cyberattaque.",
    )


def test_client_records_extraction_is_a_leak_even_after_an_intrusion(make_item):
    item = make_item(org="Medialog", threat=config.THREAT_INTRUSION)
    facts = {item.Item_ID: [{
        "Claim_Status": "confirmed",
        "Summary": "Medialog a subi une extraction d'environ 135 Go de fiches clients.",
    }]}
    assert threat_resolution.resolve_component([item], facts).value == config.THREAT_LEAK


@pytest.mark.parametrize("verb", ["n'étaient pas accessibles", "ne sont pas concernés", "n'ont pas été exposés"])
def test_denied_identity_documents_are_not_extracted(verb):
    context = f"Les numéros de pièces d'identité {verb}. Des données ont été extraites."
    assert source_facts_ai._deterministic_data_types(context) == []


def test_a_denial_on_account_count_does_not_deny_password_exposure():
    context = ("Il n’est pas possible d’affirmer que l’ensemble des comptes sont concernés, "
               "mais une fuite de mots de passe est documentée dans une base.")
    assert [row["value"] for row in source_facts_ai._deterministic_data_types(context)] == ["mots de passe"]


def test_stored_denial_is_repaired_without_losing_positive_proof():
    denial = "Les pièces d'identité n'étaient pas accessibles."
    metadata = {"editorial_context": denial + " Les adresses e-mail ont été exposées.",
                "rich_facts": {"data_types": [
                    {"value": "pièces d'identité", "status": "reported", "evidence": denial},
                ]}}
    fact = {"Item_ID": "preserved-id", "Data_Types_JSON": json.dumps([
        "pièces d'identité", "adresses e-mail",
    ]), "Evidence_JSON": json.dumps({"Data_Types_JSON": {
        "pièces d'identité": "pièces d'identité", "adresses e-mail": "adresses e-mail",
    }}), "Source_Metadata_JSON": json.dumps(metadata)}
    rows, changed = source_facts.sanitize_source_facts([fact])
    assert changed == ["preserved-id"]
    assert json.loads(rows[0]["Data_Types_JSON"]) == ["adresses e-mail"]
    rich = json.loads(rows[0]["Source_Metadata_JSON"])["rich_facts"]
    assert rich["data_types"][0]["status"] == "negated"
    assert rich["data_types"][0]["evidence"] == denial
    before = copy.deepcopy(rows)
    assert source_facts.sanitize_source_facts(rows) == (before, [])


def test_one_clause_denial_does_not_remove_exposure_in_another_clause():
    context = ("Les adresses e-mail ont été exposées, mais les pièces d'identité "
               "n'étaient pas accessibles.")
    assert not source_facts_ai._negated_data_type("adresses e-mail", "adresses e-mail", context)
    assert source_facts_ai._negated_data_type("pièces d'identité", "pièces d'identité", context)
