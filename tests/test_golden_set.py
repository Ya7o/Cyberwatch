from pathlib import Path

from cyberwatch import config
from cyberwatch.golden import blind_candidates, evaluate, match_golden, validate_file, validate_golden
from cyberwatch.golden_challengers import (
    canonical_challenger_rows,
    compare_challengers,
    match_challenger,
    normalize_challenger_location,
)

ROOT = Path(__file__).resolve().parents[1]


def _golden_row(**overrides):
    row = {
        "Golden_ID": "GOLD-0001",
        "Organisation": "Centre Exemple",
        "Organisation_Key": "centre exemple",
        "Reference_Date": "2026-06-01",
        "Source_IDs": "BONJOURLAFUITE",
        "Source_URLs": "https://example.test/reference-1",
        "Secteur_REF": config.SECTOR_HEALTH,
        "Menace_REF": config.THREAT_LEAK,
        "Localisation_REF": config.LOC_FRANCE,
        "Secteur_Confidence": "HIGH",
        "Menace_Confidence": "HIGH",
        "Localisation_Confidence": "HIGH",
        "Secteur_Evidence": "activité de santé explicitement décrite",
        "Menace_Evidence": "publication de données explicitement décrite",
        "Localisation_Evidence": "implantation française explicitement décrite",
        "Incident_ID_Snapshot": "INC-OLD",
        "Reviewed_At": "2026-08-16",
        "Golden_Version": "1",
        "Taxonomy_Version": config.METHOD_ID,
    }
    row.update(overrides)
    return row


def _incident(**overrides):
    row = {
        "Incident_ID": "INC-NEW",
        "Date": "2026-06-02",
        "Organisation": "Centre Exemple",
        "Secteur": config.SECTOR_HEALTH,
        "Menace": config.THREAT_INTRUSION,
        "Localisation": config.LOC_FRANCE,
        "Sources": "BONJOURLAFUITE",
        "Source_URLs": "https://example.test/reference-1",
    }
    row.update(overrides)
    return row


def _challenger(**overrides):
    row = {
        "date": "2026-06-01",
        "organisation": "Exemple Centre",
        "territoire": "France",
        "localisation": "Paris",
        "secteur": config.SECTOR_HEALTH,
        "type_menace": config.THREAT_LEAK,
        "source_urls": "https://example.test/reference-1",
    }
    row.update(overrides)
    return row


def test_repository_golden_file_contract_is_valid():
    assert validate_file(ROOT / "data" / "golden" / "qualification_golden.csv") == []


def test_blind_candidates_do_not_leak_current_labels():
    row = blind_candidates([_incident()])[0]
    assert "Secteur" not in row
    assert "Menace" not in row
    assert "Localisation" not in row
    assert row["Organisation_Key"] == "centre exemple"


def test_valid_golden_row_passes_contract():
    assert validate_golden([_golden_row()]) == []


def test_out_of_taxonomy_value_is_rejected():
    problems = validate_golden([_golden_row(Secteur_REF="Categorie absente")])
    assert any("Secteur_REF hors nomenclature" in problem for problem in problems)


def test_matching_survives_incident_id_change():
    result = match_golden(_golden_row(), [_incident()])
    assert result.status == "MATCHED"
    assert result.strategy == "source_url"
    assert result.incident["Incident_ID"] == "INC-NEW"


def test_evaluation_separates_unknown_from_wrong_classification():
    result = evaluate([_golden_row()], [_incident()])
    assert result["fields"]["Secteur"]["accuracy_pct"] == 100.0
    assert result["fields"]["Menace"]["wrong_classification"] == 1
    assert result["fields"]["Menace"]["resolvable_unknown"] == 0

    unknown_result = evaluate([_golden_row()], [_incident(Menace=config.THREAT_UNKNOWN)])
    assert unknown_result["fields"]["Menace"]["wrong_classification"] == 0
    assert unknown_result["fields"]["Menace"]["resolvable_unknown"] == 1


def test_challenger_location_is_mapped_to_cyberwatch_taxonomy():
    assert normalize_challenger_location("France") == config.LOC_FRANCE
    assert normalize_challenger_location("La Réunion") == config.LOC_REUNION
    assert normalize_challenger_location("États-Unis") == config.LOC_INCONNU


def test_challenger_source_url_beats_name_word_order():
    rows = canonical_challenger_rows([_challenger()], "FRENCHBREACHES_LLM")
    result = match_challenger(_golden_row(), rows, "FRENCHBREACHES_LLM")
    assert result.status == "MATCHED"
    assert result.strategy == "source_url"
    assert result.incident["Organisation"] == "Exemple Centre"


def test_comparison_counts_llm_gain_without_hiding_regressions():
    result = compare_challengers(
        [_golden_row()],
        [_incident(Menace=config.THREAT_INTRUSION)],
        {"FRENCHBREACHES_LLM": [_challenger()]},
    )
    threat = result["pairwise_vs_db"]["FRENCHBREACHES_LLM"]["Menace"]
    assert threat["common_matched_cases"] == 1
    assert threat["gains"] == 1
    assert threat["regressions"] == 0
    assert threat["delta_accuracy_pp"] == 100.0

    sector = result["pairwise_vs_db"]["FRENCHBREACHES_LLM"]["Secteur"]
    assert sector["both_correct"] == 1
    assert sector["gains"] == 0
    assert sector["regressions"] == 0
