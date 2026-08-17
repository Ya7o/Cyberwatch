import json

from cyberwatch import config
from cyberwatch.model import Item
from cyberwatch.source_llm_fallback import (
    ChallengerRecord,
    apply_source_llm_fallback,
    canonical_location,
    load_records,
)


def _item(**kwargs):
    values = dict(
        Item_ID="ITEM-1",
        Source_ID="FRENCHBREACHES",
        Published_Date="2026-06-01",
        Organisation_Raw="Exemple SA",
        Organisation_Key="exemple sa",
        Threat=config.THREAT_LEAK,
        Sector=config.SECTOR_UNKNOWN,
        Location=config.LOC_INCONNU,
        URL="https://frenchbreaches.com/alertes/exemple",
    )
    values.update(kwargs)
    return Item(**values)


def _record(**kwargs):
    values = dict(
        source_id="FRENCHBREACHES",
        date="2026-06-01",
        organisation="Exemple SA",
        organisation_key="exemple sa",
        urls=("https://frenchbreaches.com/alertes/exemple",),
        sector=config.SECTOR_HEALTH,
        location=config.LOC_FRANCE,
        threat=config.THREAT_INTRUSION,
        raw_location="France",
        evidence_urls=(),
        activity_evidence=(),
    )
    values.update(kwargs)
    return ChallengerRecord(**values)


def test_canonical_location_respects_taxonomy():
    assert canonical_location("Paris, Île-de-France") == config.LOC_FRANCE
    assert canonical_location("La Réunion") == config.LOC_REUNION
    assert canonical_location("Mayotte (976)") == config.LOC_MAYOTTE
    assert canonical_location("États-Unis") == config.LOC_INCONNU


def test_location_fallback_applies_on_exact_url():
    item = _item()
    stats, provenance = apply_source_llm_fallback(
        [item], {"FRENCHBREACHES": [_record()]}
    )
    assert item.Location == config.LOC_FRANCE
    assert stats["llm_location_fallback"] == 1
    assert any(
        row["Field"] == "Location" and row["Decision"] == "APPLIED"
        for row in provenance
    )


def test_known_location_is_never_overwritten():
    item = _item(Location=config.LOC_REUNION)
    apply_source_llm_fallback(
        [item], {"FRENCHBREACHES": [_record(location=config.LOC_FRANCE)]}
    )
    assert item.Location == config.LOC_REUNION


def test_sector_requires_exact_url_official_identity_and_activity_evidence():
    item = _item()
    record = _record(
        evidence_urls=("https://www.exemple.fr/activite",),
        activity_evidence=("hôpital et services de santé",),
    )
    stats, provenance = apply_source_llm_fallback(
        [item], {"FRENCHBREACHES": [record]}
    )
    assert item.Sector == config.SECTOR_HEALTH
    assert stats["llm_sector_fallback"] == 1
    assert any(
        row["Field"] == "Sector" and row["Decision"] == "APPLIED"
        for row in provenance
    )


def test_sector_without_external_evidence_is_rejected():
    item = _item()
    stats, provenance = apply_source_llm_fallback(
        [item], {"FRENCHBREACHES": [_record()]}
    )
    assert item.Sector == config.SECTOR_UNKNOWN
    assert stats["llm_sector_rejected"] == 1
    assert stats["llm_sector_identity_rejected"] == 1
    assert any(
        row["Field"] == "Sector"
        and row["Decision"] == "REJECTED_IDENTITY_EVIDENCE"
        for row in provenance
    )


def test_registry_or_directory_url_cannot_validate_identity():
    item = _item(Organisation_Raw="Adobe", Organisation_Key="adobe")
    record = _record(
        organisation="Adobe",
        organisation_key="adobe",
        sector=config.SECTOR_CONSTRUCTION,
        evidence_urls=("https://www.pappers.fr/entreprise/adobe-949079610",),
        activity_evidence=("activités immobilières",),
    )
    stats, provenance = apply_source_llm_fallback(
        [item], {"FRENCHBREACHES": [record]}
    )
    assert item.Sector == config.SECTOR_UNKNOWN
    assert stats["llm_sector_identity_rejected"] == 1
    assert any(
        row["Field"] == "Sector"
        and row["Decision"] == "REJECTED_IDENTITY_EVIDENCE"
        for row in provenance
    )


def test_unrelated_official_domain_cannot_validate_identity():
    item = _item(Organisation_Raw="Adobe", Organisation_Key="adobe")
    record = _record(
        organisation="Adobe",
        organisation_key="adobe",
        sector=config.SECTOR_TECH,
        evidence_urls=("https://www.unrelated-example.com/about",),
        activity_evidence=("éditeur de logiciels",),
    )
    stats, _ = apply_source_llm_fallback(
        [item], {"FRENCHBREACHES": [record]}
    )
    assert item.Sector == config.SECTOR_UNKNOWN
    assert stats["llm_sector_identity_rejected"] == 1


def test_sector_without_explicit_activity_is_rejected():
    item = _item()
    record = _record(
        evidence_urls=("https://www.exemple.fr/a-propos",),
        activity_evidence=("Exemple accompagne ses clients depuis 20 ans.",),
    )
    stats, provenance = apply_source_llm_fallback(
        [item], {"FRENCHBREACHES": [record]}
    )
    assert item.Sector == config.SECTOR_UNKNOWN
    assert stats["llm_sector_activity_rejected"] == 1
    assert any(
        row["Field"] == "Sector"
        and row["Decision"] == "REJECTED_NO_ACTIVITY_EVIDENCE"
        for row in provenance
    )


def test_sector_conflict_between_json_and_activity_is_rejected():
    item = _item()
    record = _record(
        sector=config.SECTOR_FINANCE,
        evidence_urls=("https://www.exemple.fr/a-propos",),
        activity_evidence=("éditeur de logiciels",),
    )
    stats, provenance = apply_source_llm_fallback(
        [item], {"FRENCHBREACHES": [record]}
    )
    assert item.Sector == config.SECTOR_UNKNOWN
    assert stats["llm_sector_conflict_rejected"] == 1
    assert any(
        row["Field"] == "Sector"
        and row["Decision"] == "REJECTED_SECTOR_CONFLICT"
        for row in provenance
    )


def test_known_sector_is_never_overwritten():
    item = _item(Sector=config.SECTOR_FINANCE)
    record = _record(
        evidence_urls=("https://www.exemple.fr/activite",),
        activity_evidence=("hôpital et services de santé",),
    )
    apply_source_llm_fallback([item], {"FRENCHBREACHES": [record]})
    assert item.Sector == config.SECTOR_FINANCE


def test_threat_challenger_is_diagnostic_only():
    item = _item(Threat=config.THREAT_LEAK)
    _, provenance = apply_source_llm_fallback(
        [item], {"FRENCHBREACHES": [_record(threat=config.THREAT_INTRUSION)]}
    )
    assert item.Threat == config.THREAT_LEAK
    assert any(
        row["Field"] == "Threat" and row["Decision"] == "PROTECTED"
        for row in provenance
    )


def test_unique_org_date_can_fill_location_but_not_sector():
    item = _item(URL="https://frenchbreaches.com/alertes/autre")
    record = _record(
        urls=("https://frenchbreaches.com/alertes/sans-recouvrement",),
        evidence_urls=("https://www.exemple.fr/activite",),
        activity_evidence=("hôpital et services de santé",),
    )
    stats, _ = apply_source_llm_fallback(
        [item], {"FRENCHBREACHES": [record]}
    )
    assert item.Location == config.LOC_FRANCE
    assert item.Sector == config.SECTOR_UNKNOWN
    assert stats["llm_location_fallback"] == 1
    assert stats["llm_sector_rejected"] == 1


def test_ambiguous_org_date_is_refused():
    item = _item(URL="")
    records = [
        _record(),
        _record(
            date="2026-06-02",
            urls=("https://frenchbreaches.com/alertes/second",),
        ),
    ]
    stats, _ = apply_source_llm_fallback(
        [item], {"FRENCHBREACHES": records}
    )
    assert item.Location == config.LOC_INCONNU
    assert item.Sector == config.SECTOR_UNKNOWN
    assert stats["llm_match_ambiguous"] == 1


def test_load_records_does_not_treat_generic_sources_as_sector_evidence(tmp_path):
    path = tmp_path / "challenger.json"
    path.write_text(
        json.dumps(
            {
                "incidents": [
                    {
                        "date": "2026-06-01",
                        "organisation": "Exemple SA",
                        "secteur": config.SECTOR_HEALTH,
                        "territoire": "France",
                        "type_menace": config.THREAT_LEAK,
                        "sources": [
                            "https://frenchbreaches.com/alertes/exemple",
                            "https://www.exemple.fr/a-propos",
                        ],
                        "sector_evidence_text": "hôpital et services de santé",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    record = load_records(path, "FRENCHBREACHES")[0]
    assert record.urls == (
        "https://frenchbreaches.com/alertes/exemple",
        "https://www.exemple.fr/a-propos",
    )
    assert record.evidence_urls == ()
    assert record.activity_evidence == ("hôpital et services de santé",)


def test_load_records_reads_only_structured_sector_evidence_url(tmp_path):
    path = tmp_path / "challenger.json"
    path.write_text(
        json.dumps(
            {
                "incidents": [
                    {
                        "date": "2026-06-01",
                        "organisation": "Exemple SA",
                        "secteur": config.SECTOR_HEALTH,
                        "territoire": "France",
                        "type_menace": config.THREAT_LEAK,
                        "sources": ["https://frenchbreaches.com/alertes/exemple"],
                        "sector_evidence_url": "https://www.exemple.fr/a-propos",
                        "sector_evidence_text": "hôpital et services de santé",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    record = load_records(path, "FRENCHBREACHES")[0]
    assert record.evidence_urls == ("https://www.exemple.fr/a-propos",)
    assert record.activity_evidence == ("hôpital et services de santé",)

    item = _item(Organisation_Key=record.organisation_key)
    stats, _ = apply_source_llm_fallback(
        [item], {"FRENCHBREACHES": [record]}
    )
    assert stats["llm_sector_fallback"] == 1
    assert item.Sector == config.SECTOR_HEALTH
