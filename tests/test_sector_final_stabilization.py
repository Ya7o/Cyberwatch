"""Sentinelles finales de précision pour la qualification Sector."""

from types import SimpleNamespace

from cyberwatch import company_evidence, config, org_enrichment, runner, sector
from cyberwatch.collectors.base import RawEntry, SourceSpec


class _Response:
    status_code = 200
    text = ""

    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


def _candidate(name: str, siren: str, *, section: str, code: str = "00.00Z") -> dict:
    return {
        "nom_complet": f"{name} ({name})",
        "nom_raison_sociale": name,
        "siren": siren,
        "activite_principale": code,
        "section_activite_principale": section,
    }


def _state() -> org_enrichment.OrgEnrichmentState:
    return org_enrichment.OrgEnrichmentState(
        enabled=True,
        max_calls=20,
        official_site_max_calls=20,
    )


def test_federation_francaise_non_sportive_ne_devient_pas_sport():
    name = "Fédération française de l’Ordre Maçonnique Mixte International Le Droit Humain"
    assert sector.classify_sector_name(name) == config.SECTOR_UNKNOWN


def test_federations_sportives_reconnues_restent_sport():
    assert sector.classify_sector_name("Fédération Française de Handball") == config.SECTOR_SPORT
    assert sector.classify_sector_name("Fédération Française de Karaté") == config.SECTOR_SPORT
    assert sector.classify_sector_name("Fédération Française de Danse") == config.SECTOR_SPORT


def test_federations_sportives_auditees_sont_couvertes():
    cases = (
        "Fédération Française d’Équitation",
        "Fédération Française de Bridge",
        "Fédération Française de Ski",
        "Fédération française de Savate",
        "Fédération Française de Vol Libre",
        "Fédération Française d'Aéronautique",
        "Fédération Française de Montagne Escalade",
        "Fédération Française de squash",
        "Fédération Française d’ULM",
        "Fédération Française Handisport",
    )
    for name in cases:
        assert sector.classify_sector_name(name) == config.SECTOR_SPORT, name


def test_variantes_institutionnelles_sures_sont_classees():
    assert sector.classify_sector_name("Mairie d’Eyguières") == config.SECTOR_ADMIN
    assert sector.classify_sector_name("The commune of Castries") == config.SECTOR_ADMIN
    assert sector.classify_sector_name("Université d’Avignon") == config.SECTOR_EDUCATION
    assert sector.classify_sector_name("Université Bourgogne Europe") == config.SECTOR_EDUCATION
    assert sector.classify_sector_name("Mutuelle Générale de Prévoyance") == config.SECTOR_FINANCE


def test_variantes_administration_auditees_sont_couvertes():
    cases = (
        "Ville d’Orléans",
        "Nantes Métropole",
        "Rennes Métropole",
        "La Région Occitanie",
        "FR Ministry of Agriculture",
        "Service Public",
        "France Services",
        "Centre Communal d’Action Sociale de Dunkerque",
    )
    for name in cases:
        assert sector.classify_sector_name(name) == config.SECTOR_ADMIN, name


def test_variantes_sante_auditees_sont_couvertes():
    cases = (
        "Santé publique France",
        "Agence Régionale de Santé",
        "Clinique Ambroise Paré Beuvry",
        "Centre d’imagerie médicale de Puteaux",
        "Fédération Hospitalière de France",
    )
    for name in cases:
        assert sector.classify_sector_name(name) == config.SECTOR_HEALTH, name


def test_variantes_education_auditees_sont_couvertes():
    cases = (
        "École élémentaire Montaigne de Roubaix",
        "PSB Paris School of Business",
        "PPA Business School",
        "Sciences Po",
        "Enseignement catholique",
    )
    for name in cases:
        assert sector.classify_sector_name(name) == config.SECTOR_EDUCATION, name


def test_naf_immobilier_registre_ne_devient_plus_preuve_btp():
    record = org_enrichment._record_from_candidate(
        "mcdonald s",
        "McDonald's France",
        _candidate("McDonald's France", "722003936", section="L", code="68.20B"),
        "2026-08-17",
    )
    assert record.Activity_Label == ""
    assert record.Validated_Sector == ""


def test_acronymes_courts_exigent_confirmation_d_identite():
    assert org_enrichment._identity_requires_confirmation("ENSAM") is True
    assert org_enrichment._identity_requires_confirmation("CROUS") is True
    assert org_enrichment._identity_requires_confirmation("AFPA") is True
    assert org_enrichment._identity_requires_confirmation("Scalingo") is False


def test_ensam_homonyme_financier_est_rejete_sans_preuve_officielle(monkeypatch):
    payload = {"results": [_candidate("ENSAM", "985115880", section="K", code="64.20Z")]}
    monkeypatch.setattr(org_enrichment.requests, "get", lambda *a, **k: _Response(payload))
    monkeypatch.setattr(company_evidence, "resolve_official_site", lambda *_: None)

    record = org_enrichment.resolve(
        "ecole nationale superieure d arts et metiers",
        "ENSAM",
        "2026-08-17",
        _state(),
    )

    assert record is not None
    assert record.Match_Status == org_enrichment.AMBIGUOUS
    assert record.Activity_Label == ""
    assert record.Validated_Sector == ""


def test_crous_homonyme_btp_est_rejete_sans_preuve_officielle(monkeypatch):
    payload = {"results": [_candidate("CROUS", "523806735", section="F", code="41.20B")]}
    monkeypatch.setattr(org_enrichment.requests, "get", lambda *a, **k: _Response(payload))
    monkeypatch.setattr(company_evidence, "resolve_official_site", lambda *_: None)

    record = org_enrichment.resolve("crous", "CROUS", "2026-08-17", _state())

    assert record is not None
    assert record.Match_Status == org_enrichment.AMBIGUOUS
    assert record.Validated_Sector == ""


def test_acronyme_peut_etre_resolu_par_preuve_officielle(monkeypatch):
    payload = {"results": [_candidate("ENSAM", "985115880", section="K", code="64.20Z")]}
    monkeypatch.setattr(org_enrichment.requests, "get", lambda *a, **k: _Response(payload))
    monkeypatch.setattr(
        company_evidence,
        "resolve_official_site",
        lambda *_: company_evidence.CompanyEvidence(
            sector=config.SECTOR_EDUCATION,
            evidence_url="https://www.ensam.eu/",
            evidence_text="Établissement public d'enseignement supérieur.",
        ),
    )

    record = org_enrichment.resolve(
        "ecole nationale superieure d arts et metiers",
        "ENSAM",
        "2026-08-17",
        _state(),
    )

    assert record is not None
    assert record.Match_Status == org_enrichment.MATCHED
    assert record.Validated_Sector == config.SECTOR_EDUCATION
    assert record.Validated_Via == "official_site"


def test_ransomware_native_sector_est_corrige_par_preuve_entreprise_plus_forte(make_item, monkeypatch):
    item = make_item(
        source="RANSOMWARE_LIVE",
        org="Eiffage",
        sector=config.SECTOR_TRANSPORT,
        threat=config.THREAT_RANSOMWARE,
        location=config.LOC_FRANCE,
    )
    entry = RawEntry(
        title="Eiffage revendiqué par un groupe ransomware",
        published="2026-03-01",
        organisation="Eiffage",
        sector="Transportation",
    )
    spec = SourceSpec(
        source_id="RANSOMWARE_LIVE",
        layer=config.LAYER_CORE,
        zone="Multi",
        collector="ransomware_live",
    )
    record = org_enrichment.OrgEnrichmentRecord(
        Organisation_Key=item.Organisation_Key,
        Query_Name="Eiffage",
        Matched_Name="EIFFAGE",
        Company_ID="709802094",
        Activity_Label="Construction",
        Match_Status=org_enrichment.MATCHED,
        Fetched_At="2026-08-17",
        Cache_Version=org_enrichment.ORG_ENRICHMENT_CACHE_VERSION,
    )
    monkeypatch.setattr(org_enrichment, "resolve", lambda *a, **k: record)
    state = SimpleNamespace(org_enrichment=org_enrichment.OrgEnrichmentState(enabled=True))

    runner._verify_native_ransomware_sector(item, entry, spec, state)

    assert item.Sector == config.SECTOR_CONSTRUCTION


def test_ransomware_native_sector_najamais_corrige_par_site_officiel(make_item, monkeypatch):
    """Refonte 2026-08-26 ("preuves partout, décision unique à la fin"),
    même garde-fou que ai.py::_escalate_org_enrichment_deterministic : un
    Validated_Via == "official_site" (texte de site scrappé, jamais un code
    NAF) ne doit plus jamais corriger directement le secteur natif — cas
    réel Klark AI qui a motivé cette refonte."""
    item = make_item(
        source="RANSOMWARE_LIVE",
        org="Eiffage",
        sector=config.SECTOR_TRANSPORT,
        threat=config.THREAT_RANSOMWARE,
        location=config.LOC_FRANCE,
    )
    entry = RawEntry(
        title="Eiffage revendiqué par un groupe ransomware",
        published="2026-03-01",
        organisation="Eiffage",
        sector="Transportation",
    )
    spec = SourceSpec(
        source_id="RANSOMWARE_LIVE",
        layer=config.LAYER_CORE,
        zone="Multi",
        collector="ransomware_live",
    )
    record = org_enrichment.OrgEnrichmentRecord(
        Organisation_Key=item.Organisation_Key,
        Query_Name="Eiffage",
        Matched_Name="Eiffage",
        Activity_Label="Eiffage, leader du BTP et des concessions.",
        Match_Status=org_enrichment.MATCHED,
        Fetched_At="2026-08-17",
        Validated_Sector=config.SECTOR_CONSTRUCTION,
        Validated_Via="official_site",
        Cache_Version=org_enrichment.ORG_ENRICHMENT_CACHE_VERSION,
    )
    monkeypatch.setattr(org_enrichment, "resolve", lambda *a, **k: record)
    state = SimpleNamespace(org_enrichment=org_enrichment.OrgEnrichmentState(enabled=True))

    runner._verify_native_ransomware_sector(item, entry, spec, state)

    assert item.Sector == config.SECTOR_TRANSPORT


def test_ransomware_native_sector_reste_fallback_sans_preuve_plus_forte(make_item, monkeypatch):
    item = make_item(
        source="RANSOMWARE_LIVE",
        org="Transport Exemple",
        sector=config.SECTOR_TRANSPORT,
        threat=config.THREAT_RANSOMWARE,
        location=config.LOC_FRANCE,
    )
    entry = RawEntry(
        title="Transport Exemple revendiqué",
        published="2026-03-01",
        organisation="Transport Exemple",
        sector="Transportation",
    )
    spec = SourceSpec(
        source_id="RANSOMWARE_LIVE",
        layer=config.LAYER_CORE,
        zone="Multi",
        collector="ransomware_live",
    )
    monkeypatch.setattr(org_enrichment, "resolve", lambda *a, **k: None)
    state = SimpleNamespace(org_enrichment=org_enrichment.OrgEnrichmentState(enabled=True))

    runner._verify_native_ransomware_sector(item, entry, spec, state)

    assert item.Sector == config.SECTOR_TRANSPORT
