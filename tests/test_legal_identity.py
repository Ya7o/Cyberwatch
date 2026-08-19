from cyberwatch import legal_identity, org_enrichment


class _Response:
    def __init__(self, payload, status_code=200, text=""):
        self._payload = payload
        self.status_code = status_code
        self.text = text

    def json(self):
        return self._payload


def test_extract_siret_derives_siren():
    siren, siret = legal_identity.extract_legal_ids(
        "Mentions légales — SIRET : 325 707 537 00042 — RCS Angers"
    )
    assert siren == "325707537"
    assert siret == "32570753700042"


def test_extract_siren_from_rcs():
    siren, siret = legal_identity.extract_legal_ids(
        "Société CLENET — RCS Angers 325 707 537 — capital social 100 000 euros"
    )
    assert siren == "325707537"
    assert siret == ""


def test_unlabelled_number_is_never_a_legal_identity():
    assert legal_identity.extract_legal_ids(
        "Contact 02 41 12 34 56. Plus de 325707537 références disponibles."
    ) == ("", "")


def test_extract_jsonld_organization_identity():
    structured = legal_identity.extract_structured_identity(
        '''<html><script type="application/ld+json">{
        "@context":"https://schema.org","@type":"Organization",
        "name":"EVA Nantes Sud","legalName":"EVA FRANCE SAS",
        "telephone":"02 00 00 00 00","description":"Salle de réalité virtuelle",
        "address":{"@type":"PostalAddress","streetAddress":"10 rue du Jeu",
        "postalCode":"44400","addressLocality":"Rezé"}}
        </script></html>'''
    )
    assert structured.name == "EVA Nantes Sud"
    assert structured.legal_name == "EVA FRANCE SAS"
    assert structured.postal_code == "44400"
    assert structured.city == "Rezé"


def test_jsonld_non_organization_is_ignored():
    structured = legal_identity.extract_structured_identity(
        '<script type="application/ld+json">{"@type":"Article","name":"Clenet"}</script>'
    )
    assert structured == legal_identity.StructuredIdentity()


def test_discover_legal_identity_reads_legal_notice_on_validated_domain(monkeypatch):
    monkeypatch.setattr(
        legal_identity.official_site_discovery,
        "discover_official_sites",
        lambda organisation: ["https://www.clenet.com/"],
    )
    monkeypatch.setattr(
        legal_identity.official_site_discovery,
        "domain_matches_organisation",
        lambda organisation, url: "clenet.com" in url,
    )
    monkeypatch.setattr(
        legal_identity.company_evidence,
        "_identity_matches",
        lambda *args: True,
    )
    monkeypatch.setattr(
        legal_identity,
        "_fetch_structured_identity",
        lambda url: legal_identity.StructuredIdentity(
            legal_name="CLENET SARL", postal_code="49124", city="Saint-Barthélemy-d'Anjou"
        ),
    )

    def page(url):
        if "mentions-legales" in url:
            return (
                "Mentions légales",
                "CLENET SARL. SIREN : 325 707 537. RCS Angers.",
                [],
                url,
            )
        return (
            "CLENET - Vente et Location de solutions de manutention",
            "CLENET accompagne les professionnels.",
            ["https://www.clenet.com/mentions-legales"],
            "https://www.clenet.com/",
        )

    monkeypatch.setattr(legal_identity.company_evidence, "_page", page)

    evidence = legal_identity.discover_from_official_site("Clenet")

    assert evidence is not None
    assert evidence.siren == "325707537"
    assert evidence.evidence_url.endswith("mentions-legales")
    assert evidence.structured.postal_code == "49124"


def test_registry_candidate_requires_exact_siren(monkeypatch):
    payload = {
        "results": [
            {"siren": "057202046", "nom_raison_sociale": "CLENET MOTORS"},
            {"siren": "325707537", "nom_raison_sociale": "CLENET"},
        ]
    }
    monkeypatch.setattr(
        legal_identity.requests,
        "get",
        lambda *args, **kwargs: _Response(payload),
    )

    candidate = legal_identity.fetch_registry_candidate("325707537")

    assert candidate is not None
    assert candidate["nom_raison_sociale"] == "CLENET"


def test_best_establishment_prefers_exact_siret_over_headquarters():
    evidence = legal_identity.LegalIdentityEvidence(
        siren="123456789",
        siret="12345678900042",
        evidence_url="https://eva.gg/mentions-legales",
        evidence_text="SIRET 12345678900042",
        structured=legal_identity.StructuredIdentity(postal_code="44400", city="Rezé"),
    )
    candidate = {
        "siege": {"siret": "12345678900018", "departement": "75", "code_postal": "75001", "libelle_commune": "Paris"},
        "matching_etablissements": [
            {"siret": "12345678900042", "departement": "44", "code_postal": "44400", "libelle_commune": "Rezé", "activite_principale": "93.29Z", "section_activite_principale": "R"}
        ],
    }
    row, score = legal_identity.best_establishment(candidate, evidence)
    assert row["siret"] == "12345678900042"
    assert score >= 10


def test_address_can_select_local_establishment_without_siret():
    evidence = legal_identity.LegalIdentityEvidence(
        siren="123456789",
        siret="",
        evidence_url="https://eva.gg/",
        evidence_text="SIREN 123456789",
        structured=legal_identity.StructuredIdentity(
            street="10 rue du Jeu", postal_code="44400", city="Rezé"
        ),
    )
    candidate = {
        "siege": {"departement": "75", "code_postal": "75001", "libelle_commune": "Paris"},
        "matching_etablissements": [
            {"departement": "44", "code_postal": "44400", "libelle_commune": "Rezé", "adresse": "10 rue du Jeu"}
        ],
    }
    row, score = legal_identity.best_establishment(candidate, evidence)
    assert row["departement"] == "44"
    assert score >= 6


def test_name_or_city_alone_does_not_select_legal_company():
    evidence = legal_identity.LegalIdentityEvidence(
        siren="123456789", siret="", evidence_url="https://example.com", evidence_text="SIREN 123456789",
        structured=legal_identity.StructuredIdentity(city="Paris"),
    )
    candidate = {"siege": {"departement": "75", "libelle_commune": "Paris"}}
    _row, score = legal_identity.best_establishment(candidate, evidence)
    assert score < 6


def test_cache_row_keeps_brand_legal_name_and_naf_as_evidence():
    evidence = legal_identity.LegalIdentityEvidence(
        siren="325707537",
        siret="32570753700042",
        evidence_url="https://www.clenet.com/mentions-legales",
        evidence_text="SIREN 325707537",
    )
    candidate = {
        "siren": "325707537",
        "nom_raison_sociale": "CLENET MANUTENTION",
        "activite_principale": "45.11Z",
        "section_activite_principale": "G",
        "siege": {"siret": "32570753700042", "departement": "49"},
    }

    row = legal_identity.cache_row(
        "clenet", "Clenet", "2026-08-19T00:00:00+00:00", evidence, candidate
    )

    assert row["Query_Name"] == "Clenet"
    assert row["Matched_Name"] == "CLENET MANUTENTION"
    assert row["Company_ID"] == "325707537"
    assert row["Activity_Code"] == "45.11Z"
    assert row["Activity_Label"] == org_enrichment.NAF_SECTION_LABELS["G"]
    assert row["Headquarters_Department"] == "49"
    assert row["Match_Status"] == org_enrichment.MATCHED
    assert row["Validated_Sector"] == ""
    assert row["Validated_Via"] == "legal_identity_siret"
