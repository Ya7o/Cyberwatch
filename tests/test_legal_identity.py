from cyberwatch import legal_identity, org_enrichment


class _Response:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

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


def test_cache_row_keeps_legal_identity_and_naf_as_evidence():
    evidence = legal_identity.LegalIdentityEvidence(
        siren="325707537",
        siret="32570753700042",
        evidence_url="https://www.clenet.com/mentions-legales",
        evidence_text="SIREN 325707537",
    )
    candidate = {
        "siren": "325707537",
        "nom_raison_sociale": "CLENET",
        "activite_principale": "45.11Z",
        "section_activite_principale": "G",
        "siege": {"departement": "49"},
    }

    row = legal_identity.cache_row(
        "clenet", "Clenet", "2026-08-19T00:00:00+00:00", evidence, candidate
    )

    assert row["Company_ID"] == "325707537"
    assert row["Activity_Code"] == "45.11Z"
    assert row["Activity_Label"] == org_enrichment.NAF_SECTION_LABELS["G"]
    assert row["Headquarters_Department"] == "49"
    assert row["Match_Status"] == org_enrichment.MATCHED
    assert row["Validated_Sector"] == ""
    assert row["Validated_Via"] == "legal_identity"
