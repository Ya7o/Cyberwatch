from cyberwatch import (
    company_evidence,
    company_subject_evidence,
    config,
    official_site_discovery,
)


def test_subject_attribution_accepts_named_victim_activity():
    result = company_subject_evidence.classify_subject_attributed_activity(
        "Intermarché",
        "Intermarché est une enseigne de supermarchés française spécialisée dans le commerce alimentaire.",
    )
    assert result is not None
    assert result[0] == config.SECTOR_RETAIL


def test_subject_attribution_accepts_first_person_activity():
    result = company_subject_evidence.classify_subject_attributed_activity(
        "Acme Cloud",
        "Nous sommes un éditeur de logiciels SaaS et proposons des services cloud aux entreprises.",
    )
    assert result is not None
    assert result[0] == config.SECTOR_TECH


def test_subject_attribution_rejects_supplier_activity_stor_regression():
    assert company_subject_evidence.classify_subject_attributed_activity(
        "STOR Solutions",
        "STOR Solutions travaille avec Iagona, son fournisseur, fabricant de solutions libre-service.",
    ) is None


def test_subject_attribution_rejects_partner_activity():
    assert company_subject_evidence.classify_subject_attributed_activity(
        "Acme",
        "Acme s'appuie sur Beta, partenaire spécialisé dans la construction et le génie civil.",
    ) is None


def test_strict_resolver_requires_identity_and_subject(monkeypatch):
    monkeypatch.setattr(
        official_site_discovery,
        "discover_official_sites",
        lambda organisation, hint_urls=(): ["https://www.intermarche.com/"],
    )
    monkeypatch.setattr(
        company_evidence,
        "_page",
        lambda url: (
            "Intermarché - site officiel",
            "Intermarché est une enseigne de supermarchés française.",
            [],
            "https://www.intermarche.com/",
        ),
    )
    evidence = company_subject_evidence.resolve_official_site_subject_attributed(
        "Intermarché"
    )
    assert evidence is not None
    assert evidence.sector == config.SECTOR_RETAIL
    assert evidence.evidence_type == "official_subject_activity"


def test_strict_resolver_rejects_third_party_domain_even_if_text_mentions_victim(monkeypatch):
    monkeypatch.setattr(
        company_evidence,
        "_page",
        lambda url: (
            "Intermarché : présentation",
            "Intermarché est une enseigne de supermarchés française.",
            [],
            url,
        ),
    )
    evidence = company_subject_evidence.resolve_official_site_subject_attributed(
        "Intermarché",
        ["https://actualites-exemple.fr/intermarche"],
    )
    assert evidence is None


def test_strict_resolver_accepts_acronym_domain(monkeypatch):
    assert official_site_discovery.domain_matches_organisation(
        "Bibliothèque Nationale de France", "https://www.bnf.fr/"
    )
    monkeypatch.setattr(
        company_evidence,
        "_page",
        lambda url: (
            "Bibliothèque nationale de France",
            "La Bibliothèque Nationale de France est une institution culturelle publique.",
            [],
            "https://www.bnf.fr/",
        ),
    )
    # Le secteur Culture n'est pas dans les motifs stricts actuels ; le test
    # vérifie donc uniquement que le garde de domaine ne rejette pas l'acronyme.
    assert company_subject_evidence.resolve_official_site_subject_attributed(
        "Bibliothèque Nationale de France", ["https://www.bnf.fr/"]
    ) is None
