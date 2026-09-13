"""Registre public : jamais de conclusion sur la seule concordance de nom.

La charge « Qare » de ce fichier est celle réellement mesurée sur
recherche-entreprises.api.gouv.fr le 2026-09-12. Aucun test n'accède au réseau.
"""
import json

import pytest
import requests

from cyberwatch import config, org_identity
from cyberwatch import organisation_activity as oa
from cyberwatch import organisation_activity_registry as registry
from cyberwatch.normalize import organisation_key
from cyberwatch.sector_activity import supported_activity

#: Réponse réelle de l'API pour q=qare : une société de location immobilière
#: du Haut-Rhin, qui n'est PAS la plateforme de téléconsultation du corpus.
QARE = json.dumps({"results": [{
    "siren": "921071882", "nom_complet": "QARE", "nom_raison_sociale": "QARE",
    "etat_administratif": "A", "activite_principale": "68.20B",
    "siege": {"libelle_commune": "RIXHEIM", "departement": "68"}}]})

DUPONT = json.dumps({"results": [{
    "siren": "123456789", "nom_complet": "TRANSPORTS DUPONT",
    "etat_administratif": "A", "activite_principale": "49.41A",
    "siege": {"libelle_commune": "SAINTE-MARIE", "departement": "974"}}]})


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(requests.Session, "request",
                        lambda *a, **k: pytest.fail("réseau interdit"))
    monkeypatch.setattr(org_identity, "ORGANISATION_IDENTITY_REGISTRY", {})


def test_la_concordance_de_nom_seule_ne_suffit_pas_sur_le_cas_qare():
    """Le cas qui justifie toute la corroboration : la fiche concorde par le
    nom, est active, et décrit une autre entreprise. L'accepter publierait
    Construction / BTP sur une organisation de santé, depuis son seul nom."""
    record, rejection = registry.select(registry.parse(QARE), organisation_key("Qare"))
    assert record is not None and not rejection      # le nom concorde bien
    assert record.siren == "921071882"
    assert registry.geographic_rejection(record, config.LOC_FRANCE, "") == \
        oa.EXTERNAL_IDENTITY_UNVERIFIED


@pytest.mark.parametrize("location", [config.LOC_FRANCE, config.LOC_INCONNU, ""])
def test_une_localisation_grossiere_n_est_pas_une_corroboration(location):
    """« France métropolitaine » couvre 96 départements : une concordance à
    cette échelle est une tautologie, pas une preuve d'identité."""
    record, _ = registry.select(registry.parse(QARE), organisation_key("Qare"))
    assert registry.geographic_rejection(record, location, "") == \
        oa.EXTERNAL_IDENTITY_UNVERIFIED


def test_une_corroboration_de_commune_accepte_et_scelle_la_citation():
    record, rejection = registry.select(registry.parse(DUPONT),
                                        organisation_key("Transports Dupont"))
    assert not rejection
    assert registry.geographic_rejection(record, config.LOC_REUNION, "Sainte-Marie") == ""
    label, naf_rejection = registry.activity_label(record)
    assert not naf_rejection
    assert label == "Transports terrestres et transport par conduites"

    quote = registry.structured_quote(record)
    assert oa.structured_proof(quote)
    assert oa.verify_structured_evidence(
        "Transports Dupont", organisation_key("Transports Dupont"), label, quote) == ""
    # La preuve structurée doit traverser le contrat partagé, sinon elle serait
    # acceptée à l'écriture puis refusée pour toujours à la relecture.
    assert supported_activity("Transports Dupont", label, quote)


def test_un_departement_d_outre_mer_corrobore_a_lui_seul():
    record, _ = registry.select(registry.parse(DUPONT), organisation_key("Transports Dupont"))
    assert registry.geographic_rejection(record, config.LOC_REUNION, "") == ""
    assert registry.geographic_rejection(record, config.LOC_MAYOTTE, "") == \
        oa.EXTERNAL_IDENTITY_UNVERIFIED


@pytest.mark.parametrize("fine,commune,expected", [
    ("Sainte-Marie", "SAINTE-MARIE", True),
    ("Sainte-Clotilde / Sainte-Marie", "SAINTE-MARIE", True),
    ("Le Tampon", "TAMPON", True),
    ("Saint-Pierre", "SAINTE-MARIE", False),
    ("Saint-Denis", "SAINT-PIERRE", False),
    ("", "SAINTE-MARIE", False),
])
def test_deux_communes_qui_partagent_saint_ne_concordent_pas(fine, commune, expected):
    assert registry.commune_matches(fine, commune) is expected


def test_deux_homonymes_actifs_sont_une_abstention_pas_un_choix():
    """Le registre est ici l'outil qui *détecte* l'homonymie, pas celui qui la
    tranche."""
    body = json.dumps({"results": [
        {"siren": "1", "nom_complet": "ACME", "etat_administratif": "A",
         "activite_principale": "62.01Z", "siege": {}},
        {"siren": "2", "nom_complet": "Acme", "etat_administratif": "A",
         "activite_principale": "41.20A", "siege": {}}]})
    assert registry.select(registry.parse(body), organisation_key("Acme"))[1] == \
        oa.EXTERNAL_IDENTITY_AMBIGUOUS_REGISTRY


def test_une_societe_cessee_n_est_jamais_retenue():
    body = json.dumps({"results": [{"siren": "7", "nom_complet": "ACME",
                                    "etat_administratif": "C",
                                    "activite_principale": "62.01Z", "siege": {}}]})
    assert registry.select(registry.parse(body), organisation_key("Acme"))[1] == \
        oa.EXTERNAL_IDENTITY_UNVERIFIED


def test_une_division_bloquee_fait_abstenir_le_provider():
    """Division 70, « Activités des sièges sociaux » : une coquille de holding
    ne dit rien du métier réel."""
    body = json.dumps({"results": [{"siren": "6", "nom_complet": "ACME",
                                    "etat_administratif": "A",
                                    "activite_principale": "70.10Z",
                                    "siege": {"libelle_commune": "SAINTE-MARIE",
                                              "departement": "974"}}]})
    record, _ = registry.select(registry.parse(body), organisation_key("Acme"))
    assert registry.activity_label(record)[1] == oa.EXTERNAL_NAF_NOT_MAPPABLE


def test_un_nom_qui_classe_ailleurs_que_sa_division_est_un_conflit():
    """« TRANSPORTS DUPONT » en division 41 : sans cette porte,
    `ACTIVITY_EVIDENCE_RULE` publierait Transport depuis la raison sociale."""
    body = json.dumps({"results": [{"siren": "5", "nom_complet": "TRANSPORTS DUPONT",
                                    "etat_administratif": "A",
                                    "activite_principale": "41.20A",
                                    "siege": {"libelle_commune": "SAINTE-MARIE",
                                              "departement": "974"}}]})
    record, _ = registry.select(registry.parse(body), organisation_key("Transports Dupont"))
    label, _ = registry.activity_label(record)
    quote = registry.structured_quote(record)
    assert oa.verify_structured_evidence("Transports Dupont", "transports dupont",
                                         label, quote) == \
        oa.EXTERNAL_EVIDENCE_SECTOR_CONFLICT


def test_les_cles_de_la_citation_structuree_sont_inertes_au_lexique_sectoriel():
    """Mesuré : un siège imbriqué produit les jetons `commune` et `departement`,
    deux motifs de SECTOR_ADMIN, et la citation classait alors
    « Administration / Collectivité » — un secteur venu d'un nom de champ."""
    from cyberwatch.sector import classify_sector_activity
    record, _ = registry.select(registry.parse(DUPONT), organisation_key("Transports Dupont"))
    quote = registry.structured_quote(record)
    assert "\"commune\"" not in quote and "\"departement\"" not in quote
    assert classify_sector_activity(quote) == config.SECTOR_TRANSPORT


def test_une_reponse_illisible_ne_devine_rien():
    assert registry.parse("pas du json") is None
    assert registry.parse(json.dumps({"autre": []})) is None
    assert registry.select(None, "acme")[1] == oa.EXTERNAL_REGISTRY_UNREADABLE
    assert registry.select(registry.parse(json.dumps({"results": []})), "acme")[1] == \
        oa.EXTERNAL_IDENTITY_UNVERIFIED


def test_l_url_de_requete_est_stable_et_porte_le_nom_recherche():
    url = registry.registry_query_url("Transports Dupont", config.EXTERNAL_ACTIVITY_REGISTRY_URL)
    assert url.startswith(config.EXTERNAL_ACTIVITY_REGISTRY_URL + "?")
    assert "q=Transports+Dupont" in url
    assert registry.registry_query_url("  ", config.EXTERNAL_ACTIVITY_REGISTRY_URL) == ""
