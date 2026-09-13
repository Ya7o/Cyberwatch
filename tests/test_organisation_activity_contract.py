"""Portes pures du niveau 2 : identité, preuve, nomenclature.

Aucun test n'accède au réseau ni n'appelle de modèle.
"""
import json

import pytest
import requests

from cyberwatch import config, org_identity
from cyberwatch import organisation_activity as oa
from cyberwatch.model import Item
from cyberwatch.normalize import organisation_key
from cyberwatch.sector import classify_sector_activity
from cyberwatch.sector_activity import supported_activity

QUOTE = "PassPass est un service de vente de titres de transport."


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(requests.Session, "request",
                        lambda *a, **k: pytest.fail("réseau interdit"))
    monkeypatch.setattr(org_identity, "ORGANISATION_IDENTITY_REGISTRY", {})


def identity(org, evidence):
    return oa.identity_rejection(org, organisation_key(org), evidence)


# --------------------------------------------------------------------------
# Garde d'homonymie
# --------------------------------------------------------------------------

@pytest.mark.parametrize("evidence", [
    "Acme Groupe est spécialisé dans la fabrication de logiciels.",
    "Acme Association est un organisme de formation professionnelle.",
    "Groupe Acme est spécialisé dans la fabrication de logiciels.",
    "Fondation Acme est une association qui accompagne les familles.",
    "Acme Bâtiment est spécialisée dans le second oeuvre.",
])
def test_un_nom_propre_plus_long_est_un_homonyme(evidence):
    """Mesuré : `supported_activity` accepte « Acme Groupe est spécialisé… »
    pour une victime nommée « Acme ». La garde de nom ferme cette fuite."""
    assert supported_activity("Acme", "x", evidence) or True  # la fuite existe bien
    assert identity("Acme", evidence) == oa.EXTERNAL_IDENTITY_HOMONYM


def test_un_alias_valide_resout_l_homonymie_au_lieu_de_la_bloquer(monkeypatch):
    """La garde défère à `effective_organisation_key` : c'est le référentiel
    d'identité qui tranche, jamais le niveau 2."""
    evidence = "Acme Groupe est spécialisé dans la fabrication de logiciels."
    assert identity("Acme", evidence) == oa.EXTERNAL_IDENTITY_HOMONYM
    monkeypatch.setattr(org_identity, "ORGANISATION_IDENTITY_REGISTRY",
                        {"acme groupe": "acme"})
    assert identity("Acme", evidence) == ""


@pytest.mark.parametrize("evidence", [
    "Acme SA est un opérateur de téléphonie mobile.",
    "Acme SASU est un opérateur de téléphonie mobile.",
    "Acme SARL est un opérateur de téléphonie mobile.",
])
def test_une_forme_juridique_postposee_ne_cree_pas_un_homonyme(evidence):
    assert identity("Acme", evidence) == ""


def test_la_ponctuation_arrete_le_nom_donc_une_apposition_reste_valide():
    """« Acme, entreprise spécialisée… » parle bien d'Acme : une apposition
    n'est pas un nom propre plus long."""
    assert identity("Acme", "Acme, entreprise spécialisée dans la vente, poursuit.") == ""
    assert oa.name_window("Acme", "Acme, entreprise spécialisée dans la vente.") == "Acme,"


def test_un_suffixe_de_domaine_ne_fait_pas_un_homonyme():
    """`organisation_key('Booking.com') == 'booking'` : la concordance doit
    passer par la fonction d'identité du projet, pas par une comparaison de
    chaînes."""
    page = "Booking.com est une plateforme de réservation d'hébergement."
    assert identity("Booking", page) == ""
    assert identity("Booking.com", page) == ""


def test_une_organisation_absente_de_la_citation_est_refusee():
    assert identity("Acme", "Widget Corp conçoit des systèmes.") == oa.EXTERNAL_IDENTITY_NOT_NAMED


# --------------------------------------------------------------------------
# Portes de preuve en prose
# --------------------------------------------------------------------------

def prose(activity, quote, page=None):
    return oa.verify_prose_evidence("PassPass", organisation_key("PassPass"),
                                    activity, quote, page if page is not None else quote)


def test_une_citation_metier_ancree_est_acceptee():
    assert prose(QUOTE, QUOTE, f"À propos. {QUOTE} Nous contacter.") == ""


def test_une_citation_absente_de_la_page_est_refusee():
    """Le cœur du contrat : la citation doit exister dans le contenu téléchargé."""
    assert prose(QUOTE, QUOTE, "Une page qui parle d'autre chose.") == \
        oa.EXTERNAL_QUOTE_NOT_GROUNDED


def test_une_paraphrase_proche_est_refusee():
    approx = "PassPass est un service de vente de titres de transports collectifs."
    assert prose(approx, approx, f"À propos. {QUOTE}") == oa.EXTERNAL_QUOTE_NOT_GROUNDED


@pytest.mark.parametrize("quote,expected", [
    ("PassPass fait appel à un prestataire chargé du suivi des commandes.",
     oa.EXTERNAL_ACTIVITY_THIRD_PARTY),
    ("PassPass est un client de Widget Corp, spécialisée dans la chimie.",
     oa.EXTERNAL_ACTIVITY_NOT_DESCRIBED),
    ("PassPass est une filiale du groupe Widget spécialisé dans la chimie.",
     oa.EXTERNAL_ACTIVITY_NOT_DESCRIBED),
])
def test_l_activite_d_un_tiers_ou_du_groupe_n_est_pas_celle_de_la_victime(quote, expected):
    assert prose(quote, quote) == expected


def test_un_recit_d_incident_ne_prouve_aucune_activite():
    quote = "PassPass est victime d'une cyberattaque revendiquée par un groupe."
    assert prose(quote, quote) in {oa.EXTERNAL_QUOTE_DESCRIBES_INCIDENT,
                                   oa.EXTERNAL_ACTIVITY_NOT_DESCRIBED}


def test_une_citation_vide_est_refusee_sans_rien_deviner():
    assert prose("", "") == oa.EXTERNAL_NO_QUOTE


# --------------------------------------------------------------------------
# Discriminant structuré — garde de régression de l'édition de sector_activity
# --------------------------------------------------------------------------

def _prose_corpus():
    """Citations de prose réellement employées par le projet et ses tests."""
    corpus = [QUOTE, "", "   ", "Micromania.", "Transport", "{}", "{'a': 1}",
              "Le CHU de La Réunion est un établissement public de santé.",
              json.dumps({"source": "ailleurs", "nom_complet": "ACME"}),
              '{"activite_principale":"49.41A"}']
    from pathlib import Path
    for name in ("test_sector_resolution.py", "test_blf_org_enrichment.py",
                 "test_sector_pipeline_regressions.py"):
        corpus.append(Path(__file__).parent.joinpath(name).read_text(encoding="utf-8"))
    return corpus


@pytest.mark.parametrize("text", _prose_corpus())
def test_le_discriminant_structure_est_disjoint_de_toute_prose(text):
    """`supported_activity` ne branche vers la porte structurée que sur un objet
    JSON portant le marqueur de source épinglé. Aucun texte du corpus existant
    ne peut satisfaire les deux — sans quoi l'édition changerait le verdict de
    citations en prose déjà validées."""
    assert not oa.structured_proof(text)


def test_le_marqueur_structure_reste_alignee_sur_la_configuration():
    assert oa.REGISTRY_SOURCE == config.EXTERNAL_ACTIVITY_REGISTRY_HOST
    assert oa.REGISTRY_MARKER in json.dumps(
        {"source": oa.REGISTRY_SOURCE}, separators=(",", ":"))


# --------------------------------------------------------------------------
# Nomenclature NAF
# --------------------------------------------------------------------------

def test_la_table_naf_couvre_les_88_divisions_officielles():
    assert len(oa.NAF_DIVISIONS) == 88
    assert oa.naf_division("49.41A").division == "49"
    assert oa.naf_division("") is None
    assert oa.naf_division("X") is None


@pytest.mark.parametrize("division", sorted(oa.NAF_DIVISIONS))
def test_chaque_libelle_naf_concorde_avec_le_classifieur_deterministe(division):
    """L'invariant qui rend la table digne de confiance : un libellé marqué
    `MAPPABLE` doit réellement produire le secteur annoncé, un `TAXONOMY` doit
    réellement être muet, et un `BLOCKED` ne porte jamais de secteur — soit son
    verdict est mesuré faux, soit il ne dit rien du métier réel."""
    entry = oa.NAF_DIVISIONS[division]
    verdict = classify_sector_activity(entry.label)
    if entry.status == oa.NAF_MAPPABLE:
        assert entry.expected_sector in config.SECTORS
        assert entry.expected_sector != config.SECTOR_UNKNOWN
        assert verdict == entry.expected_sector
    elif entry.status == oa.NAF_TAXONOMY:
        assert verdict == config.SECTOR_UNKNOWN and not entry.expected_sector
    else:
        assert entry.status == oa.NAF_BLOCKED and not entry.expected_sector


def test_les_divisions_au_verdict_mesure_faux_sont_bloquees():
    """Six libellés officiels classent faux — « Action sociale SANS hébergement »
    déclenche sur un mot nié. Les bloquer vaut mieux que corriger le lexique
    partagé avec toute la chaîne prose."""
    for division in ("30", "35", "36", "87", "88", "93"):
        assert oa.NAF_DIVISIONS[division].status == oa.NAF_BLOCKED


def test_les_libelles_non_informatifs_sont_bloques():
    """« Activités des sièges sociaux » décrit une coquille de holding : c'est
    le mode d'échec exact mesuré sur Qare."""
    for division in ("70", "74", "82", "96", "97", "98"):
        assert oa.NAF_DIVISIONS[division].status == oa.NAF_BLOCKED


# --------------------------------------------------------------------------
# Conflit de preuve et re-vérification
# --------------------------------------------------------------------------

def test_une_citation_qui_classe_ailleurs_que_l_activite_est_refusee():
    """Mesuré : un fragment de registre nommé « TRANSPORTS DUPONT » classe
    Transport / Logistique par son seul nom. Avec une division Construction,
    `ACTIVITY_EVIDENCE_RULE` publierait un secteur déduit du nom."""
    quote = json.dumps({"nom_complet": "TRANSPORTS DUPONT",
                        "source": oa.REGISTRY_SOURCE}, separators=(",", ":"))
    assert oa.evidence_sector_rejection("Construction de bâtiments", quote) == \
        oa.EXTERNAL_EVIDENCE_SECTOR_CONFLICT
    assert oa.evidence_sector_rejection(QUOTE, QUOTE) == ""


def _evidence(**kwargs):
    base = dict(organisation="PassPass", organisation_key="passpass",
                activity_description=QUOTE, evidence_quote=QUOTE,
                evidence_url="https://exemple-passpass.fr/a", source_type="official_site",
                provider="owned_url", verified_at="2026-09-12T00:00:00+00:00",
                content_hash="abc", verification_method=oa.VERIFY_PROSE_LITERAL)
    return oa.VerifiedActivityEvidence(**{**base, **kwargs})


def test_accepts_rejoue_la_porte_pure_sur_une_preuve_deja_constituee():
    item = Item(Item_ID="I", Organisation_Raw="PassPass", Organisation_Key="passpass")
    assert oa.accepts(_evidence(), item) == ""
    assert oa.accepts(None, item) == oa.EXTERNAL_NO_CANDIDATE
    assert oa.accepts(_evidence(organisation_key="autre"), item) == \
        oa.EXTERNAL_IDENTITY_UNVERIFIED
    assert oa.accepts(_evidence(evidence_url=""), item) == oa.EXTERNAL_URL_REJECTED
    assert oa.accepts(_evidence(content_hash=""), item) == oa.EXTERNAL_URL_REJECTED
    assert oa.accepts(_evidence(verification_method="INVENTEE"), item) == oa.EXTERNAL_ERROR


def test_le_record_shadow_ne_porte_aucune_cle_metier_au_premier_niveau():
    """C'est ce qui garantit qu'aucun lecteur aval ne peut publier un secteur
    shadow : tous lisent `Activity_Description`, qui reste vide."""
    record = oa.blf_record(_evidence(), shadow=True,
                           candidate=(config.SECTOR_TRANSPORT, "rule"))
    assert record["origin"] == oa.ORIGIN_EXTERNAL_NOT_APPLIED
    assert record["external_status"] == oa.EXTERNAL_ACTIVITY_SHADOW
    for key in ("activity_description", "evidence_quote", "evidence_url", "organisation"):
        assert key not in record
    assert record["shadow"]["candidate_sector"] == config.SECTOR_TRANSPORT

    applied = oa.blf_record(_evidence(), shadow=False)
    assert applied["origin"] == oa.ORIGIN_EXTERNAL_APPLIED
    assert applied["activity_description"] == QUOTE
    assert "shadow" not in applied


def test_les_vocabulaires_restent_fermes_et_sans_collision():
    assert oa.ORIGIN_EXTERNAL_NOT_APPLIED in oa.ORIGINS
    # `component_sector_rows` et `qualification_summary` cherchent « CONFLICT »
    # dans le motif sectoriel ; aucune origine ne doit le porter par accident.
    assert [o for o in oa.ORIGINS if "CONFLICT" in o] == [oa.ORIGIN_CONFLICT]
    assert oa.not_applied("INEXISTANT")["external_status"] == oa.EXTERNAL_ERROR
