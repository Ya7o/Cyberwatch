"""Règles déterministes de victimes Cyberattaque.org."""

import json
from pathlib import Path

from cyberwatch import config, sources
from cyberwatch.collectors.base import RawEntry, SourceSpec
from cyberwatch.collectors.cyberattaque_org import (
    is_negated_incident,
    is_obvious_multi,
    organisation_from_cyberattaque_entry,
)
from cyberwatch.runner import entry_to_item


SPEC = SourceSpec(
    "CYBERATTAQUE_ORG", config.LAYER_CORE, config.LOC_FRANCE,
    params={"scope_is_cyber": True, "include_content": True},
)
AS_OF = "2026-08-14T00:00:00+04:00"


def entry(title, summary="", content=""):
    return RawEntry(
        title=title, summary=summary, content=content, published="2026-08-12",
        url="https://www.cyberattaque.org/article/", source_item_id="9876",
    )


def item(raw):
    return entry_to_item(raw, SPEC, AS_OF, {}, {})


def test_prefixes_et_recidives_restent_des_victimes():
    assert organisation_from_cyberattaque_entry(entry("DGFiP : une 2ème cyberattaque"), {}) == "DGFiP"
    assert organisation_from_cyberattaque_entry(entry("Scalingo : données exposées"), {}) == "Scalingo"
    assert organisation_from_cyberattaque_entry(entry("Son-Video.com frappé une nouvelle fois par une cyberattaque"), {}) == "Son-Video.com"
    assert organisation_from_cyberattaque_entry(entry("Alinto : une fuite massive touche les entreprises"), {}) == "Alinto"


def test_ville_de_gagny_est_lue_dans_la_relation_explicite():
    raw = entry(
        "Cyberattaque à Gagny : la Ville confirme un accès non autorisé",
        "La Ville de Gagny confirme avoir subi une cyberattaque.",
    )
    assert organisation_from_cyberattaque_entry(raw, {}) == "Ville de Gagny"


def test_relation_explicite_est_un_fallback_si_titre_narratif():
    raw = entry(
        "Cyberattaque dans une collectivité",
        "La Ville de Test confirme avoir subi une cyberattaque.",
    )
    assert organisation_from_cyberattaque_entry(raw, {}) == "Ville de Test"


def test_mairie_de_drancy_est_lue_dans_le_contenu():
    raw = entry(
        "Cyberattaque à Drancy : tous les serveurs débranchés",
        content="La mairie de Drancy fait face à une importante attaque par rançongiciel.",
    )
    assert organisation_from_cyberattaque_entry(raw, {}) == "Mairie de Drancy"


def test_entite_connue_est_reconnue_dans_une_relation_du_contenu():
    raw = entry("Services perturbés", content="Le CHM a été victime d'une cyberattaque.")
    assert organisation_from_cyberattaque_entry(raw, {"chm": "CHM"}) == "CHM"


def test_mairie_eyguieres_est_extraite_sans_conserver_la_phrase():
    assert organisation_from_cyberattaque_entry(
        entry("La mairie d’Eyguières paralysée par un ransomware"), {}
    ) == "Mairie d’Eyguières"


def test_domaine_des_tournels_reste_normalise():
    assert organisation_from_cyberattaque_entry(
        entry("Le Domaine des Tournels ciblé par une cyberattaque"), {}
    ) == "Domaine des Tournels"


def test_federation_est_extraite_depuis_impact_chiffre_strict():
    raw = entry("284 461 membres de la Fédération Française de Bridge diffusés après une faille de sécurité")
    assert organisation_from_cyberattaque_entry(raw, {}) == "Fédération Française de Bridge"


def test_accroches_et_multi_victimes_ne_deviennent_pas_des_organisations():
    assert organisation_from_cyberattaque_entry(entry("Fuite de données scolaires : près de 15 000 élèves concernés"), {}) == ""
    assert organisation_from_cyberattaque_entry(entry("4 SDIS frappés : 5 000 pompiers exposés"), {}) == ""
    assert organisation_from_cyberattaque_entry(entry("Une IA d’OpenAI s’échappe de son environnement de test et pirate Hugging Face"), {}) == ""
    assert organisation_from_cyberattaque_entry(entry("Le site de Pierrefitte-sur-Loire mis hors ligne après une cyberattaque"), {}) == ""


def test_organisation_principale_du_titre_prime_sur_le_tiers_technique():
    cases = (
        ("Steam : noms, adresses et commandes de clients européens exposés après une cyberattaque", "Valve avertit des clients européens de Steam après une cyberattaque contre CEVA Logistics.", "Steam"),
        ("Spiko : pièces d’identité et selfies de clients exposés après une cyberattaque chez Onfido", "", "Spiko"),
        ("OpenAI : des données internes compromises après l’installation de la bibliothèque piégée TanStack", "Compromission supply-chain via un paquet npm TanStack.", "OpenAI"),
        ("Centres Sociaux de France : les données revendiquées après une compromission de RezoFed", "", "Centres Sociaux de France"),
        ("Toulouse FC : les abonnés exposés après une cyberattaque chez un prestataire", "", "Toulouse FC"),
        ("Lidl : les coordonnées de clients exposés après une cyberattaque chez un prestataire", "", "Lidl"),
    )
    for title, summary, expected in cases:
        assert organisation_from_cyberattaque_entry(entry(title, summary), {}) == expected


def test_dementis_explicites_ne_creent_pas_item():
    for title in (
        "École Directe : fausse alerte à la cyberattaque",
        "Association.fr : la fuite revendiquée ne correspond pas aux données du site",
    ):
        raw = entry(title)
        assert is_negated_incident(raw.title, raw.summary, raw.content)
        assert item(raw) is None


def test_organisations_numeriques_et_id_wordpress_sont_preserves():
    first = item(entry("1001Coques : victimes d'une cyberattaque"))
    second = item(entry("5doigts2pieds.fr piraté : données exposées"))
    assert first is not None and first.Organisation_Raw == "1001Coques"
    assert second is not None and second.Organisation_Raw == "5doigts2pieds.fr"
    assert second.Source_Item_ID == "9876"


def test_cyberattaque_demande_le_contenu_dans_la_requete_wordpress_existante():
    spec = sources.by_id("CYBERATTAQUE_ORG")
    assert spec.params["include_content"] is True


def test_cyberattaque_ne_contourne_pas_le_resolver_par_entite_connue():
    raw = entry(
        "Rapport technique sur un prestataire",
        "Air Austral est cité parmi plusieurs clients de la société.",
    )
    assert entry_to_item(raw, SPEC, AS_OF, {"air austral": "Air Austral"}, {}) is None


def test_fallback_entite_connue_reste_disponible_pour_les_autres_sources():
    spec = SourceSpec("TEST_SOURCE", config.LAYER_CORE, config.LOC_FRANCE,
                      params={"scope_is_cyber": True})
    raw = entry("Rapport technique sur un prestataire", "Air Austral est cité.")
    resolved = entry_to_item(raw, spec, AS_OF, {"air austral": "Air Austral"}, {})
    assert resolved is not None
    assert resolved.Organisation_Raw == "Air Austral"


def test_multi_couvre_les_groupes_explicitement_aggreges():
    assert is_obvious_multi("G7 d’Évian : plusieurs sites concernés")
    assert is_obvious_multi("Son-Video.com & EasyLounge : données exposées")
    assert is_obvious_multi("Alerte régionale", "Plusieurs ARS concernées")
    assert is_obvious_multi("Cyberattaque à Rennes", "Ville de Rennes et Rennes Métropole affectées")


def test_fixture_benchmark_cyberattaque_est_complete_et_figee():
    fixture = Path(__file__).parent / "fixtures/cyberattaque_org_articles_2026-08-14.json"
    payload = json.loads(fixture.read_text(encoding="utf-8"))
    assert payload["source"] == "Cyberattaque.org WordPress API"
    assert payload["article_count"] == 408
    assert len(payload["articles"]) == 408
