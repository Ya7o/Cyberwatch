"""Règles déterministes de victimes Cyberattaque.org."""

from cyberwatch import config, sources
from cyberwatch.collectors.base import RawEntry, SourceSpec
from cyberwatch.collectors.cyberattaque_org import (
    is_negated_incident,
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


def test_mairie_de_drancy_est_lue_dans_le_contenu():
    raw = entry(
        "Cyberattaque à Drancy : tous les serveurs débranchés",
        content="La mairie de Drancy a été victime d'une cyberattaque mardi.",
    )
    assert organisation_from_cyberattaque_entry(raw, {}) == "Mairie de Drancy"


def test_entite_connue_est_reconnue_dans_une_relation_du_contenu():
    raw = entry("Services perturbés", content="Le CHM a été victime d'une cyberattaque.")
    assert organisation_from_cyberattaque_entry(raw, {"chm": "CHM"}) == "CHM"


def test_mairie_eyguieres_est_extraite_sans_conserver_la_phrase():
    assert organisation_from_cyberattaque_entry(
        entry("La mairie d’Eyguières paralysée par un ransomware"), {}
    ) == "Mairie d’Eyguières"


def test_federation_est_extraite_depuis_impact_chiffre_strict():
    raw = entry("284 461 membres de la Fédération Française de Bridge diffusés après une faille de sécurité")
    assert organisation_from_cyberattaque_entry(raw, {}) == "Fédération Française de Bridge"


def test_accroches_et_multi_victimes_ne_deviennent_pas_des_organisations():
    assert organisation_from_cyberattaque_entry(entry("Fuite de données scolaires : près de 15 000 élèves concernés"), {}) == ""
    assert organisation_from_cyberattaque_entry(entry("4 SDIS frappés : 5 000 pompiers exposés"), {}) == ""
    assert organisation_from_cyberattaque_entry(entry("Une IA d’OpenAI s’échappe de son environnement de test et pirate Hugging Face"), {}) == ""
    assert organisation_from_cyberattaque_entry(entry("Le site de Pierrefitte-sur-Loire mis hors ligne après une cyberattaque"), {}) == ""


def test_victime_technique_directe_prime_sur_marque_affectee():
    raw = entry(
        "Steam : noms et adresses de clients exposés",
        "Valve avertit les clients de Steam après une cyberattaque contre CEVA Logistics.",
    )
    assert organisation_from_cyberattaque_entry(raw, {}) == "CEVA Logistics"


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
