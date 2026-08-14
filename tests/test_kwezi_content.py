"""Qualification stricte des articles Kwezi à partir du corps WordPress."""

from cyberwatch import config
from cyberwatch.collectors.base import RawEntry, SourceSpec
from cyberwatch.runner import entry_to_item


AS_OF = "2026-08-14T00:00:00+04:00"
SPEC = SourceSpec(
    "KWEZI_NUMERIQUE", config.LAYER_LOCAL_MEDIA, config.LOC_MAYOTTE,
    params={"include_content": True},
)


def _entry(*, title="Services perturbés", summary="Situation inhabituelle.", content=""):
    return RawEntry(
        title=title, summary=summary, content=content, published="2026-06-01",
        url="https://www.linfokwezi.fr/numerique/article/", source_item_id="4242",
    )


def _item(entry, known=None, territories=None):
    return entry_to_item(entry, SPEC, AS_OF, known or {}, {}, territories or {})


def test_corps_seul_detecte_cyber_et_mairie_explicite():
    item = _item(_entry(content="La Mairie de Mamoudzou a été victime d'une cyberattaque mardi matin."))

    assert item is not None
    assert item.Organisation_Raw == "Mairie de Mamoudzou"
    assert item.Source_Item_ID == "4242"
    assert item.Location == config.LOC_MAYOTTE


def test_numerique_non_cyber_reste_hors_items():
    assert _item(_entry(content="Le déploiement de la fibre et des smartphones se poursuit.")) is None


def test_cyber_sans_victime_reste_hors_items():
    assert _item(_entry(content="Une cyberattaque a perturbé plusieurs services cette semaine.")) is None


def test_entite_connue_dans_le_corps_est_reconnue():
    item = _item(
        _entry(content="Le Centre Hospitalier de Mayotte a subi une cyberattaque."),
        known={"centre hospitalier de mayotte": "Centre Hospitalier de Mayotte"},
        territories={"centre hospitalier de mayotte": config.LOC_MAYOTTE},
    )

    assert item is not None
    assert item.Organisation_Raw == "Centre Hospitalier de Mayotte"
    assert item.Location == config.LOC_MAYOTTE


def test_article_cyber_national_non_force_a_mayotte():
    item = _item(
        _entry(content="Entreprise nationale est victime d'une cyberattaque."),
        known={"entreprise nationale": "Entreprise nationale"},
    )

    assert item is not None
    assert item.Location == config.LOC_INCONNU
