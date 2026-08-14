"""Collecteur WordPress dédié à Cyberattaque.org."""
from __future__ import annotations
import re
from .. import status
from ..identity import item_id
from ..model import Item
from ..normalize import clean_organisation, organisation_key
from .wordpress import WordPressCollector

# Les tournures éditoriales composées doivent précéder les mots simples. Sans
# cela, dans « Biosynex annonce être victime… », le marqueur ``victime``
# capturait à tort « Biosynex annonce être » comme organisation.
_ORG_PREFIX = re.compile(
    r"^(.+?)\s+(?:"
    r"annonce\s+(?:avoir\s+)?(?:être|été|etre)\s+victime\b|"
    r"informe(?:\s+ses\s+clients)?\s+d['’]une\s+fuite\b|"
    r"ouvre\s+la\s+s[ée]rie\s+de\s+fuites\b|"
    r"touch[ée]e?|victime|cibl[ée]e?|frapp[ée]e?|pirat[ée]e?|"
    r"conteste|alerte|au cœur|sous la menace)\b",
    re.I,
)

# Certains titres commencent par une accroche journalistique et ne nomment la
# victime qu'après les deux-points. Cette forme reste stricte : seule une
# entité qui « confirme une cyberattaque » est retenue.
_ORG_AFTER_COLON_CONFIRMS_CYBERATTACK = re.compile(
    r":\s*(?:l['’]\s*)?(.+?)\s+confirme\s+(?:une?\s+)?cyberattaque\b",
    re.I,
)

# Une mesure chiffrée en tête de titre décrit l'impact, jamais la victime.
# Cette règle ne rejette pas les organisations pouvant commencer par un chiffre
# (par exemple « 5doigts2pieds ») : elle exige une unité de volume de données.
_EDITORIAL_DATA_COUNT = re.compile(
    r"^\s*\d[\d\s.,]*\s+(?:lignes?|enregistrements?|comptes?|"
    r"donnees?|dossiers?|go|gb|to|tb)\b",
    re.I,
)

def organisation_from_title(title: str) -> str:
    if _EDITORIAL_DATA_COUNT.match(title or ""):
        return ""
    after_colon = _ORG_AFTER_COLON_CONFIRMS_CYBERATTACK.search(title or "")
    if after_colon:
        return clean_organisation(after_colon.group(1))
    head = (title or "").split(":", 1)[0].strip()
    match = _ORG_PREFIX.match(head)
    return clean_organisation(match.group(1) if match else head)


def repair_existing_identities(items: list[Item]) -> tuple[list[Item], int]:
    """Répare les organisations déjà extraites par ce collecteur.

    Les titres Cyberattaque.org sont reparcourus ; toutes les clés existantes
    sont ensuite recalculées pour appliquer les alias déterministes. L'identifiant
    est recalculé car il inclut la clé d'identité.
    """
    repaired: list[Item] = []
    changed = 0
    for item in items:
        organisation = item.Organisation_Raw
        if item.Source_ID == "CYBERATTAQUE_ORG":
            organisation = organisation_from_title(item.Title)
            if not organisation:
                changed += 1
                continue
        key = organisation_key(organisation)
        if organisation == item.Organisation_Raw and key == item.Organisation_Key:
            repaired.append(item)
            continue
        item.Organisation_Raw = organisation
        item.Organisation_Key = key
        item.Item_ID = item_id(item.Source_ID, item.Published_Date, key, item.URL, item.Source_Item_ID)
        repaired.append(item)
        changed += 1
    return repaired, changed

class CyberattaqueOrgCollector(WordPressCollector):
    name = "cyberattaque_org"
    def collect(self, client, spec, window):
        result = super().collect(client, spec, window)
        items_seen = len(result.entries)
        for entry in result.entries:
            entry.organisation = organisation_from_title(entry.title)
        # L'article reste compté pour mesurer la couverture de la source, mais
        # sans victime nommée il ne peut pas devenir un incident.
        result.entries = [entry for entry in result.entries if entry.organisation]
        result.items_seen = items_seen
        result.units_done = items_seen
        result.status_override = status.OK if result.entries else status.FAIL
        if not result.entries and result.reason_code == status.REASON_OK:
            result.reason_code = status.REASON_PARSE_ERROR
        result.comment = f"items_seen={result.items_seen}; items_in_window={len(result.entries)}"
        return result
