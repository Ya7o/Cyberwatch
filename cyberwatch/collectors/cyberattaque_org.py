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

def organisation_from_title(title: str) -> str:
    head = (title or "").split(":", 1)[0].strip()
    match = _ORG_PREFIX.match(head)
    return clean_organisation(match.group(1) if match else head)


def repair_existing_identities(items: list[Item]) -> tuple[list[Item], int]:
    """Répare les organisations déjà extraites par ce collecteur.

    Seuls les items Cyberattaque.org dont le parseur fournit un nom différent
    sont modifiés. L'identifiant est recalculé car il inclut la clé d'identité.
    """
    repaired: list[Item] = []
    changed = 0
    for item in items:
        if item.Source_ID != "CYBERATTAQUE_ORG":
            repaired.append(item)
            continue
        organisation = organisation_from_title(item.Title)
        if not organisation or organisation == item.Organisation_Raw:
            repaired.append(item)
            continue
        item.Organisation_Raw = organisation
        item.Organisation_Key = organisation_key(organisation)
        item.Item_ID = item_id(
            item.Source_ID, item.Published_Date, item.Organisation_Key, item.URL,
        )
        repaired.append(item)
        changed += 1
    return repaired, changed

class CyberattaqueOrgCollector(WordPressCollector):
    name = "cyberattaque_org"
    def collect(self, client, spec, window):
        result = super().collect(client, spec, window)
        for entry in result.entries:
            entry.organisation = organisation_from_title(entry.title) or "Inconnu"
        result.items_seen = len(result.entries)
        result.units_done = len(result.entries)
        result.status_override = status.OK if result.entries else status.FAIL
        if not result.entries and result.reason_code == status.REASON_OK:
            result.reason_code = status.REASON_PARSE_ERROR
        result.comment = f"items_seen={result.items_seen}; items_in_window={len(result.entries)}"
        return result
