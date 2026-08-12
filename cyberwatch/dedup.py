"""Déduplication conservatrice et construction de `INCIDENTS` (§11, §12).

Règle directrice de la méthode : « un faux doublon est préférable à une fusion
non reproductible ». Deux organisations dont les clés normalisées diffèrent ne
sont jamais fusionnées, et aucun rapprochement flou n'est tenté.
"""

from __future__ import annotations

from collections import Counter, defaultdict

from . import config
from .identity import incident_id, sort_incidents, sort_items
from .model import Incident, Item
from .normalize import date_or_empty


def group_components(items: list[Item]) -> list[list[Item]]:
    """Regroupe les items en composantes d'incident.

    Application littérale du §11 :
      1. grouper par `Organisation_Key` ;
      2. trier par `Published_Date`, `Source_ID`, `URL`, `Item_ID` ;
      3. regrouper les items successifs dont l'écart est ≤ 14 jours ;
      4. un écart supérieur ouvre une nouvelle composante.

    Les items sans organisation identifiable sont écartés : un incident sans
    victime nommée n'est pas un incident (§15.1, §16.1, §17.1).
    """
    by_org: dict[str, list[Item]] = defaultdict(list)
    for item in items:
        if not item.Organisation_Key:
            continue
        by_org[item.Organisation_Key].append(item)

    components: list[list[Item]] = []
    for org_key in sorted(by_org):
        group = sorted(
            by_org[org_key],
            key=lambda it: (
                it.Published_Date or "",
                it.Source_ID or "",
                it.URL or "",
                it.Item_ID or "",
            ),
        )

        current: list[Item] = []
        previous_date = None
        for item in group:
            item_date = date_or_empty(item.best_date)

            if not current:
                current = [item]
                previous_date = item_date
                continue

            # Un item sans date exploitable reste rattaché à la composante en
            # cours : l'exclure créerait un incident fantôme sans date.
            if item_date is None or previous_date is None:
                current.append(item)
                previous_date = item_date or previous_date
                continue

            if (item_date - previous_date).days <= config.INCIDENT_GAP_DAYS:
                current.append(item)
                previous_date = item_date
            else:
                components.append(current)
                current = [item]
                previous_date = item_date

        if current:
            components.append(current)

    return components


def _component_dates(component: list[Item]) -> tuple[str, str]:
    """Date du dashboard et base de datation d'une composante (§12).

    Si au moins un `Event_Date` est connu, la date est la première `Event_Date`
    et la base vaut `EVENT`. Sinon c'est la première `Published_Date`, base
    `PUBLICATION`.
    """
    event_dates = sorted(d for d in (it.Event_Date for it in component) if d)
    if event_dates:
        return event_dates[0], config.DATE_BASIS_EVENT

    published_dates = sorted(d for d in (it.Published_Date for it in component) if d)
    if published_dates:
        return published_dates[0], config.DATE_BASIS_PUBLICATION

    return "", config.DATE_BASIS_PUBLICATION


def _majority(values: list[str], fallback: str) -> str:
    """Valeur dominante d'une liste, départages par ordre alphabétique.

    Le départage explicite garantit le déterminisme : `Counter.most_common`
    seul dépendrait de l'ordre d'insertion.
    """
    meaningful = [v for v in values if v and v != fallback]
    if not meaningful:
        return fallback
    counts = Counter(meaningful)
    top_count = max(counts.values())
    return min(k for k, c in counts.items() if c == top_count)


def _priority_threat(values: list[str]) -> str:
    """Menace retenue pour un incident : la plus haute de la hiérarchie du §8.

    Un incident vu comme « fuite de données » par une source et « ransomware »
    par une autre est un ransomware — la priorité de la taxonomie tranche, ce
    qui reste déterministe quel que soit l'ordre des sources.
    """
    known = [v for v in values if v and v in config.THREATS]
    if not known:
        return config.THREAT_UNKNOWN
    return min(known, key=lambda threat: config.THREATS.index(threat))


def build_incidents(items: list[Item]) -> list[Incident]:
    """Reconstruit intégralement `INCIDENTS` à partir de `ITEMS`.

    Fonction pure et sans réseau : c'est elle que `REPLAY` (§26) rejoue et que
    le test de répétabilité (§27) vérifie.
    """
    incidents: list[Incident] = []

    for component in group_components(items):
        ordered = sort_items(component)
        date, basis = _component_dates(ordered)

        organisation = _majority(
            [it.Organisation_Raw for it in ordered],
            ordered[0].Organisation_Raw or "",
        )

        sources = sorted({it.Source_ID for it in ordered if it.Source_ID})
        urls = sorted({it.URL for it in ordered if it.URL})
        collected = sorted({it.Collected_As_Of for it in ordered if it.Collected_As_Of})

        incidents.append(
            Incident(
                Incident_ID=incident_id(ordered[0].Organisation_Key, date),
                Date=date,
                Date_Basis=basis,
                Organisation=organisation,
                Secteur=_majority(
                    [it.Sector for it in ordered], config.SECTOR_UNKNOWN
                ),
                Menace=_priority_threat([it.Threat for it in ordered]),
                Localisation=_majority(
                    [it.Location for it in ordered], config.LOC_INCONNU
                ),
                Sources=" | ".join(sources),
                Source_URLs=" | ".join(urls),
                Items_Count=len(ordered),
                First_seen=collected[0] if collected else "",
                Last_seen=collected[-1] if collected else "",
            )
        )

    return sort_incidents(incidents)


def merge_items(existing: list[Item], incoming: list[Item]) -> tuple[list[Item], int]:
    """Fusionne les items d'une MAJ dans le stock existant (§25).

    Les items sont ajoutés ou remplacés par `Item_ID`. Un ancien item n'est
    jamais supprimé au motif qu'il n'est plus visible sur le Web (§25.6) :
    la base est un cumul de ce qui a été observé, pas un miroir du Web.

    Renvoie le stock fusionné et le nombre d'items réellement nouveaux.
    """
    by_id: dict[str, Item] = {item.Item_ID: item for item in existing}
    new_count = 0

    for item in incoming:
        if not item.Item_ID:
            continue
        if item.Item_ID not in by_id:
            new_count += 1
            by_id[item.Item_ID] = item
        else:
            # Item déjà connu : on conserve la date de première collecte.
            previous = by_id[item.Item_ID]
            item.Collected_As_Of = previous.Collected_As_Of or item.Collected_As_Of
            by_id[item.Item_ID] = item

    return sort_items(list(by_id.values())), new_count
