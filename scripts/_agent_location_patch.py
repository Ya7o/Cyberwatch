from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace(path: str, old: str, new: str) -> None:
    target = ROOT / path
    text = target.read_text(encoding="utf-8")
    if old not in text:
        raise SystemExit(f"motif introuvable dans {path}: {old[:80]!r}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


# 1) Localisation : indices sûrs avant le défaut de source.
normalize = ROOT / "cyberwatch/normalize.py"
text = normalize.read_text(encoding="utf-8")
start = text.index("#: Indices textuels par territoire")
end = text.index("\n\n# --------------------------------------------------------------------------\n# Dates", start)
location_block = '''#: Indices textuels suffisamment spécifiques pour qualifier un territoire.
#: Les mots ambigus pris isolément (``reunion``, ``maurice``, ``francais``,
#: ``paris``...) sont volontairement exclus : mieux vaut conserver Inconnu ou
#: le défaut de la source que fabriquer une localisation.
LOCATION_HINTS: list[tuple[str, list[str]]] = [
    (config.LOC_REUNION, ["974", "saint denis de la reunion", "reunionnais", "reunionnaise"]),
    (config.LOC_MAYOTTE, ["mayotte", "976", "mamoudzou", "mahorais", "mahoraise"]),
    (config.LOC_MAURICE, ["mauritius", "mauricien", "mauricienne", "port louis", "rodrigues"]),
    (config.LOC_MADAGASCAR, ["madagascar", "malgache", "antananarivo", "tananarive"]),
    (config.LOC_SEYCHELLES, ["seychelles", "seychellois", "seychelloise", "victoria mahe"]),
    (config.LOC_COMORES, ["comores", "comorien", "comorienne", "moroni", "anjouan"]),
    (config.LOC_FRANCE, ["france metropolitaine"]),
]

#: Le nom propre garde une majuscule à « Réunion », contrairement à la réunion
#: de travail. Le test reste sensible à la casse pour éviter ce faux positif.
_REUNION_PROPER_NAME_RE = re.compile(r"\\b(?:La R[ée]union|LA R[ÉE]UNION)\\b")


def _location_from_text(*texts: str) -> str:
    raw = " ".join(t for t in texts if t)
    if not raw:
        return config.LOC_INCONNU
    if _REUNION_PROPER_NAME_RE.search(raw):
        return config.LOC_REUNION
    blob = searchable(raw)
    for location, hints in LOCATION_HINTS:
        for hint in hints:
            if _contains(blob, hint):
                return location
    return config.LOC_INCONNU


def classify_location(
    *texts: str,
    given: str = "",
    entity: str = "",
    default: str = "",
) -> str:
    """Localisation normalisée, du signal le plus fort au plus faible.

    1. localisation explicitement structurée par la source (`given`) ;
    2. territoire de l'entité surveillée reconnue (`entity`) ;
    3. indice territorial textuel suffisamment spécifique ;
    4. règle fixe du collecteur (`default`) ;
    5. `Inconnu`.

    L'indice textuel précède volontairement le défaut : une victime décrite
    comme réunionnaise ou mahoraise doit corriger le défaut France d'une source
    nationale. Les marqueurs ambigus ne figurent pas dans ``LOCATION_HINTS``.
    """
    if given:
        cleaned = given.strip()
        if cleaned in config.LOCATIONS:
            return cleaned
        location = _location_from_text(cleaned)
        if location != config.LOC_INCONNU:
            return location

    if entity and entity in config.LOCATIONS:
        return entity

    location = _location_from_text(*texts)
    if location != config.LOC_INCONNU:
        return location

    if default and default in config.LOCATIONS:
        return default

    return config.LOC_INCONNU
'''
normalize.write_text(text[:start] + location_block + text[end:], encoding="utf-8")


# 2) API entreprise : conserver le département du siège déjà présent dans la
# réponse et fournir un mapping minimal vers la taxonomie Location existante.
replace(
    "cyberwatch/org_enrichment.py",
    '"""Enrichissement gratuit d\'entreprise pour `Sector`, uniquement (§12 METHODOLOGY.md).',
    '"""Enrichissement gratuit d\'entreprise réutilisé pour `Sector` et `Location` (§12 METHODOLOGY.md).',
)
replace(
    "cyberwatch/org_enrichment.py",
    '    Activity_Label: str = ""\n    Evidence_Source: str = "recherche-entreprises.api.gouv.fr"',
    '    Activity_Label: str = ""\n    Headquarters_Department: str = ""\n    Evidence_Source: str = "recherche-entreprises.api.gouv.fr"',
)
replace(
    "cyberwatch/org_enrichment.py",
    'def _env_int(name: str, default: int) -> int:\n',
    '''def location_for_headquarters_department(department: str) -> str:\n    """Mappe uniquement les départements couverts sans extrapolation.\n\n    974/976 sont les deux territoires ultramarins de la taxonomie ciblée ;\n    les départements 01-95 (ainsi que 2A/2B) valent France métropolitaine.\n    Les autres codes restent Inconnu.\n    """\n    value = str(department or "").strip().upper()\n    if value == "974":\n        return config.LOC_REUNION\n    if value == "976":\n        return config.LOC_MAYOTTE\n    if value in {"2A", "2B"}:\n        return config.LOC_FRANCE\n    if value.isdigit() and 1 <= int(value) <= 95:\n        return config.LOC_FRANCE\n    return config.LOC_INCONNU\n\n\ndef _env_int(name: str, default: int) -> int:\n''',
)
replace(
    "cyberwatch/org_enrichment.py",
    '    activity_label = NAF_SECTION_LABELS.get(section, "")\n\n    matched_name = str(candidate.get("nom_raison_sociale") or candidate.get("nom_complet") or "")',
    '    activity_label = NAF_SECTION_LABELS.get(section, "")\n    headquarters = candidate.get("siege")\n    headquarters_department = (\n        str(headquarters.get("departement") or "") if isinstance(headquarters, dict) else ""\n    )\n\n    matched_name = str(candidate.get("nom_raison_sociale") or candidate.get("nom_complet") or "")',
)
replace(
    "cyberwatch/org_enrichment.py",
    '        Activity_Code=activity_code,\n        Activity_Label=activity_label,\n        Evidence_URL=',
    '        Activity_Code=activity_code,\n        Activity_Label=activity_label,\n        Headquarters_Department=headquarters_department,\n        Evidence_URL=',
)

# Colonne additive du cache technique uniquement ; aucun nouveau champ métier.
replace(
    "cyberwatch/model.py",
    '    "Activity_Label",\n    "Evidence_Source",',
    '    "Activity_Label",\n    "Headquarters_Department",\n    "Evidence_Source",',
)


# 3) Backfill unique : référence -> indice sûr -> cache API -> défaut source.
enrichment = ROOT / "cyberwatch/enrichment.py"
text = enrichment.read_text(encoding="utf-8")
text = text.replace("from . import config, store", "from . import config, org_enrichment, store", 1)
start = text.index("def backfill_unknowns(")
backfill = '''def _cached_api_locations() -> dict[str, str]:
    """Localisations exploitables déjà présentes dans le cache entreprise.

    Lecture locale uniquement : REPLAY ne déclenche jamais de réseau.
    """
    result: dict[str, str] = {}
    for row in store.load_org_enrichment_cache():
        if row.get("Match_Status") != org_enrichment.MATCHED:
            continue
        location = org_enrichment.location_for_headquarters_department(
            row.get("Headquarters_Department", "")
        )
        key = row.get("Organisation_Key", "")
        if key and location != config.LOC_INCONNU:
            result[key] = location
    return result


def _source_location_default(source_id: str) -> str:
    # Import local pour garder ce module de qualification indépendant de
    # l'inventaire des collecteurs à l'import.
    from . import sources

    spec = sources.by_id(source_id)
    if spec and spec.location_rule in config.LOCATIONS:
        return spec.location_rule
    return ""


def backfill_unknowns(items: list[Item], reference: dict[str, Enrichment]) -> dict[str, int]:
    """Complète menace/localisation inconnues avec la même logique hors-ligne.

    Pour Location : référentiel -> indice territorial sûr -> cache de l'API
    entreprise déjà alimenté -> défaut de la source. Aucun appel réseau et
    aucune propagation aveugle d'une localisation d'un item vers un autre.
    """
    report = {
        "threat": 0,
        "location_rule": 0,
        "location_api": 0,
        "location_default": 0,
        "location_reused": 0,
    }
    ordered = sort_items(items)
    api_locations = _cached_api_locations()

    for item in ordered:
        if item.Threat == config.THREAT_UNKNOWN:
            threat = _backfill_unknown_threat(item)
            if threat != config.THREAT_UNKNOWN:
                item.Threat = threat
                report["threat"] += 1

        if item.Location != config.LOC_INCONNU:
            continue

        _sector, location = enrich_unknowns(
            item.Organisation_Raw, item.Sector, item.Location, reference
        )
        if location == config.LOC_INCONNU:
            location = classify_location(item.Title, item.Organisation_Raw)
            if location != config.LOC_INCONNU:
                report["location_rule"] += 1

        if location == config.LOC_INCONNU:
            location = api_locations.get(item.Organisation_Key, config.LOC_INCONNU)
            if location != config.LOC_INCONNU:
                report["location_api"] += 1

        if location == config.LOC_INCONNU:
            default = _source_location_default(item.Source_ID)
            if default:
                location = default
                report["location_default"] += 1

        if location != config.LOC_INCONNU:
            item.Location = location

    return report
'''
enrichment.write_text(text[:start] + backfill, encoding="utf-8")


# 4) Changement matériel de la méthode canonique.
replace(
    "cyberwatch/config.py",
    'METHOD_ID = "OBS-FR-OI-SIMPLE-SOURCING-4"',
    'METHOD_ID = "OBS-FR-OI-SIMPLE-SOURCING-5"',
)


# 5) Tests ciblés : priorité, faux positifs, cache API et historique.
tests = r'''"""Qualification Location minimale : priorité et enrichissement sans appel dédié."""

from cyberwatch import ai, config, enrichment, org_enrichment, sources, store
from cyberwatch.collectors.base import RawEntry
from cyberwatch.model import Item
from cyberwatch.normalize import classify_location, organisation_key


def _item(source: str, title: str, *, org: str = "Organisation Test Location", location: str = config.LOC_INCONNU) -> Item:
    return Item(
        Item_ID=f"{source}-{title}",
        Source_ID=source,
        Published_Date="2026-08-16",
        Organisation_Raw=org,
        Organisation_Key=organisation_key(org),
        Threat=config.THREAT_LEAK,
        Sector=config.SECTOR_UNKNOWN,
        Location=location,
        Title=title,
        URL="https://example.test/location",
        Collected_As_Of="2026-08-16T10:00:00+04:00",
    )


def test_reunion_strong_hint_beats_france_default():
    assert classify_location(
        "Une entreprise réunionnaise victime d'une fuite",
        default=config.LOC_FRANCE,
    ) == config.LOC_REUNION


def test_mayotte_strong_hint_beats_france_default():
    assert classify_location(
        "Une société basée à Mayotte victime d'une attaque",
        default=config.LOC_FRANCE,
    ) == config.LOC_MAYOTTE


def test_reunion_de_crise_is_not_reunion_territory():
    assert classify_location(
        "La réunion de crise confirme l'incident",
        default=config.LOC_FRANCE,
    ) == config.LOC_FRANCE


def test_proper_name_la_reunion_is_recognized():
    assert classify_location("Victime implantée à La Réunion") == config.LOC_REUNION


def test_ambiguous_person_or_city_does_not_guess_location():
    assert classify_location("Maurice Dupont confirme l'incident") == config.LOC_INCONNU
    assert classify_location("Communiqué publié à Paris") == config.LOC_INCONNU


def test_headquarters_department_mapping_is_minimal():
    assert org_enrichment.location_for_headquarters_department("974") == config.LOC_REUNION
    assert org_enrichment.location_for_headquarters_department("976") == config.LOC_MAYOTTE
    assert org_enrichment.location_for_headquarters_department("75") == config.LOC_FRANCE
    assert org_enrichment.location_for_headquarters_department("2A") == config.LOC_FRANCE
    assert org_enrichment.location_for_headquarters_department("971") == config.LOC_INCONNU
    assert org_enrichment.location_for_headquarters_department("") == config.LOC_INCONNU


def test_org_record_keeps_headquarters_department():
    record = org_enrichment._record_from_candidate(
        "org test", "Org Test",
        {
            "nom_raison_sociale": "Org Test",
            "siren": "123456789",
            "activite_principale": "63.11Z",
            "section_activite_principale": "J",
            "siege": {"departement": "974"},
        },
        "2026-08-16",
    )
    assert record.Headquarters_Department == "974"


def test_historical_french_source_gets_default_france(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "ORG_ENRICHMENT_CACHE_CSV", tmp_path / "org.csv")
    item = _item("FRENCHBREACHES", "Fuite de données confirmée")
    enrichment.backfill_unknowns([item], {})
    assert item.Location == config.LOC_FRANCE


def test_historical_french_source_keeps_explicit_reunion_before_default(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "ORG_ENRICHMENT_CACHE_CSV", tmp_path / "org.csv")
    item = _item("BONJOURLAFUITE", "Entreprise réunionnaise : fuite de données")
    enrichment.backfill_unknowns([item], {})
    assert item.Location == config.LOC_REUNION


def test_backfill_reuses_existing_api_cache_without_network(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "ORG_ENRICHMENT_CACHE_CSV", tmp_path / "org.csv")
    item = _item("CYBERATTAQUE_ORG", "Cyberattaque confirmée", org="Org API Location")
    store.save_org_enrichment_cache([{
        "Organisation_Key": item.Organisation_Key,
        "Query_Name": item.Organisation_Raw,
        "Matched_Name": item.Organisation_Raw,
        "Company_ID": "123456789",
        "Activity_Code": "63.11Z",
        "Activity_Label": "Information et communication",
        "Headquarters_Department": "974",
        "Match_Status": org_enrichment.MATCHED,
        "Fetched_At": "2026-08-16",
        "Cache_Version": org_enrichment.ORG_ENRICHMENT_CACHE_VERSION,
    }])

    enrichment.backfill_unknowns([item], {})
    assert item.Location == config.LOC_REUNION


def test_location_is_not_propagated_blindly_between_items(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "ORG_ENRICHMENT_CACHE_CSV", tmp_path / "org.csv")
    org = "Organisation Sans Cache 9F8A"
    direct = _item("FRENCHBREACHES", "Fuite confirmée", org=org, location=config.LOC_FRANCE)
    unknown = _item("CYBERATTAQUE_ORG", "Cyberattaque confirmée", org=org)

    enrichment.backfill_unknowns([direct, unknown], {})
    assert unknown.Location == config.LOC_INCONNU


def test_existing_sector_enrichment_cache_can_feed_location_before_llm(tmp_path, monkeypatch):
    """Le cache produit par le même enrichissement secteur suffit ; aucun appel dédié Location."""
    monkeypatch.setattr(store, "ORG_ENRICHMENT_CACHE_CSV", tmp_path / "org.csv")
    item = _item("CYBERATTAQUE_ORG", "Cyberattaque confirmée", org="Org Cache Live")
    store.save_org_enrichment_cache([{
        "Organisation_Key": item.Organisation_Key,
        "Query_Name": item.Organisation_Raw,
        "Matched_Name": item.Organisation_Raw,
        "Company_ID": "987654321",
        "Activity_Code": "63.11Z",
        "Activity_Label": "Information et communication",
        "Headquarters_Department": "976",
        "Match_Status": org_enrichment.MATCHED,
        "Fetched_At": "2026-08-16",
        "Cache_Version": org_enrichment.ORG_ENRICHMENT_CACHE_VERSION,
    }])

    enrichment.backfill_unknowns([item], {})
    assert item.Location == config.LOC_MAYOTTE
'''
(ROOT / "tests/test_location_resolution.py").write_text(tests, encoding="utf-8")

print("Location patch applied")
