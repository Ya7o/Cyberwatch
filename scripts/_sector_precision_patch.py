from pathlib import Path


def replace(path: str, old: str, new: str) -> None:
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    if old not in text:
        raise SystemExit(f"motif introuvable dans {path}: {old[:120]!r}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


# Taxonomie et règles nominatives conservatrices.
replace("cyberwatch/config.py", '    "real estate": SECTOR_CONSTRUCTION,', '    "real estate": SECTOR_UNKNOWN,')
replace(
    "cyberwatch/config.py",
    '        "mairie de", "ville de", "commune de", "ministere de", "ministere des",\n',
    '        "mairie de", "mairie d", "mairie du", "mairie des",\n'
    '        "ville de", "commune de", "commune d", "the commune of", "commune of",\n'
    '        "ministere de", "ministere des",\n',
)
replace(
    "cyberwatch/config.py",
    '        "universite de", "ecole de", "ecole superieure", "college de",\n'
    '        "lycee", "academie de", "rectorat de",\n',
    '        "universite de", "universite d", "university", "ecole de",\n'
    '        "ecole superieure", "ecole nationale superieure", "college de",\n'
    '        "lycee", "academie de", "rectorat de",\n',
)
replace(
    "cyberwatch/config.py",
    '    (SECTOR_FINANCE, ["banque de", "caisse d epargne", "credit agricole"]),',
    '    (SECTOR_FINANCE, ["banque de", "caisse d epargne", "credit agricole", "mutuelle"]),',
)
replace(
    "cyberwatch/config.py",
    '    (SECTOR_SPORT, [\n'
    '        "federation francaise de", "federation francaise d ",\n'
    '        "federation sportive", "stade francais",\n'
    '    ]),',
    '    (SECTOR_SPORT, ["federation sportive", "stade francais"]),',
)

# Registre entreprise : immobilier générique et identités collisionnelles.
replace("cyberwatch/org_enrichment.py", 'import os\nimport time\n', 'import os\nimport re\nimport time\n')
replace("cyberwatch/org_enrichment.py", 'from .normalize import organisation_key\n', 'from .normalize import organisation_key, searchable\n')
replace(
    "cyberwatch/org_enrichment.py",
    '    "L": ("Activités immobilières", config.SECTOR_CONSTRUCTION),',
    '    "L": ("Activités immobilières", config.SECTOR_UNKNOWN),',
)
replace(
    "cyberwatch/org_enrichment.py",
    '# Version 3 : après le registre exact, une preuve provenant du site officiel\n'
    '# peut résoudre le secteur. Les anciens NOT_FOUND/AMBIGUOUS doivent être\n'
    '# retentés afin de bénéficier de ce nouveau chemin.\n'
    'ORG_ENRICHMENT_CACHE_VERSION = "3"',
    '# Version 4 : les identités registre courtes/acronymiques ne suffisent plus\n'
    '# à produire un secteur. Elles doivent être confirmées par une preuve\n'
    '# officielle ; les anciennes lignes MATCHED à risque sont donc retentées.\n'
    'ORG_ENRICHMENT_CACHE_VERSION = "4"',
)
replace(
    "cyberwatch/org_enrichment.py",
    '\ndef start_state() -> OrgEnrichmentState:\n',
    '''\ndef _registry_sector_identity_requires_confirmation(query_name: str) -> bool:\n    """Vrai si un match exact reste trop collisionnel pour prouver Sector."""\n    tokens = searchable(query_name).split()\n    if len(tokens) != 1:\n        return False\n    compact = re.sub(r"[^A-Za-zÀ-ÖØ-öø-ÿ]", "", str(query_name or ""))\n    if not compact:\n        return False\n    return (compact.isupper() and len(compact) <= 12) or len(tokens[0]) <= 8\n\n\ndef start_state() -> OrgEnrichmentState:\n''',
)
replace(
    "cyberwatch/org_enrichment.py",
    '        if row.get("Cache_Version") != ORG_ENRICHMENT_CACHE_VERSION:\n'
    '            if row.get("Match_Status") in (NOT_FOUND, AMBIGUOUS):\n'
    '                continue\n'
    '            row = dict(row)\n'
    '            row["Validated_Sector"] = ""\n'
    '            row["Validated_Via"] = ""\n'
    '            row["Cache_Version"] = ORG_ENRICHMENT_CACHE_VERSION\n',
    '        if row.get("Cache_Version") != ORG_ENRICHMENT_CACHE_VERSION:\n'
    '            if row.get("Match_Status") in (NOT_FOUND, AMBIGUOUS):\n'
    '                continue\n'
    '            if (\n'
    '                row.get("Match_Status") == MATCHED\n'
    '                and _registry_sector_identity_requires_confirmation(row.get("Query_Name", ""))\n'
    '            ):\n'
    '                continue\n'
    '            row = dict(row)\n'
    '            row["Validated_Sector"] = ""\n'
    '            row["Validated_Via"] = ""\n'
    '            row["Cache_Version"] = ORG_ENRICHMENT_CACHE_VERSION\n',
)
replace(
    "cyberwatch/org_enrichment.py",
    '    if status == MATCHED:\n'
    '        state.calls_matched += 1\n'
    '        record = _record_from_candidate(\n'
    '            org_key, organisation_raw, candidate, fetched_at\n'
    '        )\n'
    '        state.cache[org_key] = asdict(record)\n'
    '        return record\n',
    '    if status == MATCHED:\n'
    '        record = _record_from_candidate(\n'
    '            org_key, organisation_raw, candidate, fetched_at\n'
    '        )\n'
    '        if _registry_sector_identity_requires_confirmation(organisation_raw):\n'
    '            attempted, official_record = _official_site_fallback(\n'
    '                org_key, organisation_raw, fetched_at, state\n'
    '            )\n'
    '            if official_record is not None:\n'
    '                state.cache[org_key] = asdict(official_record)\n'
    '                return official_record\n'
    '            record.Activity_Label = ""\n'
    '            record.Validated_Via = "registry_identity_unconfirmed"\n'
    '            state.calls_matched += 1\n'
    '            if attempted:\n'
    '                state.cache[org_key] = asdict(record)\n'
    '            return record\n'
    '        state.calls_matched += 1\n'
    '        state.cache[org_key] = asdict(record)\n'
    '        return record\n',
)

# Site officiel : une activité immobilière générique n'est pas assimilée au BTP.
replace(
    "cyberwatch/company_evidence.py",
    '        r"\\b(btp\\b|construction|travaux publics|g[ée]nie civil|civil engineering|promoteur immobilier|"\n'
    '        r"promotion immobili[eè]re|real estate developer|entreprise du b[âa]timent|"\n'
    '        r"activit[ée]s immobili[eè]res)\\b",\n',
    '        r"\\b(btp\\b|construction|travaux publics|g[ée]nie civil|civil engineering|promoteur immobilier|"\n'
    '        r"promotion immobili[eè]re|real estate developer|entreprise du b[âa]timent)\\b",\n',
)

# Nom d'organisation : formes institutionnelles sûres et fédérations sportives explicites.
replace(
    "cyberwatch/sector.py",
    'def classify_sector_name(organisation: str) -> str:\n'
    '    """Classe un nom uniquement avec des preuves nominatives sûres."""\n'
    '    sector = _watchlist_sector(organisation)\n'
    '    if sector != config.SECTOR_UNKNOWN:\n'
    '        return sector\n'
    '    return _from_rules(organisation, config.SECTOR_NAME_RULES)\n',
    '''_NAME_PREFIX_SECTORS = (\n    ("mairie ", config.SECTOR_ADMIN),\n    ("commune ", config.SECTOR_ADMIN),\n    ("the commune of ", config.SECTOR_ADMIN),\n    ("ville ", config.SECTOR_ADMIN),\n    ("universite ", config.SECTOR_EDUCATION),\n    ("university ", config.SECTOR_EDUCATION),\n    ("ecole nationale superieure ", config.SECTOR_EDUCATION),\n)\n\n_FRENCH_FEDERATION_SPORT_MARKERS = (\n    "sport", "football", "rugby", "handball", "basket", "karate",\n    "danse", "motocyclisme", "escrime", "golf", "volley", "tennis",\n    "voile", "randonnee", "aikido", "aikibudo", "gymnastique",\n    "cyclisme", "natation", "judo", "athletisme", "triathlon", "chasse",\n    "aeronautique", "canoe", "kayak", "petanque", "ski", "surf",\n)\n\n\ndef _sector_from_safe_name(organisation: str) -> str:\n    blob = searchable(organisation)\n    if not blob:\n        return config.SECTOR_UNKNOWN\n    for prefix, sector in _NAME_PREFIX_SECTORS:\n        if blob.startswith(prefix):\n            return sector\n    if blob.startswith(("federation francaise de ", "federation francaise d ")):\n        if any(_contains(blob, marker) for marker in _FRENCH_FEDERATION_SPORT_MARKERS):\n            return config.SECTOR_SPORT\n    return _from_rules(organisation, config.SECTOR_NAME_RULES)\n\n\ndef classify_sector_name(organisation: str) -> str:\n    """Classe un nom uniquement avec des preuves nominatives sûres."""\n    sector = _watchlist_sector(organisation)\n    if sector != config.SECTOR_UNKNOWN:\n        return sector\n    for candidate in (organisation, organisation_key(organisation)):\n        sector = _sector_from_safe_name(candidate)\n        if sector != config.SECTOR_UNKNOWN:\n            return sector\n    return config.SECTOR_UNKNOWN\n''',
)

# Sentinelles de release.
tests = Path("tests/test_sector_stabilization.py")
text = tests.read_text(encoding="utf-8")
if "test_federation_non_sportive_ne_devient_pas_sport" in text:
    raise SystemExit("tests déjà présents")
text = text.rstrip() + r'''


def test_federation_non_sportive_ne_devient_pas_sport():
    assert sector.classify_sector_name(
        "Fédération française de l’Ordre Maçonnique Mixte International Le Droit Humain"
    ) == config.SECTOR_UNKNOWN


def test_federations_sportives_explicitement_identifiables_restent_sport():
    assert sector.classify_sector_name("Fédération Française de Danse") == config.SECTOR_SPORT
    assert sector.classify_sector_name("Fédération Française de Handball") == config.SECTOR_SPORT
    assert sector.classify_sector_name("Fédération Française d’Escrime") == config.SECTOR_SPORT


def test_variantes_institutionnelles_sures_sont_classees():
    assert sector.classify_sector_name("Mairie d’Eyguières") == config.SECTOR_ADMIN
    assert sector.classify_sector_name("Mairie Thiverval Grignon") == config.SECTOR_ADMIN
    assert sector.classify_sector_name("The commune of Castries") == config.SECTOR_ADMIN
    assert sector.classify_sector_name("ville-rinxent") == config.SECTOR_ADMIN
    assert sector.classify_sector_name("Université d’Avignon") == config.SECTOR_EDUCATION
    assert sector.classify_sector_name("La Mutuelle Familiale") == config.SECTOR_FINANCE


def test_alias_acronyme_valide_peut_fournir_un_nom_auto_descriptif():
    assert sector.classify_sector_name("ENSAM") == config.SECTOR_EDUCATION


def test_naf_immobilier_ne_devient_plus_btp():
    label = org_enrichment.NAF_SECTION_LABELS["L"]
    assert org_enrichment.sector_for_activity_label(label) == config.SECTOR_UNKNOWN
    assert sector.classify_source_sector("real estate") == config.SECTOR_UNKNOWN


def test_identites_registre_courtes_exigent_confirmation():
    for name in ("ENSAM", "CROUS", "Generali"):
        assert org_enrichment._registry_sector_identity_requires_confirmation(name) is True
    assert org_enrichment._registry_sector_identity_requires_confirmation("Bureau Vallée") is False
    assert org_enrichment._registry_sector_identity_requires_confirmation("Cravero Motoculture") is False


def test_match_registre_court_sans_preuve_officielle_ne_fournit_pas_de_sector(monkeypatch):
    payload = {
        "results": [{
            "siren": "523806735",
            "nom_raison_sociale": "CROUS",
            "nom_complet": "CROUS",
            "activite_principale": "41.20B",
            "section_activite_principale": "F",
            "siege": {"departement": "69"},
        }]
    }
    monkeypatch.setattr(org_enrichment, "_fetch", lambda _query, _state: payload)
    monkeypatch.setattr(org_enrichment.company_evidence, "resolve_official_site", lambda _name: None)
    state = org_enrichment.OrgEnrichmentState(enabled=True, max_calls=1, official_site_max_calls=1)
    record = org_enrichment.resolve("crous", "CROUS", "2026-08-17T00:00:00+04:00", state)
    assert record is not None
    assert record.Match_Status == org_enrichment.MATCHED
    assert record.Activity_Label == ""
    assert record.Validated_Sector == ""
    assert record.Validated_Via == "registry_identity_unconfirmed"


def test_match_registre_deux_mots_conserve_mapping_deterministe(monkeypatch):
    payload = {
        "results": [{
            "siren": "123456789",
            "nom_raison_sociale": "Bureau Vallée",
            "nom_complet": "Bureau Vallée",
            "activite_principale": "47.62Z",
            "section_activite_principale": "G",
            "siege": {"departement": "75"},
        }]
    }
    monkeypatch.setattr(org_enrichment, "_fetch", lambda _query, _state: payload)
    state = org_enrichment.OrgEnrichmentState(enabled=True, max_calls=1, official_site_max_calls=0)
    record = org_enrichment.resolve("bureau vallee", "Bureau Vallée", "2026-08-17T00:00:00+04:00", state)
    assert record is not None
    assert record.Activity_Label == org_enrichment.NAF_SECTION_LABELS["G"]
    assert org_enrichment.sector_for_activity_label(record.Activity_Label) == config.SECTOR_RETAIL
'''
tests.write_text(text + "\n", encoding="utf-8")
