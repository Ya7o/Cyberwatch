from pathlib import Path


def replace(path: str, old: str, new: str) -> None:
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    if old not in text:
        raise SystemExit(f"motif introuvable dans {path}: {old[:140]!r}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


# Le premier garde-fou mono-token était trop large : conserver les marques
# correctement résolues (Scalingo, Biosynex...) et cibler les acronymes ainsi
# que les collisions de registre effectivement auditées.
replace(
    "cyberwatch/org_enrichment.py",
    '''def _registry_sector_identity_requires_confirmation(query_name: str) -> bool:\n    """Vrai si un match exact reste trop collisionnel pour prouver Sector."""\n    tokens = searchable(query_name).split()\n    if len(tokens) != 1:\n        return False\n    compact = re.sub(r"[^A-Za-zÀ-ÖØ-öø-ÿ]", "", str(query_name or ""))\n    if not compact:\n        return False\n    return (compact.isupper() and len(compact) <= 12) or len(tokens[0]) <= 8\n''',
    '''_REGISTRY_SECTOR_COLLISION_KEYS = frozenset({"generali"})\n\n\ndef _registry_sector_identity_requires_confirmation(query_name: str) -> bool:\n    """Vrai si un match exact reste trop collisionnel pour prouver Sector."""\n    tokens = searchable(query_name).split()\n    if len(tokens) != 1:\n        return False\n    compact = re.sub(r"[^A-Za-zÀ-ÖØ-öø-ÿ]", "", str(query_name or ""))\n    if not compact:\n        return False\n    if compact.isupper() and len(compact) <= 12:\n        return True\n    return searchable(query_name) in _REGISTRY_SECTOR_COLLISION_KEYS\n''',
)

# Les tests historiques doivent refléter la nouvelle politique immobilière.
replace(
    "tests/test_ai_qualification.py",
    '    def test_activite_immobiliere_enrichie_mappe_construction_btp(self, make_item, monkeypatch):\n'
    '        """Cas Savills avec enrichissement réussi : org_enrichment.NAF_SECTIONS\n'
    '        (non mocké) doit suffire, sans second appel LLM — la seule\n'
    '        information que fournit réellement l\'API est le titre de section\n'
    '        NAF "Activités immobilières" (cf. org_enrichment.py)."""\n',
    '    def test_activite_immobiliere_enrichie_reste_inconnue(self, make_item, monkeypatch):\n'
    '        """Un NAF immobilier générique ne prouve pas Construction / BTP."""\n',
)
replace(
    "tests/test_ai_qualification.py",
    '        assert item.Sector == "Construction / BTP"\n'
    '        assert state.sector_resolved_enriched_deterministic == 1\n'
    '        assert state.sector_resolved_enriched_llm == 0\n',
    '        assert item.Sector == config.SECTOR_UNKNOWN\n'
    '        assert state.sector_resolved_enriched_deterministic == 0\n'
    '        assert state.sector_resolved_enriched_llm == 0\n',
)

# Le test de métriques conserve une vraie voie déterministe mais avec une
# section NAF univoque, plutôt qu'avec l'immobilier désormais ambigu.
replace(
    "tests/test_ai_qualification.py",
    '        item_enriched = make_item(source_item_id="b", org="Savills France", sector=config.SECTOR_UNKNOWN)\n'
    '        entry_enriched = RawEntry(\n'
    '            title="Savills France victime d\'un rançongiciel",\n'
    '            summary="Le groupe LockBit revendique l\'attaque.",\n'
    '            published="2026-06-01", organisation="Savills France",\n'
    '        )\n'
    '        record = org_enrichment.OrgEnrichmentRecord(\n'
    '            Organisation_Key=item_enriched.Organisation_Key, Query_Name="Savills France",\n'
    '            Activity_Label="Activités immobilières", Match_Status=org_enrichment.MATCHED,\n'
    '            Fetched_At="2026-08-15",\n'
    '        )\n',
    '        item_enriched = make_item(source_item_id="b", org="Industrie Exemple", sector=config.SECTOR_UNKNOWN)\n'
    '        entry_enriched = RawEntry(\n'
    '            title="Industrie Exemple victime d\'un rançongiciel",\n'
    '            summary="Le groupe LockBit revendique l\'attaque.",\n'
    '            published="2026-06-01", organisation="Industrie Exemple",\n'
    '        )\n'
    '        record = org_enrichment.OrgEnrichmentRecord(\n'
    '            Organisation_Key=item_enriched.Organisation_Key, Query_Name="Industrie Exemple",\n'
    '            Activity_Label="Industrie manufacturière", Match_Status=org_enrichment.MATCHED,\n'
    '            Fetched_At="2026-08-15",\n'
    '        )\n',
)
