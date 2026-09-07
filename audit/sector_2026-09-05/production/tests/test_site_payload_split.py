"""Contrats des fichiers publiés par `build-site`.

Le découpage suit la fréquence des parcours : la consultation de veille, la
plus fréquente, ne doit pas payer le poids des faits détaillés qu'elle
n'affiche pas.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from datetime import date, timedelta

from cyberwatch import config, site

ATOM = {"a": "http://www.w3.org/2005/Atom"}


def _row(day, ident, *, location="France métropolitaine", org="Org", urls=None, facts=None):
    row = {
        "id": ident, "date": day, "org": org, "sector": "Santé", "threat": "Ransomware",
        "location": location, "sources": ["BONJOURLAFUITE"], "urls": urls or [],
        "items": 1, "first_seen": f"{day}T00:00:00+00:00", "last_seen": f"{day}T00:00:00+00:00",
    }
    if facts:
        row["facts"] = facts
    return row


def _payload():
    today = date(2026, 8, 21)
    return [
        _row((today - timedelta(days=offset)).isoformat(), f"INC-{offset:03d}",
             location="La Réunion" if offset % 20 == 0 else "France métropolitaine",
             facts=[{"source": "BONJOURLAFUITE", "item_id": f"ITM-{offset}", "impact": "x"}])
        for offset in range(0, 120)
    ]


def test_latest_est_borne_a_la_fenetre_de_veille_et_sans_faits():
    latest = site._latest_payload(_payload())
    assert len(latest) == site.LATEST_WINDOW_DAYS
    assert all("facts" not in row for row in latest)
    # Le plus récent en tête : la veille se lit de haut en bas.
    assert latest[0]["date"] > latest[-1]["date"]


def test_le_payload_principal_perd_les_faits_mais_garde_ce_qui_se_lit_en_liste():
    row = _row("2026-08-20", "INC-1", facts=[{"source": "X", "item_id": "I"}])
    row["summary"] = "Synthèse lue dans la liste"
    row["local"] = {"score": 80, "summary": "Analyse locale", "references": []}
    slim = site._without_facts(row)
    assert "facts" not in slim
    assert slim["summary"] == "Synthèse lue dans la liste"
    assert slim["local"]["score"] == 80


# ------------------------------------------------------ flux du périmètre

def test_le_flux_du_perimetre_prioritaire_est_un_atom_valide_et_borne():
    feed = site.focus_feed(_payload(), as_of="2026-08-21T23:00:00+04:00", site_url="https://example.test/")
    root = ET.fromstring(feed)
    entries = root.findall("a:entry", ATOM)
    assert entries
    assert len(entries) <= site.FEED_MAX_ENTRIES
    assert root.find("a:updated", ATOM).text == "2026-08-21T23:00:00+04:00"
    # Le périmètre vient de la configuration, jamais d'une liste écrite en dur.
    assert " / ".join(config.FOCUS_LOCATIONS) in root.find("a:title", ATOM).text


def test_le_flux_est_identique_a_entrees_identiques():
    """Un flux horodaté sur l'heure courante produirait une modification à chaque run."""
    payload = _payload()
    first = site.focus_feed(payload, as_of="2026-08-21T23:00:00+04:00", site_url="https://example.test/")
    second = site.focus_feed(list(reversed(payload)), as_of="2026-08-21T23:00:00+04:00", site_url="https://example.test/")
    assert first == second


def test_le_flux_ne_renvoie_jamais_vers_un_site_de_revendication_onion():
    """Un lecteur de flux en ferait un lien cliquable vers l'infrastructure d'un groupe criminel."""
    rows = [_row("2026-08-20", "INC-A", location="Mayotte",
                 urls=["http://abcdef.onion/leak?id=1", "https://presse.example/article"])]
    feed = site.focus_feed(rows, as_of="2026-08-21T00:00:00Z", site_url="https://example.test/")
    assert ".onion" not in feed
    assert "https://presse.example/article" in feed

    only_onion = [_row("2026-08-20", "INC-B", location="Mayotte", urls=["http://abcdef.onion/leak"])]
    fallback = site.focus_feed(only_onion, as_of="2026-08-21T00:00:00Z", site_url="https://example.test/")
    assert ".onion" not in fallback
    assert "https://example.test/" in fallback


def test_le_flux_nomme_les_sources_avec_le_libelle_partage():
    rows = [_row("2026-08-20", "INC-C", location="La Réunion")]
    rows[0]["sources"] = ["VEILLE_LLM"]
    feed = site.focus_feed(rows, as_of="2026-08-21T00:00:00Z", site_url="https://example.test/")
    assert config.source_label("VEILLE_LLM") in feed
    assert "VEILLE_LLM" not in feed


# ------------------------------------------------------ libellés partagés

def test_les_libelles_de_sources_ont_une_seule_origine():
    """`VEILLE_LLM` s'affichait « veillellmReYt » dans app.js et « Veille IA » dans p2.js."""
    from cyberwatch import sources
    for spec in sources.ALL_SOURCES:
        assert spec.source_id in config.SOURCE_LABELS, spec.source_id
        assert config.source_label(spec.source_id) != spec.source_id
    assert config.source_label("SOURCE_INCONNUE") == "SOURCE_INCONNUE"


def test_les_libelles_sont_publies_pour_la_page():
    state = site.status_payload()
    assert state["labels"]["sources"] == config.SOURCE_LABELS
