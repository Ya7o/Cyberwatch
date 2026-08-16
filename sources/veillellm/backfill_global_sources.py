#!/usr/bin/env python3
import csv
import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

YEAR = 2026
OUT = Path("sources/veillellm")
OUT.mkdir(parents=True, exist_ok=True)
UA = "Cyberwatch/1.0 (+https://github.com/Ya7o/Cyberwatch)"
S = requests.Session()
S.headers.update({"User-Agent": UA, "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.7"})

TYPE_VALUES = {
    "Ransomware", "DDoS", "Malware", "Compromission de compte / messagerie",
    "Intrusion", "Fuite de données", "Phishing / fraude", "Incident tiers",
    "Autre cyber", "Inconnu"
}
SECTOR_VALUES = {
    "Administration / Collectivité", "Santé", "Éducation / Formation",
    "Finance / Assurance", "Transport / Logistique", "Sport",
    "Commerce / Distribution", "Numérique / Technologie", "Énergie / Utilities",
    "Industrie / Manufacture", "Construction / BTP", "Services aux entreprises",
    "Inconnu"
}

MONTHS = {
    "janvier": 1, "février": 2, "fevrier": 2, "mars": 3, "avril": 4,
    "mai": 5, "juin": 6, "juillet": 7, "août": 8, "aout": 8,
    "septembre": 9, "octobre": 10, "novembre": 11, "décembre": 12, "decembre": 12,
}


def get(url, timeout=30):
    for i in range(4):
        try:
            r = S.get(url, timeout=timeout)
            if r.status_code == 404:
                return None
            r.raise_for_status()
            return r
        except requests.RequestException:
            if i == 3:
                raise
            time.sleep(1.5 * (i + 1))


def parse_date(text):
    text = " ".join((text or "").split()).lower()
    m = re.search(r"\b(\d{1,2})\s+(janvier|février|fevrier|mars|avril|mai|juin|juillet|août|aout|septembre|octobre|novembre|décembre|decembre)\s+(20\d{2})\b", text)
    if m:
        return datetime(int(m.group(3)), MONTHS[m.group(2)], int(m.group(1))).date()
    m = re.search(r"\b(\d{1,2})/(\d{1,2})/(20\d{2})\b", text)
    if m:
        return datetime(int(m.group(3)), int(m.group(2)), int(m.group(1))).date()
    return None


def clean_org_from_title(title):
    t = re.sub(r"\s+", " ", title).strip()
    m = re.match(r"Cyberattaque\s+(?:à|chez|contre)\s+([^:–—-]+)", t, re.I)
    if m:
        return m.group(1).strip()
    for sep in (" : ", ": ", " – ", " — "):
        if sep in t:
            p = t.split(sep, 1)[0].strip()
            if len(p) >= 2:
                return p
    return t[:180]


def infer_threat(text):
    s = (text or "").lower()
    if re.search(r"ransomware|rançongiciel|rancongiciel|chiffr(?:ement|é|e)|\bqilin\b|\blockbit\b|\bkrybit\b|\banubis\b", s):
        return "Ransomware"
    if re.search(r"\bddos\b|déni de service|deni de service|saturation", s):
        return "DDoS"
    if re.search(r"malware|cheval de troie|trojan|spyware|infostealer|botnet|virus", s):
        return "Malware"
    if re.search(r"compromission (?:de )?(?:compte|messagerie)|bo[iî]te mail|messagerie compromise|account takeover|identifiants? vol", s):
        return "Compromission de compte / messagerie"
    if re.search(r"intrusion|accès non autorisé|acces non autorise|injection sql|sql injection|système compromis|systeme compromis|pirat(?:age|é|e)", s):
        return "Intrusion"
    if re.search(r"fuite de données|fuite massive|exfiltrat|data breach|données exposées|donnees exposees|données volées|donnees volees|données diffusées|donnees diffusees|base de données.*(?:fuite|publiée|diffusée)", s):
        return "Fuite de données"
    if re.search(r"phishing|hameçonnage|hameconnage|smishing|faux site|usurpation|arnaque|fraude", s):
        return "Phishing / fraude"
    if re.search(r"prestataire|fournisseur|sous-traitant|chaîne d'approvisionnement|supply chain", s):
        return "Incident tiers"
    if re.search(r"cyberattaque|incident de sécurité|incident de securite|compromission", s):
        return "Autre cyber"
    return "Inconnu"


def infer_sector(org, text=""):
    s = f"{org} {text}".lower()
    if re.search(r"banque|assurance|mutuelle|prévoyance|prevoyance|crédit|credit|cetelem|sofinco|yomoni|waltio", s):
        return "Finance / Assurance"
    if re.search(r"hôpital|hopital|hospices|clinique|santé|sante|pharma|laboratoire|ehpad|médecin|medecin|biosynex|synlab|biomérieux|biomerieux", s):
        return "Santé"
    if re.search(r"universit|école|ecole|collège|college|lycée|lycee|formation|académie|academie|enseignement|campus|afpa|parcoursup|ed[u]?connect|insep|inseei|crous|étudiant|etudiant", s):
        return "Éducation / Formation"
    if re.search(r"mairie|ville de |ministère|ministere|département|departement|métropole|metropole|préfecture|prefecture|gouvernement|service-public|service publique|gendarmerie|police municipale|ants|anct|urssaf|ofii|banatic|collectivité|collectivite", s):
        return "Administration / Collectivité"
    if re.search(r"fédération française|federation francaise|football|handball|rugby|sport|club|fitness|gymnastique|judo|karaté|karate|athlétisme|athletisme|natation|tennis|golf|squash|volley|basket|moto|voile|aikido|savate", s):
        return "Sport"
    if re.search(r"compagnie aérienne|compagnie aerienne|aéroport|aeroport|transport|logistique|trenitalia|ratp|relais colis|aviation|air austral|air corsica|mondial relay", s):
        return "Transport / Logistique"
    if re.search(r"télécom|telecom|cloud|hébergeur|hebergeur|logiciel|software|informatique|technologie|\btech\b|openai|mistral ai|sfr|bouygues telecom|kosc|erp|web|hosting|blgcloud", s):
        return "Numérique / Technologie"
    if re.search(r"engie|edf|enercoop|énergie|energie|utilities|pétrole|petrole|gaz", s):
        return "Énergie / Utilities"
    if re.search(r"industrie|manufactur|usine|safran|thales|automobile|skoda|renault", s):
        return "Industrie / Manufacture"
    if re.search(r"immobilier|construction|bâtiment|batiment|travaux publics|batipro|socotec|arthurimmo|capifrance|nestenn|propriétés privées|proprietes privees", s):
        return "Construction / BTP"
    if re.search(r"intermarché|intermarche|lidl|auchan|leroy merlin|darty|la redoute|manomano|bureau vallée|bureau vallee|boutique|e-commerce|commerce|magasin|grossiste|optic|boulangerie|easycash", s):
        return "Commerce / Distribution"
    if re.search(r"cabinet|conseil|recrutement|intérim|interim|services aux entreprises|expert-comptable|comptable|crit|avocat|juridique", s):
        return "Services aux entreprises"
    return "Inconnu"


def infer_territory(org, text=""):
    s = f"{org} {text}".lower()
    if re.search(r"la réunion|réunionnais|reunionnais|air austral|saint-denis.*réunion|saint-paul.*réunion|bras-panon", s):
        return "La Réunion"
    if re.search(r"mayotte|mamoudzou|mahorais", s):
        return "Mayotte"
    if re.search(r"belgique|belge|lidl \(belgique\)|ifapme", s):
        return "Belgique"
    if re.search(r"suisse|swiss|lancy fc", s):
        return "Suisse"
    if re.search(r"tunisie|tunisien|tunisienne", s):
        return "Tunisie"
    if re.search(r"états-unis|etats-unis|usa|américain|americaine|intoxalock", s):
        return "États-Unis"
    if re.search(r"commission européenne|commission europeenne|union européenne|union europeenne", s):
        return "Union européenne"
    if re.search(r"france|français|francaise|française|mairie|ville de |ministère|ministere|département|departement|métropole|metropole|fédération française|federation francaise|académie|academie|crous|urssaf|service-public|gendarmerie|cnrs|insee|ants|afpa", s):
        return "France"
    return "Inconnu"


def infer_actor(text):
    s = text or ""
    patterns = [
        r"\b(Qilin|LockBit|KRYBit|Anubis|ChimeraZ|ZeroBytes|0xSec|Cybernox|TeamPCP|LAPSUS\$|incransom)\b"
    ]
    for p in patterns:
        m = re.search(p, s, re.I)
        if m:
            return m.group(1)
    return "Inconnu"


def infer_status_score(text):
    s = (text or "").lower()
    if re.search(r"confirme|confirmé|confirmée|a reconnu|reconnaît|annonce (?:avoir|être)|victime confirme", s):
        return "Confirmé", 100
    if re.search(r"revendiqu|affirme|prétend|pretend|selon le hacker|sur un forum cybercriminel", s):
        return "Revendiqué / non corroboré", 65
    return "Signal documenté par la source", 60


def make_incident(date, org, territory, sector, threat, actor, status, score, impact, source, synthese):
    territory = territory or "Inconnu"
    sector = sector if sector in SECTOR_VALUES else "Inconnu"
    threat = threat if threat in TYPE_VALUES else "Inconnu"
    return {
        "date": date.isoformat(),
        "organisation": org.strip() or "Inconnu",
        "territoire": territory,
        "localisation": "Inconnu",
        "secteur": sector,
        "type_menace": threat,
        "acteur": actor or "Inconnu",
        "statut": status,
        "score_cyberattaque": int(score),
        "impact_connu": impact.strip()[:1500] if impact else "Inconnu",
        "sources": [source],
        "synthese": synthese.strip()[:1500],
        "evolution": "nouveau",
    }


def scrape_cyberattaque():
    base = "https://www.cyberattaque.org/type/attaque/"
    out, seen = [], set()
    reached_pre_year = False
    for page in range(1, 80):
        url = base if page == 1 else f"{base}page/{page}/"
        r = get(url)
        if r is None:
            break
        soup = BeautifulSoup(r.text, "html.parser")
        articles = soup.find_all("article")
        if not articles:
            # Generic WordPress fallback: use heading links and nearest container text.
            articles = []
            for h in soup.find_all(["h2", "h3"]):
                a = h.find("a", href=True)
                if a and "/type/" not in a["href"]:
                    articles.append(h.parent)
        page_dates = []
        page_added = 0
        for art in articles:
            txt = " ".join(art.get_text(" ", strip=True).split())
            d = parse_date(txt)
            if not d:
                t = art.find("time") if hasattr(art, "find") else None
                if t:
                    d = parse_date(t.get("datetime", "") + " " + t.get_text(" ", strip=True))
            if not d:
                continue
            page_dates.append(d)
            if d.year != YEAR:
                continue
            title_el = art.find(["h1", "h2", "h3"]) if hasattr(art, "find") else None
            a = title_el.find("a", href=True) if title_el else None
            if not a:
                # pick a same-domain content link, excluding category/navigation
                for cand in art.find_all("a", href=True):
                    href = urljoin(url, cand["href"])
                    if urlparse(href).netloc.endswith("cyberattaque.org") and "/type/" not in href and cand.get_text(strip=True):
                        a = cand
                        break
            if not a:
                continue
            link = urljoin(url, a["href"])
            if link in seen:
                continue
            title = " ".join(a.get_text(" ", strip=True).split())
            if not title:
                continue
            seen.add(link)
            org = clean_org_from_title(title)
            threat = infer_threat(title + " " + txt)
            sector = infer_sector(org, title + " " + txt)
            territory = infer_territory(org, title + " " + txt)
            actor = infer_actor(title + " " + txt)
            status, score = infer_status_score(title + " " + txt)
            # Use the article excerpt as impact when available; remove title/date noise conservatively.
            paras = [" ".join(p.get_text(" ", strip=True).split()) for p in art.find_all("p")]
            impact = max(paras, key=len) if paras else txt
            out.append(make_incident(
                d, org, territory, sector, threat, actor, status, score,
                impact, link,
                f"Rattrapage 2026 Cyberattaque.org — {title}"
            ))
            page_added += 1
        if page_dates and max(page_dates).year < YEAR:
            reached_pre_year = True
            break
        if not page_dates and page > 3:
            break
        # Be polite to the source.
        time.sleep(0.2)
    out.sort(key=lambda x: (x["date"], x["organisation"], x["sources"][0]), reverse=True)
    return out, reached_pre_year


def scrape_frenchbreaches():
    archive = "https://frenchbreaches.com/archives"
    r = get(archive)
    soup = BeautifulSoup(r.text, "html.parser")
    out, seen = [], set()
    found_2026 = False
    reached_2025 = False
    for li in soup.find_all("li"):
        txt = " ".join(li.get_text(" ", strip=True).split())
        d = parse_date(txt)
        if not d:
            continue
        if d.year == YEAR:
            found_2026 = True
        elif found_2026 and d.year < YEAR:
            reached_2025 = True
            break
        else:
            continue
        a = li.find("a", href=True)
        if not a:
            continue
        org = " ".join(a.get_text(" ", strip=True).split())
        link = urljoin(archive, a["href"])
        key = (d.isoformat(), org, link)
        if key in seen:
            continue
        seen.add(key)
        territory = infer_territory(org)
        sector = infer_sector(org)
        out.append(make_incident(
            d, org, territory, sector, "Fuite de données", "Inconnu",
            "Référencé par FrenchBreaches ; corroboration variable", 50,
            "Alerte référencée dans l’archive 2026 de FrenchBreaches ; détails à enrichir depuis la fiche source.",
            link,
            f"Rattrapage 2026 depuis l’archive FrenchBreaches — {org}."
        ))
    out.sort(key=lambda x: (x["date"], x["organisation"], x["sources"][0]), reverse=True)
    return out, reached_2025


def write_dataset(stem, source_name, source_url, incidents, backfill_complete, limitations):
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    metadata = {
        "year": YEAR,
        "source": source_name,
        "scope": "Monde",
        "generated_at": now,
        "record_count": len(incidents),
        "backfill_required": False,
        "backfill_status": "completed_best_effort" if incidents else "failed_empty",
        "backfill_complete_to_2025_boundary": bool(backfill_complete),
        "schema": "cyberwatch-global-source-v1",
        "watch_result": {
            "new_incidents": len(incidents),
            "enriched_incidents": 0,
            "corrected_incidents": 0,
            "note": "Rattrapage initial 2026 ; les exécutions suivantes sont incrémentales."
        },
        "collection": {
            "source_url": source_url,
            "limitations": limitations,
        }
    }
    jpath = OUT / f"{stem}.json"
    cpath = OUT / f"{stem}.csv"
    jpath.write_text(json.dumps({"metadata": metadata, "incidents": incidents}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    cols = ["date", "organisation", "territoire", "localisation", "secteur", "type_menace", "acteur", "statut", "score_cyberattaque", "impact_connu", "source_urls", "synthese", "evolution"]
    with cpath.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for inc in incidents:
            row = {k: inc.get(k, "") for k in cols if k != "source_urls"}
            row["source_urls"] = " | ".join(inc.get("sources", []))
            w.writerow(row)


def main():
    cyber, cyber_boundary = scrape_cyberattaque()
    fb, fb_boundary = scrape_frenchbreaches()
    if not cyber:
        raise RuntimeError("Cyberattaque.org backfill returned zero records; refusing to overwrite baseline")
    if not fb:
        raise RuntimeError("FrenchBreaches backfill returned zero records; refusing to overwrite baseline")
    write_dataset(
        "cyberattaque_org_2026", "cyberattaque.org", "https://www.cyberattaque.org/type/attaque/",
        cyber, cyber_boundary,
        "Archive de catégorie paginée ; les champs territoire/secteur/menace sont normalisés automatiquement et les cas ambigus restent Inconnu. Le backfill est basé sur les entrées accessibles de la catégorie Attaque."
    )
    write_dataset(
        "frenchbreaches_2026", "FrenchBreaches", "https://frenchbreaches.com/feed.xml",
        fb, fb_boundary,
        "Le flux RSS est complété par https://frenchbreaches.com/archives pour le rattrapage. FrenchBreaches décrit cette archive comme complète mais non exhaustive ; la corroboration varie selon les alertes."
    )
    print(f"Cyberattaque.org: {len(cyber)} records; reached pre-2026 boundary={cyber_boundary}")
    print(f"FrenchBreaches: {len(fb)} records; reached pre-2026 boundary={fb_boundary}")


if __name__ == "__main__":
    main()
