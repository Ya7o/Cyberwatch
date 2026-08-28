#!/usr/bin/env python3
import re
import time
from datetime import datetime
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

import backfill_global_sources as base


def from_post(d, title, excerpt, link):
    org = base.clean_org_from_title(title)
    text = f"{title} {excerpt}"
    threat = base.infer_threat(text)
    sector = base.infer_sector(org, text)
    territory = base.infer_territory(org, text)
    actor = base.infer_actor(text)
    status, score = base.infer_status_score(text)
    return base.make_incident(
        d, org, territory, sector, threat, actor, status, score,
        excerpt or title, link,
        f"Rattrapage 2026 Cyberattaque.org — {title}"
    )


def scrape_cyberattaque_rest():
    root = "https://www.cyberattaque.org"
    cats = base.get(root + "/wp-json/wp/v2/categories?slug=attaque")
    if cats is None:
        return [], False
    try:
        category_list = cats.json()
    except Exception:
        return [], False
    if not category_list:
        return [], False
    cat_id = category_list[0]["id"]
    out, seen = [], set()
    page = 1
    reached_boundary = False
    while page <= 50:
        params = {
            "categories": cat_id,
            "after": "2026-01-01T00:00:00",
            "before": "2027-01-01T00:00:00",
            "per_page": 100,
            "page": page,
            "orderby": "date",
            "order": "desc",
            "_fields": "date,link,title,excerpt",
        }
        try:
            r = base.S.get(root + "/wp-json/wp/v2/posts", params=params, timeout=30)
        except Exception:
            break
        if r.status_code == 400 and "rest_post_invalid_page_number" in r.text:
            reached_boundary = True
            break
        if r.status_code >= 400:
            break
        try:
            posts = r.json()
        except Exception:
            break
        if not posts:
            reached_boundary = True
            break
        for p in posts:
            try:
                d = datetime.fromisoformat(p["date"]).date()
            except Exception:
                continue
            if d.year != base.YEAR:
                continue
            title = BeautifulSoup(p.get("title", {}).get("rendered", ""), "html.parser").get_text(" ", strip=True)
            excerpt = BeautifulSoup(p.get("excerpt", {}).get("rendered", ""), "html.parser").get_text(" ", strip=True)
            link = p.get("link", "")
            if not title or not link or link in seen:
                continue
            seen.add(link)
            out.append(from_post(d, title, excerpt, link))
        total_pages = int(r.headers.get("X-WP-TotalPages", page))
        if page >= total_pages:
            reached_boundary = True
            break
        page += 1
        time.sleep(0.15)
    return out, reached_boundary


def scrape_cyberattaque_html():
    root = "https://www.cyberattaque.org"
    base_url = root + "/type/attaque/"
    out, seen = [], set()
    date_rx = re.compile(r"\b\d{1,2}\s+(?:janvier|février|fevrier|mars|avril|mai|juin|juillet|août|aout|septembre|octobre|novembre|décembre|decembre)\s+20\d{2}\b", re.I)
    reached_boundary = False
    for page in range(1, 60):
        url = base_url if page == 1 else f"{base_url}page/{page}/"
        r = base.get(url)
        if r is None:
            reached_boundary = True
            break
        soup = BeautifulSoup(r.text, "html.parser")
        nodes = soup.find_all(string=date_rx)
        page_dates = []
        for node in nodes:
            d = base.parse_date(str(node))
            if not d:
                continue
            page_dates.append(d)
            if d.year != base.YEAR:
                continue
            a = node.parent.find_next("a", href=True)
            while a:
                href = urljoin(url, a.get("href", ""))
                txt = " ".join(a.get_text(" ", strip=True).split())
                if (txt and urlparse(href).netloc.endswith("cyberattaque.org")
                        and "/type/" not in href and href.rstrip("/") != root):
                    break
                a = a.find_next("a", href=True)
            if not a:
                continue
            link = urljoin(url, a["href"])
            if link in seen:
                continue
            title = " ".join(a.get_text(" ", strip=True).split())
            # Avoid nav/footer links accidentally selected after a date node.
            if len(title) < 8:
                continue
            container = a.find_parent("article") or a.parent
            excerpt = " ".join(container.get_text(" ", strip=True).split()) if container else title
            seen.add(link)
            out.append(from_post(d, title, excerpt, link))
        if page_dates and min(page_dates).year < base.YEAR:
            reached_boundary = True
            break
        if not page_dates and page > 3:
            break
        time.sleep(0.2)
    return out, reached_boundary


def scrape_cyberattaque():
    rows, boundary = scrape_cyberattaque_rest()
    if rows:
        rows.sort(key=lambda x: (x["date"], x["organisation"], x["sources"][0]), reverse=True)
        return rows, boundary
    rows, boundary = scrape_cyberattaque_html()
    rows.sort(key=lambda x: (x["date"], x["organisation"], x["sources"][0]), reverse=True)
    return rows, boundary


def main():
    cyber, cyber_boundary = scrape_cyberattaque()
    fb, fb_boundary = base.scrape_frenchbreaches()
    if not cyber:
        raise RuntimeError("Cyberattaque.org backfill returned zero records after REST and HTML fallbacks")
    if not fb:
        raise RuntimeError("FrenchBreaches backfill returned zero records")
    base.write_dataset(
        "cyberattaque_org_2026", "cyberattaque.org", "https://www.cyberattaque.org/type/attaque/",
        cyber, cyber_boundary,
        "Rattrapage de la catégorie Attaque via API WordPress quand disponible, avec fallback HTML paginé. Les champs normalisés ambigus restent Inconnu."
    )
    base.write_dataset(
        "frenchbreaches_2026", "FrenchBreaches", "https://frenchbreaches.com/feed.xml",
        fb, fb_boundary,
        "Le RSS est complété par https://frenchbreaches.com/archives pour le rattrapage. FrenchBreaches qualifie son historique de complet mais non exhaustif ; la corroboration varie selon les alertes."
    )
    print(f"Cyberattaque.org: {len(cyber)} records; boundary={cyber_boundary}")
    print(f"FrenchBreaches: {len(fb)} records; boundary={fb_boundary}")


if __name__ == "__main__":
    main()
