"""Preuve Secteur depuis la page officielle, quand le nom EST un domaine.

Déclencheur volontairement étroit : uniquement les organisations dont le nom
collecté est lui-même une forme de domaine (``Klark.ai``, ``iMapper.tech``,
``Lebonmateriel.fr``). Dans ce cas seulement, le site officiel n'a pas à être
deviné ni cherché — il est déjà nommé par la source. C'est ce qui distingue ce
canal du balayage général déjà mesuré le 2026-08-23
(``audit/SECTOR_QUALIFICATION_AUDIT.md`` : 60 organisations testées via
``scripts/enrich_sector_queue.py``, 0 correspondance) : là, il fallait
découvrir un site plausible pour des noms quelconques ; ici, il n'y a rien à
découvrir.

Comme :mod:`cyberwatch.organisation_sector_llm`, ce module est un worker : il
fait les accès réseau et persiste un cache, que
:mod:`cyberwatch.organisation_sector` relit ensuite hors-ligne. Ce dernier ne
déclenche jamais d'appel réseau lui-même. La preuve produite reste faible
(``MEDIUM``, hors ``STRONG_EVIDENCE_TYPES``) : elle ne confirme jamais seule
un secteur, elle entre dans l'arbitrage comme les autres.

Le texte retenu (titre + meta description de la page) est classé par
``context_sector.classify_explicit_activity``, le classificateur strict déjà
utilisé pour ``Activity_Description`` — aucun vocabulaire de classification
n'est réinventé ici.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from . import (
    company_evidence,
    config,
    context_sector,
    official_site_discovery,
    organisation_sector as osec,
    store,
)
from .model import Item

CACHE_CSV = osec.DOMAIN_PAGE_CACHE_CSV
#: Audit 2026-08-26 : ``Sector`` renommé ``Activity_Sector_Match`` et
#: ``Activity_Description`` ajouté, pour le même contrat à 2 champs que
#: source_facts_ai.py (activité déclarée puis rapprochement taxonomie),
#: plutôt qu'un blob brut titre/description. Aucune ligne de production
#: n'existait avant ce changement (ce cache n'a jamais tourné en conditions
#: réelles) : pas de migration nécessaire. ``Extraction_Source`` distingue
#: une classification gratuite (``deterministic``) d'un fallback payant
#: (``llm``) ou d'une abstention LLM (``llm_declined``, jamais redemandée
#: sans ``--force-llm``, cf. domain_page_sector_llm.py), pour l'audit de coût
#: comme pour éviter de rejouer indéfiniment une question sans réponse.
CACHE_COLUMNS = [
    "Organisation_Key", "Organisation", "URL", "Status",
    "Activity_Description", "Activity_Sector_Match", "Extraction_Source",
    "Page_Title", "Page_Description", "Fetched_At",
]

STATUS_MATCHED = "MATCHED"
STATUS_NO_EVIDENCE = "NO_EVIDENCE"
STATUS_UNREACHABLE = "UNREACHABLE"

FETCH_TIMEOUT_SECONDS = 8
#: Bornes de lecture : une page officielle annonce son activité en haut de
#: page. Inutile d'ingérer un site entier pour en extraire deux balises.
MAX_HTML_CHARS = 200_000
MAX_TEXT_CHARS = 400

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
#: La citation fermante doit être la même que l'ouvrante (backréférence) :
#: une description française contient presque toujours une apostrophe
#: ("plateforme d'intelligence artificielle"), qui tronquerait le texte si
#: n'importe quel guillemet fermait la capture.
_META_DESCRIPTION_RE = re.compile(
    r"""<meta[^>]+?name\s*=\s*["']description["'][^>]*?content\s*=\s*(["'])(.*?)\1""",
    re.IGNORECASE | re.DOTALL,
)
_META_DESCRIPTION_REVERSED_RE = re.compile(
    r"""<meta[^>]+?content\s*=\s*(["'])(.*?)\1[^>]*?name\s*=\s*["']description["']""",
    re.IGNORECASE | re.DOTALL,
)
_TAG_RE = re.compile(r"<[^>]+>")
_WHITESPACE_RE = re.compile(r"\s+")


def _clean(value: str) -> str:
    text = _TAG_RE.sub(" ", str(value or ""))
    text = (
        text.replace("&amp;", "&").replace("&#39;", "'").replace("&rsquo;", "'")
        .replace("&quot;", '"').replace("&nbsp;", " ").replace("&eacute;", "é")
        .replace("&egrave;", "è").replace("&agrave;", "à")
    )
    return _WHITESPACE_RE.sub(" ", text).strip()[:MAX_TEXT_CHARS]


def organisation_is_domain(organisation: str) -> str:
    """Retourne le domaine si le nom EST déjà un domaine, sinon "".

    Réutilise strictement le même motif que
    ``official_site_discovery._direct_domain_guesses`` : ce canal ne doit pas
    reconnaître un nom que la découverte de site officiel ne reconnaîtrait
    pas.
    """
    raw = str(organisation or "").strip().casefold().rstrip(".")
    if re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+", raw):
        return raw
    return ""


def extract_page_activity(html: str) -> tuple[str, str]:
    """Titre et meta description, nettoyés. Aucune autre partie de la page.

    Le corps d'une page commerciale est un argumentaire, pas une description
    d'activité : l'y chercher produirait exactement le bruit que
    ``classify_explicit_activity`` est fait pour refuser.
    """
    text = str(html or "")[:MAX_HTML_CHARS]
    title = _TITLE_RE.search(text)
    description = _META_DESCRIPTION_RE.search(text) or _META_DESCRIPTION_REVERSED_RE.search(text)
    return (
        _clean(title.group(1)) if title else "",
        _clean(description.group(2)) if description else "",
    )


def _empty_row(base: dict, status: str) -> dict:
    return {
        **base, "Status": status,
        "Activity_Description": "", "Activity_Sector_Match": "", "Extraction_Source": "",
        "Page_Title": "", "Page_Description": "",
    }


def resolve_domain_page(organisation: str) -> dict | None:
    """Un accès réseau borné, jamais bloquant. ``None`` = non applicable."""
    domain = organisation_is_domain(organisation)
    if not domain:
        return None

    url = f"https://{domain}/"
    fetched_at = datetime.now(timezone.utc).isoformat()
    base = {"Organisation": organisation, "URL": url, "Fetched_At": fetched_at}

    # Garde d'identité : la page doit appartenir à l'organisation nommée.
    if not official_site_discovery.domain_matches_organisation(organisation, url):
        return _empty_row(base, STATUS_NO_EVIDENCE)

    response = company_evidence._http_get(url, timeout=FETCH_TIMEOUT_SECONDS)
    if response is None:
        return _empty_row(base, STATUS_UNREACHABLE)

    # Audit 2026-08-26 : _http_get suit les redirections (allow_redirects=True)
    # sans jamais revalider l'identité sur l'URL finale. Un domaine qui
    # redirige vers un site sans rapport serait sinon accepté à tort. Un mock
    # de test sans attribut/valeur `.url` retombe sur `url` (pas de vérité
    # différente disponible) : comportement inchangé pour ces tests, jamais
    # pour un vrai `requests.Response` (`.url` y est toujours renseigné).
    final_url = getattr(response, "url", "") or url
    base["URL"] = final_url
    if final_url != url and not official_site_discovery.domain_matches_organisation(organisation, final_url):
        return _empty_row(base, STATUS_NO_EVIDENCE)

    title, description = extract_page_activity(response.text)
    sector = config.SECTOR_UNKNOWN
    activity_text = ""
    for text in (description, title):
        if not text:
            continue
        candidate = context_sector.classify_explicit_activity(text)
        if candidate != config.SECTOR_UNKNOWN:
            sector = candidate
            activity_text = text
            break

    return {
        **base,
        "Status": STATUS_MATCHED if sector != config.SECTOR_UNKNOWN else STATUS_NO_EVIDENCE,
        # Jamais d'activité publiée sans secteur classé : même discipline
        # anti-hallucination que source_facts_ai.py (une preuve, c'est un
        # secteur nommé, jamais un texte non classé).
        "Activity_Description": activity_text if sector != config.SECTOR_UNKNOWN else "",
        "Activity_Sector_Match": sector if sector != config.SECTOR_UNKNOWN else "",
        "Extraction_Source": "deterministic" if sector != config.SECTOR_UNKNOWN else "",
        "Page_Title": title,
        "Page_Description": description,
    }


def select_organisations(items: list[Item]) -> list[tuple[str, str]]:
    """Organisations encore Inconnu dont le nom est déjà un domaine.

    Déterministe et dédupliqué par ``Organisation_Key`` : une organisation
    n'est testée qu'une fois, quel que soit son nombre d'items.
    """
    selected: dict[str, str] = {}
    for item in items:
        if item.Sector != config.SECTOR_UNKNOWN:
            continue
        if not item.Organisation_Key or item.Organisation_Key in selected:
            continue
        if organisation_is_domain(item.Organisation_Raw):
            selected[item.Organisation_Key] = item.Organisation_Raw
    return sorted(selected.items())


def load_cache(path=None) -> list[dict]:
    return store.read_csv(path or (store.ITEMS_CSV.parent / CACHE_CSV.name))


def save_cache(rows: list[dict], path=None) -> None:
    ordered = sorted(rows, key=lambda row: row.get("Organisation_Key", ""))
    store.write_csv(path or (store.ITEMS_CSV.parent / CACHE_CSV.name), CACHE_COLUMNS, ordered)


def enrich_domain_pages(
    items: list[Item],
    *,
    cache_rows: list[dict] | None = None,
    allow_network: bool = True,
    limit: int = 20,
) -> list[dict]:
    """Collecte les pages de domaines applicables sans décider ``Sector``.

    Cette fonction ne persiste rien : le runner inclut ses lignes dans la
    transaction finale du snapshot. En mode hors ligne, elle se contente du
    cache fourni.
    """
    by_key = {
        row.get("Organisation_Key", ""): dict(row)
        for row in (cache_rows if cache_rows is not None else load_cache())
        if row.get("Organisation_Key")
    }
    if not allow_network:
        return sorted(by_key.values(), key=lambda row: row.get("Organisation_Key", ""))
    candidates = [
        pair for pair in select_organisations(items)
        if pair[0] not in by_key
    ]
    if limit > 0:
        candidates = candidates[:limit]
    for key, organisation in candidates:
        row = resolve_domain_page(organisation)
        if row is None:
            continue
        row["Organisation_Key"] = key
        by_key[key] = row
    return sorted(by_key.values(), key=lambda row: row.get("Organisation_Key", ""))
