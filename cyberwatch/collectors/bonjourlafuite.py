"""Collecteur dédié à BonjourLaFuite — contrat fonctionnel V0.

Cette source ne suit volontairement pas le modèle générique de couverture.
Son statut répond à une seule question : le parseur reconnaît-il encore au
moins un bloc de la timeline ?

Un bloc est reconnu dès qu'une date valide est suivie d'un titre ``h2`` dont
le libellé d'organisation est non vide. La fenêtre ne sert qu'à décider quels
blocs sont transmis au runner pour matérialisation dans ITEMS ; elle ne décide
jamais du statut de la source.
"""

from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urljoin

from .. import status
from ..normalize import clean_organisation, parse_date
from .base import CollectResult, Collector, RawEntry, SourceSpec, Window


class _RecognizedEntries(list):
    """Itère sur les entrées de la fenêtre mais rapporte le total reconnu.

    Le runner historique utilise ``len(result.entries)`` pour ``Items_seen`` et
    itère sur la même collection pour construire ITEMS. Pour BonjourLaFuite,
    ces deux populations sont différentes par définition : ce petit conteneur
    conserve cette compatibilité sans faire entrer d'item hors fenêtre dans la
    base.
    """

    def __init__(self, in_window: list[RawEntry], total_seen: int):
        super().__init__(in_window)
        self.total_seen = total_seen

    def __len__(self) -> int:
        return self.total_seen


class _BonjourHtmlParser(HTMLParser):
    """Parse la structure sémantique stable de la timeline.

    Les organisations sont publiées comme titres ``h2`` sur la page. On évite
    volontairement les classes CSS : la reconnaissance dépend seulement de la
    séquence ``date lisible -> h2 non vide``, ce qui est plus robuste et rend le
    protocole facilement testable.
    """

    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.entries: list[RawEntry] = []
        self.pending_date = ""
        self.current: RawEntry | None = None
        self._in_h2 = False
        self._h2_parts: list[str] = []
        self._anchor_href = ""
        self._anchor_parts: list[str] = []
        #: Texte libre du bloc courant ("Via", "Données concernées", ...),
        #: déjà présent sur la page téléchargée : sert de contexte pour la
        #: qualification (règles déterministes puis, en dernier recours, le
        #: filet de rattrapage LLM), jamais une requête HTTP supplémentaire.
        self._extra_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs):
        lowered = tag.lower()
        if lowered == "h2":
            self._in_h2 = True
            self._h2_parts = []
        elif lowered == "a":
            self._anchor_href = ""
            self._anchor_parts = []
            for key, value in attrs:
                if key.lower() == "href" and value:
                    self._anchor_href = value
                    break

    def handle_endtag(self, tag: str):
        lowered = tag.lower()
        if lowered == "h2":
            self._finish_heading()
        elif lowered == "a":
            self._finish_anchor()

    def handle_data(self, data: str):
        text = " ".join((data or "").replace("\xa0", " ").split())
        if not text:
            return

        if self._in_h2:
            self._h2_parts.append(text)
            return

        in_anchor = bool(self._anchor_href)
        if in_anchor:
            self._anchor_parts.append(text)

        parsed = parse_date(text)
        if parsed:
            self.pending_date = parsed
        elif not in_anchor and self.current is not None:
            # Ni une date, ni le libellé d'un lien : texte libre du bloc en
            # cours ("Via : ...", "Données concernées : ...", etc.).
            self._extra_parts.append(text)

    def _finish_heading(self) -> None:
        raw = " ".join(self._h2_parts).strip()
        self._in_h2 = False
        self._h2_parts = []
        self._flush_extra()

        organisation = clean_organisation(raw)
        if not self.pending_date or not organisation:
            self.current = None
            return

        entry = RawEntry(
            title=organisation,
            organisation=organisation,
            published=self.pending_date,
        )
        self.entries.append(entry)
        self.current = entry
        # Une date ne peut reconnaître qu'un seul bloc.
        self.pending_date = ""

    def _flush_extra(self) -> None:
        """Attache le texte libre accumulé au bloc qui se termine."""
        if self.current is not None and self._extra_parts:
            self.current.summary = " ".join(self._extra_parts).strip()
        self._extra_parts = []

    def finalize(self) -> None:
        """À appeler une fois le flux entièrement parcouru (dernier bloc)."""
        self._flush_extra()

    def _finish_anchor(self) -> None:
        label = " ".join(self._anchor_parts).strip().lower()
        if (
            self.current is not None
            and not self.current.url
            and self._anchor_href
            and label.startswith("source")
        ):
            self.current.url = urljoin(self.base_url, self._anchor_href)
        self._anchor_href = ""
        self._anchor_parts = []


def parse_timeline(html: str, base_url: str) -> list[RawEntry]:
    """Retourne tous les blocs reconnus, sans appliquer de fenêtre temporelle."""
    parser = _BonjourHtmlParser(base_url)
    parser.feed(html or "")
    parser.close()
    parser.finalize()
    return parser.entries


class BonjourLaFuiteCollector(Collector):
    """Implémente strictement la règle OK/FAIL spécifique à BonjourLaFuite."""

    name = "bonjourlafuite"

    def collect(self, client, spec: SourceSpec, window: Window) -> CollectResult:
        budget = client.source_budget()
        result = CollectResult(access_method="bonjourlafuite-html-v0")

        response = client.fetch(spec.start_url, budget)
        result.calls = budget.requests_made

        if not response.ok:
            result.status_override = status.FAIL
            result.reason_code = response.reason_code
            result.comment = (
                f"Lecture impossible: {response.reason_code}"
                + (f" (HTTP {response.status_code})" if response.status_code else "")
            )
            return result

        recognized = parse_timeline(response.text, spec.start_url)
        seen = len(recognized)

        if seen == 0:
            result.status_override = status.FAIL
            result.reason_code = status.REASON_PARSE_ERROR
            result.comment = "Page récupérée mais aucun bloc date + organisation reconnu"
            return result

        in_window = [entry for entry in recognized if window.contains(entry.published)]

        # V0 : statut purement fonctionnel, indépendant de la fenêtre et de la
        # matérialisation finale dans ITEMS. reached_boundary reste donc False.
        result.status_override = status.OK
        result.reason_code = status.REASON_OK
        result.entries = _RecognizedEntries(in_window, seen)
        result.items_seen = seen
        result.items_in_window = len(in_window)
        result.units_done = 1
        result.units_expected = 1
        result.comment = f"items_in_window={len(in_window)}"
        return result
