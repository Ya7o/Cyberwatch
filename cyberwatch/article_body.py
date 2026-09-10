"""Isolement du corps de l'article principal, avant toute extraction.

Le contexte capturé par un collecteur n'est pas l'article : il porte aussi la
navigation de la page, ses ressources de bas de page et, chez FrenchBreaches,
un article *connexe* recopié en entier au-dessus du corps réel. L'audit du
10 septembre 2026 en a fait la démonstration : le seul « fuite de données » de
l'article du Tampon vient du pied de page « Ressources utiles », et les deux
contextes Citadium/Printemps contiennent l'intégralité d'un article Shipup qui
parle d'autres victimes, d'une CVE et d'une exploitation de vulnérabilité.

Ce module découpe donc le texte capturé en blocs nommés et ne conserve que ceux
du corps principal. Il ne réécrit rien : un bloc est gardé tel quel ou retiré,
avec son motif. Les sections pédagogiques du corps principal — « Comment une
mairie peut-elle être paralysée ? » — sont **conservées** : elles appartiennent
à l'article. C'est le contrat d'extraction qui refuse d'en faire des faits de
l'incident, pas ce module.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

#: Version de la préparation, tracée à côté des empreintes : une décision
#: archivée reste interprétable après évolution des motifs ci-dessous.
PREPARATION_VERSION = "article-body-2026-09-10.1"

#: Ouverture du bloc « article connexe » recopié par FrenchBreaches au-dessus du
#: corps réel. Le bloc se ferme sur son propre lien de renvoi.
_RELATED_OPEN_RE = re.compile(
    r"^\s*(?:cet article vous est propos[ée] en relation\b"
    r"|à lire (?:aussi|également)\b|a lire (?:aussi|egalement)\b"
    r"|lire (?:aussi|également|egalement)\s*:?\s*$"
    r"|sur le m[êe]me sujet\b|articles? (?:connexes?|similaires?|li[ée]s?)\b"
    r"|voir (?:aussi|également|egalement)\b)",
    re.I,
)
_RELATED_CLOSE_RE = re.compile(r"^\s*lire l['’]alerte li[ée]e\b", re.I)

#: Signature de la ligne d'auteur FrenchBreaches. Elle marque le début du corps
#: rédactionnel : ce qui la précède est le chapô tronqué et, le cas échéant,
#: l'article connexe.
_BYLINE_RE = re.compile(r"^\s*par\s+\S+.{0,80}?,\s*r[ée]dact(?:eur|rice)\b", re.I)

#: Ressources de bas de page : une liste de liens de service, séparés par des
#: « | », qui n'appartient à aucun incident. C'est elle qui affirmait « fuite de
#: données » sur l'article du Tampon, lequel écarte explicitement cette menace.
_FOOTER_OPEN_RE = re.compile(
    r"^\s*(?:ressources utiles\s*:?\s*$"
    r"|partager\s*:?\s*$|nos derni[èe]res? (?:alertes?|actualit[ée]s?)\b"
    r"|sur le m[êe]me th[èe]me\s*:?\s*$"
    r"|newsletter\s*:?\s*$|abonnez-vous\b|suivez-nous\b"
    r"|mentions l[ée]gales\b|politique de confidentialit[ée]\b)",
    re.I,
)

#: Codes de retrait, stables et lisibles dans les journaux de qualification.
RELATED_ARTICLE = "RELATED_ARTICLE"
FOOTER_RESOURCES = "FOOTER_RESOURCES"


def _hash(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class PreparedContext:
    """Contexte capturé et contexte réellement préparé, côte à côte.

    Les deux textes sont conservés séparément avec leurs empreintes et tailles :
    un audit doit pouvoir distinguer « la collecte n'a pas vu la phrase » de
    « la préparation l'a retirée ».
    """

    captured: str
    prepared: str
    removed: tuple[tuple[str, str], ...] = ()
    truncated: bool = False
    version: str = PREPARATION_VERSION
    _hashes: dict = field(default_factory=dict, repr=False, compare=False)

    @property
    def captured_hash(self) -> str:
        return _hash(self.captured)

    @property
    def prepared_hash(self) -> str:
        return _hash(self.prepared)

    @property
    def captured_chars(self) -> int:
        return len(self.captured)

    @property
    def prepared_chars(self) -> int:
        return len(self.prepared)

    @property
    def removed_codes(self) -> tuple[str, ...]:
        return tuple(sorted({code for code, _ in self.removed}))

    def metadata(self) -> dict:
        """Empreintes et tailles, telles qu'archivées dans les journaux du run.

        Le texte n'y figure pas : il est stocké une seule fois par empreinte.
        """
        return {
            "version": self.version,
            "captured_hash": self.captured_hash,
            "captured_chars": self.captured_chars,
            "prepared_hash": self.prepared_hash,
            "prepared_chars": self.prepared_chars,
            "truncated": self.truncated,
            "removed": [{"code": code, "marker": marker} for code, marker in self.removed],
        }


def _lines(text: str) -> list[str]:
    return (text or "").split("\n")


def _isolate(text: str) -> tuple[str, list[tuple[str, str]]]:
    """Retire les blocs hors corps principal et rend leurs motifs de retrait."""
    lines = _lines(text)
    removed: list[tuple[str, str]] = []
    keep = [True] * len(lines)

    index = 0
    while index < len(lines):
        line = lines[index]
        if _FOOTER_OPEN_RE.match(line):
            removed.append((FOOTER_RESOURCES, line.strip()))
            for position in range(index, len(lines)):
                keep[position] = False
            break
        if _RELATED_OPEN_RE.match(line):
            marker = line.strip()
            end = index
            for position in range(index + 1, len(lines)):
                if _RELATED_CLOSE_RE.match(lines[position]) or _BYLINE_RE.match(lines[position]):
                    # La ligne de fermeture appartient au bloc connexe ; une
                    # ligne d'auteur, elle, ouvre le corps réel et doit rester.
                    end = position if _RELATED_CLOSE_RE.match(lines[position]) else position - 1
                    break
            else:
                end = len(lines) - 1
            removed.append((RELATED_ARTICLE, marker))
            for position in range(index, end + 1):
                keep[position] = False
            index = end + 1
            continue
        index += 1

    kept = "\n".join(line for line, flag in zip(lines, keep) if flag)
    return kept.strip("\n"), removed


def prepare(*texts: str) -> PreparedContext:
    """Prépare le contexte d'un article à partir de ses fragments capturés."""
    captured = "\n\n".join(part.strip() for part in texts if (part or "").strip())
    prepared, removed = _isolate(captured)
    # Un retrait ne doit jamais vider l'article : si les motifs emportent tout,
    # c'est la structure de la page qui a changé, pas l'article qui est absent.
    if not prepared.strip():
        return PreparedContext(captured=captured, prepared=captured, removed=())
    return PreparedContext(captured=captured, prepared=prepared, removed=tuple(removed))


def prepare_entry(entry) -> PreparedContext:
    """Prépare le contexte d'un ``RawEntry`` — titre, résumé puis contenu."""
    return prepare(
        getattr(entry, "title", "") or "",
        getattr(entry, "summary", "") or "",
        getattr(entry, "content", "") or "",
    )


def body(*texts: str) -> str:
    """Corps principal seul — raccourci des appelants qui n'auditent rien."""
    return prepare(*texts).prepared
