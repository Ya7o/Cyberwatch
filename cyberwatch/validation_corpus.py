"""Liste blanche immuable pour une reconstruction de validation.

Le corpus ne remplace pas un collecteur : les collecteurs lisent toujours les
sources réelles. Il constitue une frontière d'ingestion appliquée avant toute
qualification, écriture, cache ou requête LLM.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from .model import Incident, Item


def canonical_url(value: str) -> str:
    """Clé stable d'une URL éditoriale, sans fragment ni slash final parasite."""
    parsed = urlsplit((value or "").strip())
    path = parsed.path.rstrip("/") or "/"
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), path, parsed.query, ""))


@dataclass(frozen=True)
class CorpusTarget:
    case_id: str
    source_id: str
    url: str
    published_date: str

    @property
    def key(self) -> tuple[str, str]:
        return self.source_id, canonical_url(self.url)


@dataclass(frozen=True)
class ValidationCorpus:
    name: str
    targets: tuple[CorpusTarget, ...]

    @classmethod
    def load(cls, path: str | Path) -> "ValidationCorpus":
        source = Path(path)
        try:
            payload = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ValueError(f"manifeste de validation illisible : {source}") from exc
        if not isinstance(payload, dict) or not str(payload.get("name") or "").strip():
            raise ValueError("manifeste de validation invalide : name absent")
        targets_raw = payload.get("targets")
        if not isinstance(targets_raw, list) or not targets_raw:
            raise ValueError("manifeste de validation invalide : targets absent")
        targets: list[CorpusTarget] = []
        for row in targets_raw:
            if not isinstance(row, dict):
                raise ValueError("manifeste de validation invalide : cible non objet")
            target = CorpusTarget(
                case_id=str(row.get("case") or "").strip(),
                source_id=str(row.get("source_id") or "").strip(),
                url=str(row.get("url") or "").strip(),
                published_date=str(row.get("published_date") or "").strip(),
            )
            if not all((target.case_id, target.source_id, target.url, target.published_date)):
                raise ValueError("manifeste de validation invalide : cible incomplète")
            targets.append(target)
        keys = [target.key for target in targets]
        if len(keys) != len(set(keys)):
            raise ValueError("manifeste de validation invalide : URL source dupliquée")
        return cls(str(payload["name"]).strip(), tuple(targets))

    @property
    def source_ids(self) -> frozenset[str]:
        return frozenset(target.source_id for target in self.targets)

    @property
    def case_ids(self) -> frozenset[str]:
        return frozenset(target.case_id for target in self.targets)

    def accepts(self, source_id: str, url: str) -> bool:
        return (source_id, canonical_url(url)) in {target.key for target in self.targets}

    def urls_for_source(self, source_id: str) -> tuple[str, ...]:
        return tuple(
            target.url for target in self.targets if target.source_id == source_id
        )

    def audit(self, items: list[Item], incidents: list[Incident]) -> list[str]:
        """Contrat de cardinalité et de rattachement, sans modifier la base."""
        targets_by_key = {target.key: target for target in self.targets}
        actual_by_key = {(item.Source_ID, canonical_url(item.URL)): item for item in items}
        problems: list[str] = []
        unexpected = sorted(set(actual_by_key) - set(targets_by_key))
        missing = sorted(set(targets_by_key) - set(actual_by_key))
        if unexpected:
            problems.append(f"Corpus validation : item hors liste blanche ({len(unexpected)})")
        if missing:
            problems.append(f"Corpus validation : cible source manquante ({len(missing)})")
        for key, target in targets_by_key.items():
            item = actual_by_key.get(key)
            if item and item.Published_Date != target.published_date:
                problems.append(
                    f"Corpus validation : date inattendue {target.source_id} {target.url}"
                )

        targets_by_case: dict[str, set[tuple[str, str]]] = {}
        for target in self.targets:
            targets_by_case.setdefault(target.case_id, set()).add(target.key)
        incident_evidence: list[tuple[set[str], set[str]]] = []
        for incident in incidents:
            urls = [value for value in (incident.Source_URLs or "").split(" | ") if value]
            sources = [value for value in (incident.Sources or "").split(" | ") if value]
            incident_evidence.append((set(sources), {canonical_url(url) for url in urls}))
        if len(incidents) != len(targets_by_case):
            problems.append(
                f"Corpus validation : {len(incidents)} incidents publiés, {len(targets_by_case)} attendus"
            )
        for case_id, expected in sorted(targets_by_case.items()):
            expected_sources = {source for source, _url in expected}
            expected_urls = {url for _source, url in expected}
            matches = [evidence for evidence in incident_evidence if expected_urls <= evidence[1]]
            if len(matches) != 1:
                problems.append(f"Corpus validation : incident {case_id} non dédupliqué correctement")
            elif matches[0] != (expected_sources, expected_urls):
                problems.append(f"Corpus validation : sources inattendues pour {case_id}")
        return problems
