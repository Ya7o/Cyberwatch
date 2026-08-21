"""Remise à zéro certifiée de l'état métier Cyberwatch.

Cette opération est volontairement radicale : elle archive d'abord l'état actif,
puis supprime datasets, historiques, registres d'identité, caches, baselines et
artefacts publiés. Seuls les référentiels statiques explicitement allowlistés
restent disponibles pour une reconstruction fraîche.

Le module ne fait aucun accès réseau et ne publie rien.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import tarfile
from dataclasses import asdict, dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

PRESERVED_DATA_PATHS = frozenset({
    "sector_auto_policy.json",
    "territorial_identities.csv",
})
PRESERVED_SITE_DATA_PATHS: frozenset[str] = frozenset()


@dataclass(frozen=True)
class PurgeReport:
    root: str
    archived: bool
    archive: str
    removed: tuple[str, ...]
    preserved: tuple[str, ...]
    unexpected_preserved: tuple[str, ...]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _files(base: Path) -> list[Path]:
    if not base.exists():
        return []
    return sorted(path for path in base.rglob("*") if path.is_file())


def inventory(root: Path) -> dict:
    root = root.resolve()
    payload = []
    for area in ("data", "assets/data"):
        base = root / area
        for path in _files(base):
            payload.append({
                "path": str(path.relative_to(root)),
                "size": path.stat().st_size,
                "sha256": _sha256(path),
            })
    payload.sort(key=lambda row: row["path"])
    return {
        "schema": "cyberwatch-zero-reset-inventory-v1",
        "root": str(root),
        "files": payload,
        "count": len(payload),
        "bytes": sum(row["size"] for row in payload),
    }


def archive(root: Path, output: Path) -> dict:
    """Crée une archive avant toute purge et la relit pour certification."""
    root = root.resolve()
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    before = inventory(root)
    with tarfile.open(output, "w:gz") as tar:
        for area in ("data", "assets/data"):
            path = root / area
            if path.exists():
                tar.add(path, arcname=area, recursive=True)
    if not output.exists() or output.stat().st_size == 0:
        raise RuntimeError("archive zero-reset absente ou vide")
    with tarfile.open(output, "r:gz") as tar:
        names = [member.name for member in tar.getmembers() if member.isfile()]
    if before["count"] and not names:
        raise RuntimeError("archive zero-reset illisible ou sans fichiers")
    return {
        "archive": str(output),
        "archive_sha256": _sha256(output),
        "archive_bytes": output.stat().st_size,
        "inventory": before,
        "members": len(names),
    }


def _purge_area(base: Path, preserved: frozenset[str]) -> tuple[list[str], list[str]]:
    removed: list[str] = []
    kept: list[str] = []
    if not base.exists():
        return removed, kept
    for path in _files(base):
        relative = str(path.relative_to(base))
        if relative in preserved:
            kept.append(relative)
            continue
        path.unlink()
        removed.append(relative)
    for directory in sorted((p for p in base.rglob("*") if p.is_dir()), reverse=True):
        try:
            directory.rmdir()
        except OSError:
            pass
    return removed, kept


def purge(root: Path, *, archive_path: Path | None = None) -> PurgeReport:
    """Archive éventuellement puis détruit tout état métier actif."""
    root = root.resolve()
    archive_result = None
    if archive_path is not None:
        archive_result = archive(root, archive_path)

    removed_data, kept_data = _purge_area(root / "data", PRESERVED_DATA_PATHS)
    removed_site, kept_site = _purge_area(root / "assets/data", PRESERVED_SITE_DATA_PATHS)
    preserved = tuple(sorted([f"data/{p}" for p in kept_data] + [f"assets/data/{p}" for p in kept_site]))
    allowed = {f"data/{p}" for p in PRESERVED_DATA_PATHS} | {f"assets/data/{p}" for p in PRESERVED_SITE_DATA_PATHS}
    unexpected = tuple(sorted(set(preserved) - allowed))
    return PurgeReport(
        root=str(root),
        archived=archive_result is not None,
        archive=str(archive_path.resolve()) if archive_path else "",
        removed=tuple(sorted([f"data/{p}" for p in removed_data] + [f"assets/data/{p}" for p in removed_site])),
        preserved=preserved,
        unexpected_preserved=unexpected,
    )


def verify_zero(root: Path) -> dict:
    """Échoue si un état historique a survécu à la purge."""
    root = root.resolve()
    survivors = []
    allowed = {f"data/{p}" for p in PRESERVED_DATA_PATHS} | {f"assets/data/{p}" for p in PRESERVED_SITE_DATA_PATHS}
    for area in ("data", "assets/data"):
        base = root / area
        for path in _files(base):
            relative = str(path.relative_to(root))
            if relative not in allowed:
                survivors.append(relative)
    return {
        "schema": "cyberwatch-zero-state-v1",
        "verdict": "ZERO" if not survivors else "DIRTY",
        "survivors": sorted(survivors),
        "preserved": sorted(allowed),
    }


def _write_or_print(payload: dict, output: str | None) -> None:
    text = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if output:
        Path(output).write_text(text, encoding="utf-8")
    else:
        print(text, end="")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m cyberwatch.zero_reset")
    sub = parser.add_subparsers(dest="command", required=True)

    inv = sub.add_parser("inventory")
    inv.add_argument("--root", default=str(ROOT))
    inv.add_argument("--output")

    arc = sub.add_parser("archive")
    arc.add_argument("--root", default=str(ROOT))
    arc.add_argument("--output", required=True)
    arc.add_argument("--report")

    zero = sub.add_parser("purge")
    zero.add_argument("--root", default=str(ROOT))
    zero.add_argument("--archive")
    zero.add_argument("--output")

    verify = sub.add_parser("verify")
    verify.add_argument("--root", default=str(ROOT))
    verify.add_argument("--output")

    args = parser.parse_args(argv)
    root = Path(args.root)
    if args.command == "inventory":
        _write_or_print(inventory(root), args.output)
        return 0
    if args.command == "archive":
        result = archive(root, Path(args.output))
        _write_or_print(result, args.report)
        return 0
    if args.command == "purge":
        report = purge(root, archive_path=Path(args.archive) if args.archive else None)
        payload = asdict(report)
        _write_or_print(payload, args.output)
        return 2 if report.unexpected_preserved else 0
    payload = verify_zero(root)
    _write_or_print(payload, args.output)
    return 0 if payload["verdict"] == "ZERO" else 2


if __name__ == "__main__":
    raise SystemExit(main())
