"""Verdict de qualification d'un run : ce qui a été traité, ce qui reste bloqué.

L'audit du 10 septembre 2026 a relevé qu'un run pouvait être marqué `OK` et
`Published=true` alors que l'extraction et la déduplication LLM étaient
désactivées : rien, dans le verdict, ne distinguait « aucun traitement
nécessaire » de « traitements nécessaires non exécutés ». Ce module lit les
journaux déjà écrits par run et rend cette distinction explicite.

Il ne collecte rien, n'appelle aucun modèle et ne modifie aucune donnée : il
relit `data/llm_runs/<RUN_ID>/`, la file de reprise d'extraction et la file de
revue de déduplication, puis rend un état, ses motifs et ses décomptes.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from . import store
from .sector_activity import ACTIVITY_FIELDS

#: Tous les traitements nécessaires de ce run sont terminés.
STATE_COMPLETE = "COMPLETE"
#: Des traitements nécessaires restent bloqués — clé absente, budget, panne,
#: capacité de batch. La publication continue, mais elle est incomplète.
STATE_PARTIAL = "PARTIAL"
#: Aucun traitement n'était nécessaire : ni champ manquant, ni paire candidate.
STATE_NOT_NEEDED = "NOT_NEEDED"
#: Run trop ancien pour être jugé : ses journaux n'existent pas ou ne portent
#: pas l'information. Ce n'est pas un échec, c'est une absence de preuve.
STATE_UNKNOWN = "UNKNOWN"

#: Message affiché dans le dashboard et les rapports de production.
INCOMPLETE_LABEL = "Qualification incomplète"

#: Statuts de paire qui constatent un traitement nécessaire non abouti. Une
#: paire `DIFFERENT` ou `APPLIED` est traitée ; `UNKNOWN` l'est aussi : le
#: modèle a répondu qu'il ne pouvait pas trancher, ce qui est une décision.
_BLOCKING_PAIR_STATUSES = frozenset({
    "DISABLED",
    "ERROR",
    "RETRY_EXHAUSTED",
    "BUDGET_BLOCKED",
    "NOT_REVIEWED_CAPACITY",
    "NOT_REVIEWED_PAIR_TOO_LARGE",
})


def runs_dir(root: Path | None = None) -> Path:
    return (root or store.DATA_DIR) / "llm_runs"


def _read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None


def known_run_ids(root: Path | None = None) -> list[str]:
    """Runs disposant d'un journal LLM, du plus ancien au plus récent."""
    directory = runs_dir(root)
    if not directory.is_dir():
        return []
    return sorted(child.name for child in directory.iterdir() if child.is_dir())


def latest_run_id(root: Path | None = None) -> str:
    """Dernier run journalisé, ou à défaut le dernier run du journal de runs."""
    known = known_run_ids(root)
    if known:
        return known[-1]
    rows = store.load_run_log()
    return str(rows[-1].get("Run_ID", "")) if rows else ""


@dataclass(frozen=True)
class QualificationRun:
    """Journaux d'un run, relus tels qu'ils ont été écrits."""

    run_id: str
    extraction: dict = field(default_factory=dict)
    trace: list = field(default_factory=list)
    contexts: dict = field(default_factory=dict)
    dedup: dict = field(default_factory=dict)
    deferred: list = field(default_factory=list)
    pending_pairs: list = field(default_factory=list)
    documented: bool = False
    #: Provenance de `deferred` : "archive" (figée à la fin de ce run),
    #: "live" (file courante, ne décrit que le dernier run) ou "" (inconnue).
    #: Le défaut vide préserve le chemin des runs construits à la main.
    deferred_source: str = ""

    @property
    def pairs(self) -> list[dict]:
        rows = self.dedup.get("pairs")
        return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []

    @property
    def dedup_summary(self) -> dict:
        summary = self.dedup.get("summary")
        return summary if isinstance(summary, dict) else {}


def load_run(run_id: str = "", root: Path | None = None) -> QualificationRun:
    """Relit les journaux d'un run ; `run_id` vide désigne le dernier."""
    run_id = run_id or latest_run_id(root)
    directory = runs_dir(root) / run_id if run_id else None
    extraction = _read_json(directory / "source_facts_ai_usage.json") if directory else None
    trace = _read_json(directory / "source_facts_ai_trace.json") if directory else None
    contexts = _read_json(directory / "source_facts_ai_contexts.json") if directory else None
    dedup = _read_json(directory / "dedup_review.json") if directory else None
    archived = _read_json(directory / "source_facts_retry_queue.json") if directory else None
    archived = archived.get("entries") if isinstance(archived, dict) else None
    if isinstance(archived, list):
        deferred = [row for row in archived if isinstance(row, dict)]
        deferred_source = "archive"
    elif run_id and run_id == latest_run_id(root):
        deferred = [row for row in _deferred_entries() if isinstance(row, dict)]
        deferred_source = "live"
    else:
        # La file est globale et sans identifiant de run : la prêter à un run
        # ancien lui ferait décrire un état qui n'est pas le sien.
        deferred, deferred_source = [], ""
    pending = _read_json(store.DATA_DIR / "dedup_review_queue.json")
    return QualificationRun(
        run_id=run_id,
        extraction=extraction if isinstance(extraction, dict) else {},
        trace=trace if isinstance(trace, list) else [],
        contexts=contexts if isinstance(contexts, dict) else {},
        dedup=dedup if isinstance(dedup, dict) else {},
        deferred=deferred,
        pending_pairs=[row for row in pending if isinstance(row, dict)] if isinstance(pending, list) else [],
        documented=isinstance(extraction, dict) or isinstance(dedup, dict),
        deferred_source=deferred_source,
    )


def run_from_snapshot(payload: dict) -> QualificationRun:
    """Reconstruit un run à partir d'un instantané figé par un audit.

    Les audits archivent les mêmes journaux sous un seul fichier. Les relire par
    ce chemin évite de rejouer une collecte pour rendre le tableau d'un run
    passé — et garantit que le rapport porte bien sur l'état audité.
    """
    run = payload.get("run")
    row = run[0] if isinstance(run, list) and run else {}
    dedup = payload.get("dedup")
    return QualificationRun(
        run_id=str(row.get("Run_ID") or payload.get("snapshot", {}).get("Run_ID") or ""),
        extraction=payload.get("extraction_usage") or {},
        trace=payload.get("extraction_trace") or [],
        dedup=dedup if isinstance(dedup, dict) else {},
        deferred=_snapshot_deferred(payload.get("deferred_entries")),
        documented=True,
        # Un audit sans file figée ne sait pas ce qui restait en attente : le
        # dire, plutôt que d'annoncer zéro.
        deferred_source="archive" if payload.get("deferred_entries") is not None else "",
    )


def _snapshot_deferred(payload) -> list[dict]:
    """File figée par un audit, écrite tantôt à plat, tantôt sous `entries`."""
    rows = payload.get("entries") if isinstance(payload, dict) else payload
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def _deferred_entries() -> list[dict]:
    from . import source_facts_retry

    return source_facts_retry.load()


def _pending_field_count(run: QualificationRun) -> tuple[int, bool]:
    """Champs restés sans réponse dans CE run, et si l'on peut le savoir.

    L'archive de fin de run fait autorité : elle a été figée pour ce run. La
    trace le dit ensuite. La file courante, globale et sans identifiant de run,
    ne peut décrire que le dernier run. Au-delà, l'information est perdue et se
    dit « non disponible » plutôt que zéro.
    """
    if run.deferred_source == "archive":
        return sum(len(row.get("pending_fields") or ()) for row in run.deferred), True
    if run.trace:
        return sum(
            len(event.get("requested_fields") or ())
            for event in run.trace
            if isinstance(event, dict)
            and event.get("status") in {"disabled", "budget_blocked", "failed"}
        ), True
    if run.deferred_source == "live":
        return sum(len(row.get("pending_fields") or ()) for row in run.deferred), True
    return 0, False


def _pair_counts(run: QualificationRun) -> dict | None:
    """Décompte des couples activité/secteur ; None quand le run l'ignore."""
    counts = run.extraction.get("activity_pairs")
    if isinstance(counts, dict) and counts:
        return counts
    return _pair_counts_from_trace(run)


def _pair_counts_from_trace(run: QualificationRun) -> dict | None:
    """Reconstruction depuis la trace, un couple par (observation, contenu)."""
    outcomes: dict[tuple[str, str], tuple[str, str]] = {}
    for event in run.trace:
        if not isinstance(event, dict):
            continue
        requested = set(event.get("requested_fields") or ())
        if not ACTIVITY_FIELDS & requested:
            continue
        status = str(event.get("status") or "")
        cached = event.get("fields") if isinstance(event.get("fields"), dict) else None
        if status in {"disabled", "budget_blocked", "failed"}:
            outcome = "technical_failure"
        elif cached:
            # Une relecture de cache porte les statuts eux-mêmes : les lire
            # évite de compter un rejet mémorisé comme une abstention.
            from .source_facts_ai_activity import pair_outcome
            outcome = pair_outcome(cached)
        else:
            normalized = event.get("normalized") if isinstance(event.get("normalized"), dict) else {}
            rejections = event.get("rejections") if isinstance(event.get("rejections"), dict) else {}
            if ACTIVITY_FIELDS <= set(normalized):
                outcome = "accepted"
            elif ACTIVITY_FIELDS & set(rejections):
                outcome = "rejected"
            else:
                outcome = "abstained"
        key = (str(event.get("item_id") or ""), str(event.get("content_hash") or ""))
        outcomes[key] = (outcome, "cache" if status == "cache_read" else
                         "call" if status == "success" else "none")
    if not outcomes:
        return None
    counts: dict = {"requested": len(outcomes)}
    for outcome, origin in outcomes.values():
        bucket = counts.setdefault(outcome, {"total": 0, "from_cache": 0, "from_call": 0})
        bucket["total"] += 1
        if origin == "cache":
            bucket["from_cache"] += 1
        elif origin == "call":
            bucket["from_call"] += 1
    return counts


def _pair_total(counts: dict | None, outcome: str) -> int:
    bucket = (counts or {}).get(outcome)
    return int(bucket.get("total") or 0) if isinstance(bucket, dict) else 0


def _blocked_pairs(run: QualificationRun) -> list[dict]:
    blocked = [row for row in run.pairs if row.get("status") in _BLOCKING_PAIR_STATUSES]
    if blocked:
        return blocked
    # Un run sans journal de paires peut malgré tout laisser une file de revue :
    # elle constate le même besoin non satisfait.
    return [row for row in run.pending_pairs if row.get("status") in _BLOCKING_PAIR_STATUSES]


def evaluate(run: QualificationRun) -> dict:
    """État, motifs et décomptes de la qualification de ce run."""
    reasons: list[str] = []
    pending_fields, pending_known = _pending_field_count(run)
    blocked_pairs = _blocked_pairs(run)

    if not run.run_id or not run.documented:
        return {
            "run_id": run.run_id,
            "state": STATE_UNKNOWN,
            "reasons": ["run non documenté : aucun journal de qualification"],
            "pending_fields": pending_fields,
            "pending_fields_available": pending_known,
            "pending_pairs": len(blocked_pairs),
            "extraction": _extraction_counts(run),
            "dedup": _dedup_counts(run),
        }

    extraction = _extraction_counts(run)
    dedup = _dedup_counts(run)

    if pending_fields:
        reasons.append(f"{pending_fields} champ(s) d'extraction différé(s)")
    if extraction["disabled_events"]:
        reasons.append(
            f"{extraction['disabled_events']} passage(s) d'extraction désactivé(s)"
            + (f" ({extraction['disabled_reason']})" if extraction["disabled_reason"] else "")
        )
    if extraction["budget_blocked"]:
        reasons.append(f"{extraction['budget_blocked']} appel(s) d'extraction bloqué(s) par le budget")
    if extraction["needed"] and not extraction["calls"] and extraction["disabled_reason"]:
        # Des champs manquaient, aucun appel n'a eu lieu : c'est le cas exact du
        # run audité, marqué `OK` alors que l'extraction était désactivée.
        reasons.append(
            f"{extraction['needed']} article(s) à extraire sans appel exécuté "
            f"({extraction['disabled_reason']})"
        )
    if blocked_pairs:
        statuses = sorted({str(row.get("status") or "") for row in blocked_pairs})
        reasons.append(f"{len(blocked_pairs)} paire(s) non tranchée(s) : {', '.join(statuses)}")

    # Un couple activité/secteur refusé mais encore à traiter est un besoin non
    # satisfait, y compris quand tous les appels du run ont réussi. Une
    # abstention explicite, elle, n'entre dans aucune de ces conditions.
    pairs = extraction["pairs"]
    if _pair_total(pairs, "rejected"):
        reasons.append(
            f"{_pair_total(pairs, 'rejected')} couple(s) activité/secteur "
            "rejeté(s) en attente de reprise"
        )
    if _pair_total(pairs, "rejected_exhausted"):
        reasons.append(
            f"{_pair_total(pairs, 'rejected_exhausted')} couple(s) activité/secteur "
            "en rejet persistant (tentatives épuisées)"
        )
    if _pair_total(pairs, "technical_failure"):
        reasons.append(
            f"{_pair_total(pairs, 'technical_failure')} couple(s) activité/secteur "
            "en échec technique"
        )

    if reasons:
        state = STATE_PARTIAL
    elif extraction["needed"] or dedup["candidates_generated"]:
        state = STATE_COMPLETE
    else:
        # Aucune extraction à faire et aucune paire candidate : une clé absente
        # ne constitue pas un échec quand le cache couvrait tous les besoins.
        state = STATE_NOT_NEEDED

    return {
        "run_id": run.run_id,
        "state": state,
        "reasons": reasons,
        "pending_fields": pending_fields,
        "pending_fields_available": pending_known,
        "pending_pairs": len(blocked_pairs),
        "extraction": extraction,
        "dedup": dedup,
    }


def _extraction_counts(run: QualificationRun) -> dict:
    stats = run.extraction
    events = [row for row in run.trace if isinstance(row, dict)]
    return {
        "items_eligible": int(stats.get("items_eligible") or 0),
        "needed": int(stats.get("items_would_call") or 0),
        "calls": int(stats.get("calls_attempted") or 0),
        "accepted_from_cache": int(stats.get("accepted_field_cache_hits") or 0),
        "abstained_from_cache": int(stats.get("abstained_field_cache_hits") or 0),
        "fields_invalidated": int(stats.get("fields_invalidated") or 0),
        "rejected_from_cache": int(stats.get("rejected_field_cache_hits") or 0),
        "pairs": _pair_counts(run),
        "cache_read_events": sum(row.get("status") == "cache_read" for row in events),
        "disabled_events": sum(row.get("status") == "disabled" for row in events),
        "budget_blocked": sum(row.get("status") == "budget_blocked" for row in events),
        "disabled_reason": str(stats.get("disabled_reason") or ""),
        "requested_model": str(stats.get("requested_model") or stats.get("model") or ""),
        # Aucun appel, aucun modèle exécuté : le champ reste vide plutôt que de
        # recopier le modèle demandé.
        "effective_model": str(stats.get("effective_model") or ""),
    }


def _dedup_counts(run: QualificationRun) -> dict:
    summary = run.dedup_summary
    return {
        "candidates_generated": int(summary.get("dedup_candidates_generated") or 0),
        "candidates_selected": int(summary.get("dedup_candidates_selected") or 0),
        "pairs_reviewed": int(summary.get("dedup_pairs_reviewed") or 0),
        "not_reviewed_capacity": int(summary.get("dedup_candidates_not_reviewed_capacity") or 0),
        "not_reviewed_too_large": int(summary.get("dedup_candidates_not_reviewed_too_large") or 0),
        "status": str(summary.get("dedup_status") or ""),
        "disabled_reason": str(summary.get("dedup_disabled_reason") or ""),
        "requested_model": str(summary.get("dedup_requested_model") or ""),
        "effective_model": str(summary.get("dedup_effective_model") or ""),
    }


def payload(run_id: str = "", root: Path | None = None) -> dict:
    """Objet `qualification` joint aux données de statut."""
    verdict = evaluate(load_run(run_id, root))
    return {
        "run_id": verdict["run_id"],
        "state": verdict["state"],
        "reasons": verdict["reasons"],
        "pending_fields": verdict["pending_fields"],
        "pending_fields_available": verdict["pending_fields_available"],
        "pending_pairs": verdict["pending_pairs"],
        "pairs": verdict["extraction"]["pairs"],
        "label": INCOMPLETE_LABEL if verdict["state"] == STATE_PARTIAL else "",
    }


# --- Rapports Markdown ------------------------------------------------------

def _cell(value) -> str:
    text = " ".join(str(value if value not in (None, "") else "—").split())
    return text.replace("|", "\\|")[:200]


def _origin(event: dict) -> str:
    return {
        "cache_read": "cache",
        "success": "LLM",
        "failed": "LLM (échec)",
        "disabled": "désactivé",
        "budget_blocked": "budget",
    }.get(str(event.get("status") or ""), str(event.get("status") or ""))


def _deferred_by_item(run: QualificationRun) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for row in run.deferred:
        item_id = str((row.get("item") or {}).get("Item_ID") or "")
        if item_id:
            out[item_id] = row
    return out


def extraction_rows(run: QualificationRun) -> list[dict]:
    """Une ligne par champ traité : origine, valeur, preuve, décision."""
    rows: list[dict] = []
    for event in run.trace:
        if not isinstance(event, dict):
            continue
        item_id = str(event.get("item_id") or "")
        origin = _origin(event)
        fields = event.get("fields")
        if isinstance(fields, dict) and fields:
            for name, detail in sorted(fields.items()):
                detail = detail if isinstance(detail, dict) else {}
                value = detail.get("value")
                rows.append({
                    "item_id": item_id,
                    "field": name,
                    "origin": origin,
                    "value": _value_text(value),
                    "evidence": _evidence_text(value),
                    "validation": detail.get("status") or "",
                    "rejection": detail.get("rejection_reason") or "",
                    "kept": _value_text(value) if detail.get("status") == "accepted" else "",
                })
            continue
        normalized = event.get("normalized") if isinstance(event.get("normalized"), dict) else {}
        rejections = event.get("rejections") if isinstance(event.get("rejections"), dict) else {}
        kinds = event.get("rejection_kinds") if isinstance(event.get("rejection_kinds"), dict) else {}
        proposals = event.get("proposals") if isinstance(event.get("proposals"), dict) else {}
        for name in sorted(event.get("requested_fields") or ()):
            value = normalized.get(name)
            # Un champ rejeté n'a pas de valeur normalisée : sans la proposition
            # brute, le tableau n'afficherait qu'un motif sans son objet.
            shown = value if name in normalized else proposals.get(name)
            reason = rejections.get(name, "") or str(event.get("reason") or "")
            kind = str(kinds.get(name) or "")
            rows.append({
                "item_id": item_id,
                "field": name,
                "origin": origin,
                "value": _value_text(shown),
                "evidence": _evidence_text(shown),
                "validation": "accepted" if name in normalized else (
                    "rejected" if name in rejections else "deferred"
                ),
                "rejection": f"{reason} ({kind})" if reason and kind else reason,
                "kept": _value_text(value) if name in normalized else "",
            })
    return rows


def _value_text(value) -> str:
    if isinstance(value, dict):
        return str(value.get("value") if value.get("value") is not None else "")
    if isinstance(value, list):
        return " ; ".join(_value_text(item) for item in value[:3])
    return "" if value is None else str(value)


def _evidence_text(value) -> str:
    if isinstance(value, dict):
        return str(value.get("evidence") or "")
    if isinstance(value, list) and value:
        return _evidence_text(value[0])
    return ""


def _incident_by_item() -> dict[str, str]:
    incidents = store.load_incidents()
    out: dict[str, str] = {}
    for incident in incidents:
        for url in str(incident.Source_URLs or "").split(" | "):
            if url.strip():
                out[url.strip()] = incident.Incident_ID
    return out


def extraction_table(run: QualificationRun) -> str:
    """Tableau « extraction → décision par champ »."""
    incident_by_url = _incident_by_item()
    url_by_item = {
        str(event.get("item_id") or ""): str(event.get("url") or "")
        for event in run.trace if isinstance(event, dict)
    }
    header = (
        "| Item | Champ | Origine | Valeur proposée | Preuve | Validation | "
        "Motif de rejet | Valeur conservée | Incident final |"
    )
    lines = [header, "|---|---|---|---|---|---|---|---|---|"]
    rows = extraction_rows(run)
    if not rows:
        lines.append("| _aucun champ traité dans ce run_ |  |  |  |  |  |  |  |  |")
        return "\n".join(lines)
    for row in rows:
        incident = incident_by_url.get(url_by_item.get(row["item_id"], ""), "")
        lines.append("| " + " | ".join(_cell(value) for value in (
            row["item_id"], row["field"], row["origin"], row["value"], row["evidence"],
            row["validation"], row["rejection"], row["kept"], incident,
        )) + " |")
    return "\n".join(lines)


def dedup_table(run: QualificationRun) -> str:
    """Tableau « déduplication par paire »."""
    header = (
        "| Paire | Candidats | Décision | Confiance | Garde-fou | Fusion effective | Modèle |"
    )
    lines = [header, "|---|---|---|---|---|---|---|"]
    pairs = run.pairs or run.pending_pairs
    if not pairs:
        lines.append("| _aucune paire candidate dans ce run_ |  |  |  |  |  |  |")
        return "\n".join(lines)
    for row in pairs:
        decision = f"{row.get('same_organisation', '')}/{row.get('same_incident', '')}"
        merged = "oui" if row.get("status") == "APPLIED" else "non"
        lines.append("| " + " | ".join(_cell(value) for value in (
            row.get("pair_key", ""),
            f"{row.get('left', '')} ↔ {row.get('right', '')}",
            f"{row.get('status', '')} ({decision})",
            row.get("confidence", ""),
            row.get("blocked_reason") or row.get("disabled_reason") or "",
            merged,
            row.get("model") or "",
        )) + " |")
    return "\n".join(lines)


def _partition(run: QualificationRun) -> dict[str, list[dict]]:
    """Nouveautés, articles relus et reprises différées, séparés."""
    deferred_items = set(_deferred_by_item(run))
    fresh: list[dict] = []
    reread: list[dict] = []
    postponed: list[dict] = []
    for row in extraction_rows(run):
        if row["item_id"] in deferred_items and row["validation"] in {"deferred", ""}:
            postponed.append(row)
        elif row["origin"] == "cache":
            reread.append(row)
        else:
            fresh.append(row)
    return {"nouveautés": fresh, "articles relus": reread, "reprises différées": postponed}


def markdown_report(run: QualificationRun) -> str:
    """Rapport complet de qualification d'un run."""
    verdict = evaluate(run)
    extraction = verdict["extraction"]
    dedup = verdict["dedup"]
    groups = _partition(run)
    lines = [
        f"## Qualification — `{verdict['run_id'] or 'run inconnu'}`",
        f"- État : **{verdict['state']}**"
        + (f" — {INCOMPLETE_LABEL}" if verdict["state"] == STATE_PARTIAL else ""),
        "- Champs d'extraction en attente : "
        + (f"**{verdict['pending_fields']}**" if verdict["pending_fields_available"]
           else "_non disponible_"),
        f"- Paires en attente : **{verdict['pending_pairs']}**",
        f"- Modèle d'extraction demandé : `{extraction['requested_model'] or '—'}` ; "
        f"exécuté : `{extraction['effective_model'] or '—'}`",
        f"- Modèle de déduplication demandé : `{dedup['requested_model'] or '—'}` ; "
        f"exécuté : `{dedup['effective_model'] or '—'}`",
    ]
    for reason in verdict["reasons"]:
        lines.append(f"- ! {reason}")
    lines += [
        "",
        "### Extraction → décision par champ",
        "",
        extraction_table(run),
        "",
        "#### Répartition",
        "",
        "| Périmètre | Champs |",
        "|---|---:|",
    ]
    for label, rows in groups.items():
        lines.append(f"| {label} | {len(rows)} |")
    lines += ["", "### Couples activité/secteur", "", pair_table(verdict)]
    lines += ["", "### Déduplication par paire", "", dedup_table(run)]
    return "\n".join(lines)


_PAIR_LABELS = (
    ("accepted", "Acceptés"),
    ("abstained", "Abstentions"),
    ("rejected", "Rejets en attente de reprise"),
    ("rejected_exhausted", "Rejets persistants"),
    ("technical_failure", "Échecs techniques"),
)


def pair_table(verdict: dict) -> str:
    """Décompte des couples activité/secteur, cache et appel séparés."""
    counts = verdict["extraction"]["pairs"]
    lines = ["| Issue | Total | Cache | Appel |", "|---|---:|---:|---:|"]
    if not counts:
        # Distinguer « aucun couple » de « le run ne le dit pas » : un rapport
        # historique ne doit pas afficher zéro pour une information perdue.
        lines.append("| _non disponible pour ce run_ |  |  |  |")
        return "\n".join(lines)
    lines.append(f"| **Demandés** | **{int(counts.get('requested') or 0)}** |  |  |")
    for key, label in _PAIR_LABELS:
        bucket = counts.get(key)
        bucket = bucket if isinstance(bucket, dict) else {}
        lines.append(
            f"| {label} | {int(bucket.get('total') or 0)} "
            f"| {int(bucket.get('from_cache') or 0)} | {int(bucket.get('from_call') or 0)} |"
        )
    return "\n".join(lines)
