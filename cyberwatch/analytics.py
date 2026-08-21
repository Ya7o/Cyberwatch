"""Analytics déterministes pour Cyberwatch.

Aucun accès réseau, aucun LLM et aucune mutation des données canoniques. Le module
transforme les incidents publiables en métriques, signaux et contexte de confiance.
La narration générée ici reste factuelle et templatisée ; un LLM éventuel ne doit
consommer que ce payload déjà calculé.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import date, datetime, timedelta
from math import log2
from typing import Any, Iterable

UNKNOWN = "Inconnu"
WINDOWS = (7, 30, 90, 365)
DIMENSIONS = ("threat", "sector", "location")


def _day(value: Any) -> date | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).date()
    except ValueError:
        try:
            return date.fromisoformat(raw[:10])
        except ValueError:
            return None


def _known(value: Any) -> bool:
    return bool(str(value or "").strip()) and str(value).strip() != UNKNOWN


def _ratio(part: int, total: int) -> float:
    return round(part / total, 4) if total else 0.0


def _pct_change(current: int, previous: int) -> float | None:
    if previous == 0:
        return None if current == 0 else 100.0
    return round(100.0 * (current - previous) / previous, 1)


def _source_count(row: dict) -> int:
    source_values = row.get("sources") or []
    if isinstance(source_values, str):
        source_values = [part.strip() for part in source_values.split("|") if part.strip()]
    return len(set(source_values))


def _slice(rows: list[dict], as_of: date, days: int, offset: int = 0) -> list[dict]:
    end = as_of - timedelta(days=offset)
    start = end - timedelta(days=days - 1)
    return [row for row in rows if (d := _day(row.get("date"))) and start <= d <= end]


def _counts(rows: Iterable[dict], key: str) -> list[dict[str, Any]]:
    counter = Counter(str(row.get(key) or UNKNOWN) for row in rows)
    return [{"label": label, "count": count} for label, count in sorted(counter.items(), key=lambda item: (-item[1], item[0]))]


def _entropy(rows: list[dict], key: str) -> float:
    counts = Counter(str(row.get(key) or UNKNOWN) for row in rows if _known(row.get(key)))
    total = sum(counts.values())
    if total <= 1 or len(counts) <= 1:
        return 0.0
    entropy = -sum((n / total) * log2(n / total) for n in counts.values())
    return round(entropy / log2(len(counts)), 3)


def _confidence(*, count: int, multi_source: int, known_ratio: float) -> dict[str, Any]:
    evidence = min(1.0, count / 12.0)
    corroboration = _ratio(multi_source, count)
    score = round(100 * (0.55 * evidence + 0.25 * corroboration + 0.20 * known_ratio))
    level = "high" if score >= 75 else "medium" if score >= 50 else "low"
    return {"score": score, "level": level, "incidents": count, "multi_source_incidents": multi_source, "known_ratio": round(known_ratio, 3)}


def _evidence_ids(rows: list[dict]) -> list[str]:
    return sorted({str(row.get("id") or "") for row in rows if row.get("id")})[:12]


def _dimension_signals(current: list[dict], previous: list[dict], dimension: str, days: int) -> list[dict]:
    cur = Counter(str(row.get(dimension) or UNKNOWN) for row in current if _known(row.get(dimension)))
    prev = Counter(str(row.get(dimension) or UNKNOWN) for row in previous if _known(row.get(dimension)))
    signals = []
    for label in sorted(set(cur) | set(prev)):
        now, before = cur[label], prev[label]
        delta = now - before
        if now < 3 or delta < 2:
            continue
        change = _pct_change(now, before)
        if before and (change or 0) < 50:
            continue
        evidence = [row for row in current if str(row.get(dimension) or UNKNOWN) == label]
        multi = sum(_source_count(row) > 1 for row in evidence)
        known_fields = sum(sum(_known(row.get(key)) for key in DIMENSIONS) for row in evidence)
        signals.append({
            "kind": "emerging" if before == 0 else "acceleration",
            "dimension": dimension,
            "label": label,
            "window_days": days,
            "current": now,
            "previous": before,
            "delta": delta,
            "change_pct": change,
            "confidence": _confidence(count=now, multi_source=multi, known_ratio=known_fields / max(1, now * len(DIMENSIONS))),
            "incident_ids": _evidence_ids(evidence),
        })
    return signals


def _new_pairs(current: list[dict], previous: list[dict], days: int) -> list[dict]:
    def pairs(rows):
        result = defaultdict(list)
        for row in rows:
            threat, sector = row.get("threat"), row.get("sector")
            if _known(threat) and _known(sector):
                result[(str(threat), str(sector))].append(row)
        return result
    cur, prev = pairs(current), pairs(previous)
    signals = []
    for pair, evidence in sorted(cur.items()):
        if pair in prev or len(evidence) < 3:
            continue
        signals.append({
            "kind": "new_pair",
            "dimension": "threat_sector",
            "label": f"{pair[0]} × {pair[1]}",
            "window_days": days,
            "current": len(evidence),
            "previous": 0,
            "delta": len(evidence),
            "change_pct": 100.0,
            "confidence": _confidence(count=len(evidence), multi_source=sum(_source_count(row) > 1 for row in evidence), known_ratio=1.0),
            "incident_ids": _evidence_ids(evidence),
        })
    return signals


def _rank_signal(signal: dict) -> tuple:
    confidence = signal.get("confidence", {}).get("score", 0)
    return (-confidence, -int(signal.get("delta") or 0), str(signal.get("label") or ""))


def _narrative(signals: list[dict], windows: dict[str, dict]) -> list[str]:
    lines = []
    for signal in signals[:5]:
        label, now, before, days = signal["label"], signal["current"], signal["previous"], signal["window_days"]
        confidence = signal["confidence"]["level"]
        if signal["kind"] == "emerging":
            lines.append(f"{label} apparaît sur {days} jours avec {now} incidents, contre aucun sur la période précédente (confiance {confidence}).")
        elif signal["kind"] == "new_pair":
            lines.append(f"Nouveau couple observé {label} : {now} incidents sur {days} jours (confiance {confidence}).")
        else:
            lines.append(f"{label} accélère sur {days} jours : {now} incidents contre {before} auparavant (confiance {confidence}).")
    if not lines:
        count = windows.get("30", {}).get("current", 0)
        lines.append(f"Aucun signal suffisamment étayé n'est détecté sur 30 jours ; {count} incidents sont observés dans la fenêtre courante.")
    return lines


def build_analytics(incidents: list[dict], *, as_of: str | date | None = None) -> dict[str, Any]:
    anchor = as_of if isinstance(as_of, date) else _day(as_of)
    dated = [row for row in incidents if _day(row.get("date"))]
    anchor = anchor or (max((_day(row.get("date")) for row in dated), default=None) or date.today())
    windows: dict[str, dict] = {}
    for days in WINDOWS:
        current = _slice(dated, anchor, days)
        previous = _slice(dated, anchor, days, offset=days)
        multi = sum(_source_count(row) > 1 for row in current)
        windows[str(days)] = {
            "current": len(current), "previous": len(previous), "delta": len(current) - len(previous),
            "change_pct": _pct_change(len(current), len(previous)), "multi_source": multi,
            "multi_source_pct": round(100 * _ratio(multi, len(current)), 1),
        }
    signals = []
    for days in (30, 90):
        current, previous = _slice(dated, anchor, days), _slice(dated, anchor, days, offset=days)
        for dimension in DIMENSIONS:
            signals.extend(_dimension_signals(current, previous, dimension, days))
        signals.extend(_new_pairs(current, previous, days))
    unique = {}
    for signal in sorted(signals, key=lambda s: (s["window_days"],) + _rank_signal(s)):
        unique.setdefault((signal["kind"], signal["dimension"], signal["label"]), signal)
    signals = sorted(unique.values(), key=_rank_signal)[:20]
    current90 = _slice(dated, anchor, 90)
    coverage = {
        key: {
            "known": sum(_known(row.get(key)) for row in current90),
            "unknown": sum(not _known(row.get(key)) for row in current90),
            "known_pct": round(100 * _ratio(sum(_known(row.get(key)) for row in current90), len(current90)), 1),
        } for key in DIMENSIONS
    }
    top = {key: _counts(current90, key)[:8] for key in DIMENSIONS}
    org_counts = Counter(str(row.get("org") or UNKNOWN) for row in current90 if _known(row.get("org")))
    recurring = [{"organisation": label, "incidents": count} for label, count in sorted(org_counts.items(), key=lambda item: (-item[1], item[0])) if count >= 2][:10]
    return {
        "schema": "cyberwatch-analytics-v1", "as_of": anchor.isoformat(), "incident_count": len(incidents),
        "dated_incidents": len(dated), "windows": windows, "coverage": coverage, "top_90d": top,
        "diversity_90d": {key: _entropy(current90, key) for key in DIMENSIONS},
        "recurring_organisations_90d": recurring, "signals": signals, "briefing": _narrative(signals, windows),
        "method": {
            "signal_rule": "minimum 3 incidents and +2 delta; acceleration requires >=50% increase; new threat-sector pairs require >=3 incidents",
            "confidence": "55% sample size + 25% multi-source corroboration + 20% field completeness",
            "warning": "Observed publication patterns are not estimates of true cyber incident prevalence.",
        },
    }
