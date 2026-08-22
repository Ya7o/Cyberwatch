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

#: Un signal doit dépasser la croissance globale de la fenêtre, sinon il ne
#: décrit que la montée générale du volume de publication. Sans cette
#: normalisation, « Fuite de données » (69 % de la fenêtre) et « France
#: métropolitaine » (93 %) ressortaient en tête avec une confiance élevée alors
#: qu'ils suivaient exactement le taux de base.
BASE_RATE_EXCESS_POINTS = 25.0

#: Une catégorie qui représente l'essentiel de la fenêtre *est* la fenêtre :
#: sa variation ne dit rien de plus que le total.
DOMINANT_SHARE_PCT = 60.0

#: La normalisation n'a de sens que si le taux de base est estimable. En
#: dessous, l'écart observé est du bruit d'échantillon, pas un taux.
BASE_RATE_MIN_PREVIOUS = 10
BASE_RATE_MIN_CURRENT = 20

#: Unités de volume comparables entre elles (on n'additionne pas des fichiers
#: et des personnes).
EXPOSURE_UNITS = ("people", "records", "users", "accounts", "clients")


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


def _base_rate(current: list[dict], previous: list[dict]) -> float | None:
    """Croissance globale de la fenêtre, si elle est estimable.

    `None` signifie « pas assez de matière pour parler de taux » : sur quelques
    incidents, l'écart observé est du bruit d'échantillon. Dans ce cas les
    seuils bruts font foi et aucune normalisation n'est appliquée.
    """
    if len(previous) < BASE_RATE_MIN_PREVIOUS or len(current) < BASE_RATE_MIN_CURRENT:
        return None
    return round(100.0 * (len(current) - len(previous)) / len(previous), 1)


def _dimension_signals(current: list[dict], previous: list[dict], dimension: str, days: int) -> list[dict]:
    cur = Counter(str(row.get(dimension) or UNKNOWN) for row in current if _known(row.get(dimension)))
    prev = Counter(str(row.get(dimension) or UNKNOWN) for row in previous if _known(row.get(dimension)))
    base = _base_rate(current, previous)
    signals = []
    for label in sorted(set(cur) | set(prev)):
        now, before = cur[label], prev[label]
        delta = now - before
        if now < 3 or delta < 2:
            continue
        change = _pct_change(now, before)
        if before and (change or 0) < 50:
            continue
        share = round(100.0 * now / len(current), 1) if current else 0.0
        excess = None if (base is None or change is None) else round(change - base, 1)
        if base is not None:
            # Une catégorie majoritaire *est* la fenêtre : sa variation ne dit
            # rien de plus que le total.
            if share > DOMINANT_SHARE_PCT:
                continue
            # Et une croissance qui suit la croissance globale mesure la
            # couverture, pas la menace.
            if excess is not None and excess < BASE_RATE_EXCESS_POINTS:
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
            # Publiés pour que l'interface puisse montrer *pourquoi* c'est un
            # signal : la part et le taux de base sont la moitié de la lecture.
            "share_pct": share,
            "base_rate_pct": base,
            "excess_points": excess,
            "confidence": _confidence(count=now, multi_source=multi, known_ratio=known_fields / max(1, now * len(DIMENSIONS))),
            "incident_ids": _evidence_ids(evidence),
        })
    return signals


def _new_pairs(current: list[dict], previous: list[dict], days: int) -> list[dict]:
    base = _base_rate(current, previous)

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
            "share_pct": round(100.0 * len(evidence) / len(current), 1) if current else 0.0,
            "base_rate_pct": base,
            "excess_points": None,
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


def _month(value: Any) -> str:
    day = _day(value)
    return day.strftime("%Y-%m") if day else ""


def _month_range(rows: list[dict]) -> list[str]:
    months = sorted({_month(row.get("date")) for row in rows} - {""})
    if not months:
        return []
    year, month = (int(part) for part in months[0].split("-"))
    end_year, end_month = (int(part) for part in months[-1].split("-"))
    out = []
    while (year, month) <= (end_year, end_month):
        out.append(f"{year}-{month:02d}")
        month, year = (1, year + 1) if month == 12 else (month + 1, year)
    return out


def _series(rows: list[dict]) -> dict[str, Any]:
    """Évolution mois par mois, dimension par dimension.

    Publie aussi le nombre de sources distinctes observées chaque mois : une
    part qui monte peut être une menace qui monte *ou* une source qui vient
    d'être branchée. Les deux courbes doivent se lire ensemble, sinon une
    hausse de couverture se cite comme une hausse de menace.
    """
    months = _month_range(rows)
    if not months:
        return {"months": [], "total": [], "threat": {}, "sector": {}, "sources_observed": []}
    index = {month: position for position, month in enumerate(months)}
    total = [0] * len(months)
    sources: list[set] = [set() for _ in months]
    per_dimension: dict[str, dict[str, list[int]]] = {"threat": {}, "sector": {}}
    for row in rows:
        month = _month(row.get("date"))
        if month not in index:
            continue
        position = index[month]
        total[position] += 1
        for value in (row.get("sources") or []):
            sources[position].add(str(value))
        for dimension in ("threat", "sector"):
            label = str(row.get(dimension) or UNKNOWN)
            if not _known(label):
                continue
            per_dimension[dimension].setdefault(label, [0] * len(months))[position] += 1
    # Seules les catégories qui pèsent réellement méritent une courbe.
    for dimension, table in per_dimension.items():
        per_dimension[dimension] = {
            label: counts for label, counts in
            sorted(table.items(), key=lambda item: (-sum(item[1]), item[0]))[:6]
        }
    return {
        "months": months,
        "total": total,
        "threat": per_dimension["threat"],
        "sector": per_dimension["sector"],
        "sources_observed": [len(entry) for entry in sources],
    }


def _exposure(rows: list[dict]) -> dict[str, Any]:
    """Ampleur des fuites, sans jamais produire de total.

    Les volumes sont majoritairement *revendiqués* et couvrent moins d'un
    tiers des incidents : une somme donnerait un chiffre spectaculaire et
    indéfendable, dominé par quelques revendications extrêmes. Seules la
    médiane et le 90e centile sont publiés, avec l'effectif concerné et la
    répartition des niveaux de preuve.
    """
    values: list[int] = []
    evidence: Counter = Counter()
    for row in rows:
        best: tuple[int, str] | None = None
        for fact in (row.get("facts") or []):
            rich = fact.get("rich_facts") or {}
            for record in (rich.get("affected_counts") or []):
                value, unit = record.get("value"), record.get("unit")
                if isinstance(value, int) and unit in EXPOSURE_UNITS:
                    if best is None or value > best[0]:
                        best = (value, str(record.get("status") or "unknown"))
            if best is None and isinstance(fact.get("affected_count"), int) and fact.get("affected_unit") in EXPOSURE_UNITS:
                best = (int(fact["affected_count"]), str(fact.get("claim_status") or "unknown"))
        if best:
            values.append(best[0])
            evidence[best[1]] += 1
    total = len(rows)
    if not values:
        return {"documented": 0, "total": total, "documented_pct": 0.0, "evidence": {}}
    ordered = sorted(values)
    return {
        "documented": len(ordered),
        "total": total,
        "documented_pct": round(100 * _ratio(len(ordered), total), 1),
        "median": ordered[len(ordered) // 2],
        "p90": ordered[min(len(ordered) - 1, int(0.9 * len(ordered)))],
        "max": ordered[-1],
        "evidence": dict(sorted(evidence.items(), key=lambda item: (-item[1], item[0]))),
        "note": "Volumes majoritairement revendiqués et non vérifiés ; aucun total n'est publié.",
    }


def _quality(rows: list[dict], anchor: date) -> dict[str, Any]:
    """Ce que vaut la base — le préalable à toute citation d'un de ses chiffres."""
    total = len(rows)
    if not total:
        return {"incidents": 0}
    mono = sum(len(set(row.get("sources") or [])) <= 1 for row in rows)
    days = [day for day in (_day(row.get("date")) for row in rows) if day]
    sources = {str(value) for row in rows for value in (row.get("sources") or [])}
    return {
        "incidents": total,
        "organisations": len({str(row.get("org") or "").strip().lower() for row in rows if row.get("org")}),
        "mono_source": mono,
        "mono_source_pct": round(100 * _ratio(mono, total), 1),
        "corroborated_pct": round(100 * _ratio(total - mono, total), 1),
        "with_summary_pct": round(100 * _ratio(sum(bool(row.get("summary")) for row in rows), total), 1),
        "sources": len(sources),
        "first_date": min(days).isoformat() if days else "",
        "last_date": max(days).isoformat() if days else "",
        "history_months": (len(_month_range(rows)) if days else 0),
        "unknown_pct": {
            key: round(100 * _ratio(sum(not _known(row.get(key)) for row in rows), total), 1)
            for key in DIMENSIONS
        },
    }


def _gap_days(days: list[date]) -> tuple[int | None, int | None]:
    if len(days) < 2:
        return None, None
    ordered = sorted(days, reverse=True)
    gaps = sorted((ordered[i] - ordered[i + 1]).days for i in range(len(ordered) - 1))
    return gaps[len(gaps) // 2], gaps[-1]


def _focus(rows: list[dict], anchor: date, locations: tuple[str, ...]) -> dict[str, Any]:
    """Périmètre prioritaire (Réunion / Mayotte) : informer sans crier au loup.

    À ~2 incidents par mois, « aucun incident » est l'état normal. Le silence
    n'est donc lisible qu'accompagné de la normale observée et de l'état de la
    source locale : sans cela, un écart banal se lit comme une accalmie, et une
    panne de collecte se lit comme une absence d'incident.
    """
    if not locations:
        return {}
    inside = [row for row in rows if str(row.get("location") or "") in locations]
    outside = [row for row in rows if str(row.get("location") or "") not in locations]
    days = [day for day in (_day(row.get("date")) for row in inside) if day]
    median_gap, max_gap = _gap_days(days)
    last = max(days) if days else None
    multi = sum(len(set(row.get("sources") or [])) > 1 for row in inside)

    def profile(subset: list[dict]) -> dict[str, Any]:
        """Profil de menace d'un périmètre, avec ce qui le conditionne.

        Sur un petit périmètre, le profil de menace est déterminé par la
        composition des sources, pas par la réalité du terrain : une source
        mono-thématique qui couvre seule un territoire y produit mécaniquement
        100 % de sa thématique. Le profil n'est donc jamais publié seul — la
        composition des sources et un indicateur de fiabilité l'accompagnent,
        faute de quoi un artefact de couverture se cite comme un fait.
        """
        total = len(subset)
        by_source = Counter(str(value) for row in subset for value in (row.get("sources") or []))
        top_share = round(100 * _ratio(by_source.most_common(1)[0][1], total), 1) if by_source and total else 0.0
        return {
            "incidents": total,
            "threats": _counts(subset, "threat")[:4],
            "sectors": [entry for entry in _counts(subset, "sector") if entry["label"] != UNKNOWN][:4],
            "ransomware_pct": round(100 * _ratio(sum(str(row.get("threat") or "") == "Ransomware" for row in subset), total), 1),
            "by_source": dict(by_source.most_common()),
            "dominant_source_pct": top_share,
            # En dessous de 30 incidents ou avec une source dominante, le profil
            # de menace décrit la couverture, pas la menace.
            "threat_profile_reliable": bool(total >= 30 and top_share <= DOMINANT_SHARE_PCT),
        }

    return {
        "locations": list(locations),
        "incidents": len(inside),
        "by_location": {
            location: sum(str(row.get("location") or "") == location for row in inside)
            for location in locations
        },
        "last_date": last.isoformat() if last else "",
        "days_since_last": (anchor - last).days if last else None,
        "median_gap_days": median_gap,
        "max_gap_days": max_gap,
        # Le silence est-il anormal, ou simplement conforme à ce qu'on observe ?
        "silence_is_unusual": bool(last and max_gap is not None and (anchor - last).days > max_gap),
        "multi_source": multi,
        "share_pct": round(100 * _ratio(len(inside), len(rows)), 1),
        "profile": profile(inside),
        "comparison": profile(outside),
    }


def build_analytics(
    incidents: list[dict],
    *,
    as_of: str | date | None = None,
    focus_locations: tuple[str, ...] | list[str] = (),
) -> dict[str, Any]:
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
        "series": _series(dated),
        "exposure": _exposure(incidents),
        "quality": _quality(incidents, anchor),
        "focus": _focus(dated, anchor, tuple(focus_locations)),
        "method": {
            "signal_rule": "minimum 3 incidents and +2 delta; acceleration requires >=50% increase; new threat-sector pairs require >=3 incidents",
            "base_rate": (
                f"a signal must exceed the window's overall growth by {BASE_RATE_EXCESS_POINTS:.0f} points; "
                f"a category holding more than {DOMINANT_SHARE_PCT:.0f}% of the window is excluded. "
                f"Normalisation applies only when the previous window holds at least {BASE_RATE_MIN_PREVIOUS} incidents."
            ),
            "confidence": "55% sample size + 25% multi-source corroboration + 20% field completeness",
            "exposure": "median and 90th percentile only; volumes are mostly claimed and never summed",
            "warning": "Observed publication patterns are not estimates of true cyber incident prevalence.",
        },
    }
