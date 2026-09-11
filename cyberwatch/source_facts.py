"""Faits supplémentaires publiés par chaque source.

Couche auxiliaire et non canonique : elle ne modifie jamais Threat/Sector/Location.
Pour FrenchBreaches et Cyberattaque.org, le LLM comprend le récit puis cette
couche valide mécaniquement les faits candidats. Les autres sources restent
strictement déterministes/structurées.
"""
from __future__ import annotations

import json
import logging
import re

from . import config, organisation_family, source_facts_ai
from .headline import is_organisation_name_only, is_publishable_for_organisation, is_publishable_headline, rejection_reason
from .collectors.base import RawEntry, SourceSpec
from .model import SOURCE_FACT_COLUMNS, Item
from .normalize import (
    classify_threat,
    clean_organisation,
    extract_activity_description,
    organisation_key,
    parse_date,
    searchable,
    strip_accents,
)
from .source_facts_materialization import (
    materialize_cached_llm_fields,
    semantic_materialization_gaps,
)

logger = logging.getLogger(__name__)

SOURCE_FACTS_VERSION = "6"

_BASE_COLUMNS = {
    "Item_ID", "Source_ID", "Extraction_Method", "Extraction_Version",
    "Source_Metadata_JSON", "Evidence_JSON",
}


def _dumps_json(value) -> str:
    if not value:
        return ""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _loads_json(raw: str):
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return None


_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
_CVSS_RE = re.compile(
    r"\bCVSS[:\s]*(?:score\s*)?(?:de\s*)?(\d{1,2}(?:[.,]\d)?)(?:\s*/\s*10)?\b",
    re.I,
)
_FILE_COUNT_RE = re.compile(r"\b(\d[\d\s .,]*)\s*(?:fichiers?|documents?)\b", re.I)
_ATTACK_TIMELINE_RE = re.compile(
    r"\b(?:cyberattaque|attaque|intrusion|compromission)\b.{0,100}"
    r"\b(?:a eu lieu|est survenue|a commence|victime)\b|"
    r"\b(?:a ete victime|victime)\b.{0,100}"
    r"\b(?:cyberattaque|attaque|intrusion|compromission)\b",
    re.I,
)
_DISCOVERY_TIMELINE_RE = re.compile(
    r"\b(?:detectee?|decouverte?|notifiee?|informee?|publiee?|revelee?)\b", re.I,
)


def _attack_date_from_rich(metadata: dict) -> tuple[str, str]:
    rich = metadata.get("rich_facts") if isinstance(metadata.get("rich_facts"), dict) else {}
    timeline = rich.get("timeline") if isinstance(rich, dict) else None
    candidates: list[tuple[int, int, str, str]] = []
    for position, row in enumerate(timeline if isinstance(timeline, list) else []):
        if not isinstance(row, dict):
            continue
        date = parse_date(row.get("date"))
        evidence = str(row.get("evidence") or row.get("event") or "").strip()
        blob = searchable(evidence)
        if not date or not evidence or not _ATTACK_TIMELINE_RE.search(blob):
            continue
        score = 2
        if re.search(r"\b(?:a eu lieu|est survenue|a commence)\b", blob, re.I):
            score += 2
        if _DISCOVERY_TIMELINE_RE.search(blob) and not re.search(
            r"\b(?:mais|avant d|apres avoir)\b", blob, re.I
        ):
            score -= 3
        candidates.append((score, position, date, evidence))
    if not candidates:
        return "", ""
    _, _, date, evidence = sorted(candidates, key=lambda row: (-row[0], row[1]))[0]
    return date, evidence


def apply_event_dates(items: list[Item], facts: list[dict]) -> list[str]:
    """Propage une date d'attaque sourcée sans modifier l'identité de l'item."""
    dates: dict[str, str] = {}
    for row in facts:
        item_id = str(row.get("Item_ID") or "")
        date = parse_date(row.get("Attack_Date"))
        if item_id and date:
            dates[item_id] = date
    changed: list[str] = []
    for item in items:
        candidate = dates.get(item.Item_ID, "")
        if not item.Event_Date and candidate:
            item.Event_Date = candidate
            changed.append(item.Item_ID)
    return sorted(changed)


def _extract_cves(*texts: str) -> list[str]:
    return sorted({match.upper() for text in texts for match in _CVE_RE.findall(text or "")})


def _extract_cvss(*texts: str) -> str:
    for text in texts:
        match = _CVSS_RE.search(text or "")
        if match:
            return match.group(0).strip()
    return ""


def _digits(raw: str) -> str:
    cleaned = (raw or "").replace(" ", "").replace(" ", "").replace(".", "").replace(",", "")
    return cleaned if cleaned.isdigit() else ""


def _extract_file_count(*texts: str) -> str:
    for text in texts:
        match = _FILE_COUNT_RE.search(text or "")
        if match:
            return _digits(match.group(1))
    return ""


def _split_list(text: str) -> list[str]:
    parts = re.split(r",|\bet\b", text or "")
    return [part.strip(" .") for part in parts if part.strip(" .")]


_UNIT_MAP = {
    "personne": "people", "personnes": "people",
    "victime": "people", "victimes": "people",
    "membre": "people", "membres": "people",
    "agent": "people", "agents": "people",
    "compte": "accounts", "comptes": "accounts",
    "utilisateur": "users", "utilisateurs": "users",
    "client": "clients", "clients": "clients",
    "employe": "people", "employes": "people",
    "salarie": "people", "salaries": "people",
    "patient": "people", "patients": "people",
    "eleve": "people", "eleves": "people",
    "abonne": "people", "abonnes": "people", "assure": "people", "assures": "people",
    "adherent": "people", "adherents": "people",
    "particulier": "people", "particuliers": "people",
    "professionnel": "people", "professionnels": "people",
    "enregistrement": "records", "enregistrements": "records",
    "ligne": "records", "lignes": "records",
    "commande": "records", "commandes": "records",
    "transaction": "records", "transactions": "records",
    "dossier": "files", "dossiers": "files",
    "fichier": "files", "fichiers": "files",
}

_COUNT_RE = re.compile(
    r"(?:environ\s+|plus\s+de\s+|pr[eè]s\s+de\s+|jusqu['’]?[àa]\s+)?"
    r"(?P<number>\d[\d\s .,]*\d|\d)\s*"
    r"(?P<scale>million[s]?|millier[s]?|mille)?\s*"
    r"(?:de\s+|d['’])?\s*"
    r"(?P<unit>[a-zàâäéèêëïîôöùûüç]+)",
    re.I,
)


def _to_number(raw_number: str, scale: str) -> int | None:
    cleaned = raw_number.replace(" ", "").replace(" ", "").strip()
    scale = (scale or "").lower()
    try:
        if scale.startswith("million"):
            return int(round(float(cleaned.replace(",", ".")) * 1_000_000))
        if scale.startswith(("millier", "mille")):
            return int(round(float(cleaned.replace(",", ".")) * 1_000))
        return int(cleaned.replace(".", "").replace(",", ""))
    except ValueError:
        return None


def _parse_count_phrase(text: str) -> tuple[str, str, str]:
    """Retourne le premier comptage dont l'unité appartient au vocabulaire fermé."""
    if not text:
        return "", "", ""
    for match in _COUNT_RE.finditer(text):
        unit_word = strip_accents(match.group("unit") or "").lower().rstrip(".,;:")
        canonical_unit = _UNIT_MAP.get(unit_word, "")
        if not canonical_unit:
            continue
        number = _to_number(match.group("number"), match.group("scale") or "")
        if number is not None:
            return str(number), canonical_unit, match.group(0).strip()
    return "", "", ""


def _clean_span(raw: str) -> str:
    return clean_organisation(raw).rstrip(" .,;:")


def _normalise_url(value: str) -> str:
    value = (value or "").strip()
    if value and not value.startswith(("http://", "https://")) and "." in value:
        return f"https://{value}"
    return value


_ACTOR_SENTINELS = {
    "", "un", "une", "le", "la", "les", "hacker", "le hacker", "un hacker",
    "de", "et", "group", "groupe",
    "attaquant", "l attaquant", "l'attaquant", "auteur", "inconnu", "non identifie",
    "non identifie publiquement", "n a", "na", "n/a",
    "ransomware", "rancongiciel", "cybercriminel", "cybercriminels", "pirate", "pirates",
    "article", "publication", "source", "entreprise", "l entreprise", "l'entreprise",
    "societe", "la societe", "organisation", "l organisation", "l'organisation", "victime",
    "prestataire", "fournisseur", "sous traitant", "sous-traitant", "tiers",
    "syndicat", "le syndicat", "association", "l association", "l'association",
    "celui ci", "celle ci", "celui la", "celle la", "ce dernier", "cette derniere",
}


def _valid_actor(candidate: str, organisation: str = "") -> str:
    candidate = _clean_span(candidate)
    normalized = searchable(candidate)
    if not candidate or normalized in _ACTOR_SENTINELS:
        return ""
    if normalized.startswith(("le hacker", "un hacker", "l attaquant", "un attaquant")):
        return ""
    if organisation and organisation_key(candidate) == organisation_key(organisation):
        return ""
    return candidate


def _valid_third_party(candidate: str, organisation: str = "") -> str:
    candidate = _clean_span(candidate)
    normalized = searchable(candidate)
    if not candidate or normalized in {"un", "une", "le", "la", "les", "inconnu"}:
        return ""
    if organisation and organisation_key(candidate) == organisation_key(organisation):
        return ""
    return candidate


_ACTIVITY_BRIDGES = {
    "", "est", "est un", "est une", "est un acteur", "est une entreprise",
    "est une societe", "est un groupe", "est une association", "est un organisme",
    "est une plateforme",
}


def _extract_victim_activity(organisation: str, *texts: str) -> str:
    org = searchable(organisation)
    if not org:
        return ""
    for text in texts:
        for segment in re.split(r"(?<=[.!?;])\s+|\n+", text or ""):
            segment_norm = searchable(segment)
            org_pos = segment_norm.find(org)
            if org_pos < 0:
                continue
            activity = extract_activity_description(segment)
            if not activity:
                continue
            activity_norm = searchable(activity)
            activity_pos = segment_norm.find(activity_norm)
            if activity_pos < org_pos + len(org):
                continue
            bridge = segment_norm[org_pos + len(org):activity_pos].strip(" ,-:()")
            if bridge in _ACTIVITY_BRIDGES:
                return activity
    return ""


def _activity_evidence_matches_organisation(organisation: str, evidence: str) -> bool:
    """Même contrat pour la validation IA et la promotion SourceFacts.

    L'ancien contrôle exigeait le libellé normalisé complet dans la citation ;
    un cache pouvait donc être `accepted` puis rejeté ici pour une variante
    éditoriale du nom. On accepte soit le nom complet, soit un faisceau de
    jetons distinctifs de la victime (sigle inclus), jamais une citation sans
    rattachement identifiable.
    """
    org = searchable(organisation)
    proof = searchable(evidence)
    if not org or not proof:
        return False
    if org in proof:
        return True
    stop = {"de", "du", "des", "la", "le", "les", "l", "d", "et", "the", "of"}
    tokens = [token for token in org.split() if token not in stop and len(token) >= 3]
    proof_tokens = set(proof.split())
    hits = {token for token in tokens if token in proof_tokens}
    acronyms = {
        searchable(token)
        for token in organisation.split()
        if len(token) <= 5 and token.isalpha() and token.upper() == token
    }
    if acronyms:
        if acronyms & proof_tokens:
            return True
        # Une forme développée peut légitimement remplacer le sigle, mais elle
        # doit aussi conserver un élément distinctif du nom (par ex. Moselle),
        # sans quoi une mention générique du type d'organisme serait acceptée.
        family = organisation_family.match_organisation_family(organisation)
        if family is None:
            return False
        rule = next(
            (value for value in organisation_family.load_rules() if value.family_id == family.family_id),
            None,
        )
        expanded = bool(rule) and any(
            prefix in proof
            for prefix in (*rule.full_name_prefixes, *rule.aliases)
        )
        return expanded and bool(hits - acronyms)
    return len(hits) >= min(2, len(set(tokens))) if tokens else False


def _ai_activity(ai_result: dict, organisation: str) -> tuple[str, str]:
    candidate = ai_result.get("activity_description") if isinstance(ai_result, dict) else None
    if not isinstance(candidate, dict):
        return "", ""
    value = str(candidate.get("value") or "").strip()
    evidence = str(candidate.get("evidence") or "").strip()
    if not value or not evidence or not _activity_evidence_matches_organisation(organisation, evidence):
        return "", ""
    return value, evidence


def _ai_sector_match(ai_result: dict) -> tuple[str, str]:
    """Rapprochement taxonomie Secteur produit par le même appel LLM que
    activity_description (§audit 2026-08-26) : jamais un canal LLM séparé."""
    candidate = ai_result.get("activity_sector_match") if isinstance(ai_result, dict) else None
    if not isinstance(candidate, dict):
        return "", ""
    value = str(candidate.get("value") or "").strip()
    evidence = str(candidate.get("evidence") or "").strip()
    if not value or value not in config.SECTORS or value == config.SECTOR_UNKNOWN or not evidence:
        return "", ""
    return value, evidence


def _ai_text(ai_result: dict, key: str) -> tuple[str, str]:
    candidate = ai_result.get(key) if isinstance(ai_result, dict) else None
    if not isinstance(candidate, dict):
        return "", ""
    return str(candidate.get("value") or "").strip(), str(candidate.get("evidence") or "").strip()


def _ai_threat_candidate(ai_result: dict) -> dict | None:
    value, evidence = _ai_text(ai_result, "threat_candidate")
    if value not in config.THREATS or value == config.THREAT_UNKNOWN or not evidence:
        return None
    candidate = ai_result.get("threat_candidate") or {}
    return {"value": value, "evidence": evidence, "confidence": candidate.get("confidence", "")}


_STATUS_PRIORITY = {"confirmed": 4, "reported": 3, "claimed": 2, "unknown": 1}


def _ordered_ai_evidence(ai_result: dict, key: str) -> list[dict]:
    values = ai_result.get(key) if isinstance(ai_result, dict) else None
    if not isinstance(values, list):
        return []
    return sorted(
        (value for value in values if isinstance(value, dict)),
        key=lambda value: (
            _STATUS_PRIORITY.get(str(value.get("status") or "unknown"), 0),
            float(value.get("confidence") or 0),
        ),
        reverse=True,
    )


def _ai_count(ai_result: dict) -> tuple[str, str, str, str]:
    for candidate in _ordered_ai_evidence(ai_result, "affected_counts"):
        evidence = str(candidate.get("evidence") or "").strip()
        count, unit, raw = _parse_count_phrase(evidence)
        if count:
            return count, unit, raw, str(candidate.get("status") or "unknown")
    return "", "", "", ""


def _ai_data_types(ai_result: dict) -> tuple[list[str], dict[str, str]]:
    values = ai_result.get("data_types") if isinstance(ai_result, dict) else None
    if not isinstance(values, list):
        return [], {}
    result: list[str] = []
    evidence: dict[str, str] = {}
    seen = set()
    for candidate in values:
        if not isinstance(candidate, dict):
            continue
        value = str(candidate.get("value") or "").strip(" .")
        proof = str(candidate.get("evidence") or "").strip()
        key = searchable(value)
        # LLM candidates are accepted only when their cited sentence states an
        # exposure.  A negated citation ("pas d'IBAN", "aucun mot de passe")
        # must not leak into Data_Types_JSON as a positive exposure.
        negated = re.search(
            r"\b(?:aucun(?:e)?|sans)\b.{0,48}\b(?:IBAN|RIB|mot(?:s)?\s+de\s+passe|"
            r"donn[ée]es?\s+bancaires?|carte(?:s)?\s+(?:bancaires?|de\s+paiement))\b|"
            r"\b(?:n['’ ](?:ai|as|a|avons|avez|ont|est|sommes|[êe]tes|sont)\s+pas|"
            r"ne\s+.{0,40}\s+pas|impossible\s+de\s+(?:d[ée]terminer|savoir|[ée]tablir))\b",
            proof,
            re.I,
        )
        if not value or not proof or key in seen or negated:
            continue
        seen.add(key)
        result.append(value)
        evidence[value] = proof
    return result, evidence


def _ai_initial_access(ai_result: dict) -> tuple[str, str]:
    value, evidence = _ai_text(ai_result, "initial_access")
    if value not in source_facts_ai.INITIAL_ACCESS_VALUES or not evidence:
        return "", ""
    return value, evidence


def _blank_fact(item: Item, spec: SourceSpec) -> dict:
    fact = {col: "" for col in SOURCE_FACT_COLUMNS}
    fact["Item_ID"] = item.Item_ID
    fact["Source_ID"] = item.Source_ID
    fact["Extraction_Method"] = spec.source_id
    fact["Extraction_Version"] = SOURCE_FACTS_VERSION
    return fact


def _has_content(fact: dict) -> bool:
    return any(fact.get(col) for col in SOURCE_FACT_COLUMNS if col not in _BASE_COLUMNS) or bool(fact.get("_Rich_Facts"))


def _finalize(fact: dict, item: Item, entry: RawEntry, evidence: dict) -> dict | None:
    if not _has_content(fact):
        return None
    fact["Evidence_JSON"] = _dumps_json(evidence)
    semantic_status = fact.pop("_Semantic_Refresh_Status", None)
    # Les métadonnées déjà posées par les handlers — contexte éditorial,
    # empreintes de préparation, réserve de menace — étaient écrasées ici par
    # celles du collecteur. C'est ce qui laissait `Editorial_Evidence` vide dans
    # le filet de déduplication et empêchait une décision « Inconnu » explicite
    # de survivre aux passes de reprise. Le collecteur reste prioritaire sur les
    # clés qu'il renseigne lui-même ; le reste est conservé.
    metadata = {**(_loads_json(fact.get("Source_Metadata_JSON")) or {}),
                **dict(entry.source_metadata or {})}
    threat_tentative = fact.pop("_Threat_Tentative", None)
    if isinstance(threat_tentative, dict):
        metadata["threat_tentative"] = threat_tentative
    semantic_rich = fact.pop("_Rich_Facts", None)
    if isinstance(semantic_rich, dict) and semantic_rich:
        existing_rich = metadata.get("rich_facts") if isinstance(metadata.get("rich_facts"), dict) else {}
        merged_rich = dict(existing_rich)
        for key, values in semantic_rich.items():
            if not isinstance(values, list):
                continue
            current = merged_rich.get(key) if isinstance(merged_rich.get(key), list) else []
            # The semantic layer is additive: deterministic collector facts
            # remain intact and are never overwritten by an LLM interpretation.
            merged_rich[key] = current + [value for value in values if value not in current]
        metadata["rich_facts"] = merged_rich
    if fact.get("Source_ID") in source_facts_ai.TARGET_SOURCES:
        # Ces marqueurs restent dans le metadata auxiliaire, jamais dans le
        # schéma public SOURCE_FACT_COLUMNS.
        metadata["_source_facts_content_hash"] = source_facts_ai.content_hash(entry)
        if isinstance(semantic_status, dict) and semantic_status:
            metadata["_source_facts_semantic_status"] = semantic_status
        summary = str(fact.get("Summary") or "").strip()
        # Un titre d'article est une headline éditoriale sourcée, à l'inverse
        # des fallbacks construits à partir de volumes ou de vecteurs. Il offre
        # une sortie sûre lorsque le LLM s'abstient, à condition de respecter
        # exactement le même contrat de publication.
        # FrenchBreaches ne renseigne pas systématiquement l'organisation sur
        # RawEntry. L'item a déjà été résolu de manière canonique : c'est lui
        # qui fait autorité pour rejeter un nom seul, y compris au reset zéro.
        organisation = item.Organisation_Raw or entry.organisation or ""
        from .headline import summary_role_is_supported
        summary_proof = evidence.get("Summary", "")
        if not (
            is_publishable_for_organisation(summary, organisation)
            and summary_role_is_supported(summary, summary_proof, organisation)
        ):
            # Certains adaptateurs d'hydratation ne réinjectent que le corps
            # dans RawEntry. Le titre canonique est néanmoins conservé sur
            # Item : l'utiliser évite qu'une indisponibilité LLM transforme un
            # article éditorial correctement collecté en synthèse vide.
            title = " ".join(str(entry.title or item.Title or "").split()).strip()
            if is_publishable_for_organisation(title, organisation):
                fact["Summary"] = summary = title
                evidence["Summary"] = title
        if is_publishable_for_organisation(summary, organisation):
            metadata["_source_facts_summary_status"] = "accepted"
        else:
            # Une absence éditoriale est explicite : aucun champ structuré ne
            # peut désormais servir de substitut pour une carte.
            fact["Summary"] = ""
            evidence.pop("Summary", None)
            status = (semantic_status or {}).get("summary") if isinstance(semantic_status, dict) else ""
            metadata["_source_facts_summary_status"] = (
                "abstained" if status == "abstained" else "rejected_quality"
            )
            metadata["_source_facts_summary_rejection"] = (
                "organisation_name_only" if is_organisation_name_only(summary, organisation)
                else rejection_reason(summary) or status or "missing"
            )
    if metadata:
        fact["Source_Metadata_JSON"] = _dumps_json(metadata)
    # Les fallbacks éditoriaux peuvent ajouter une preuve après la première
    # sérialisation en tête de fonction.
    fact["Evidence_JSON"] = _dumps_json(evidence)
    return fact


def _apply_blf_summary_certainty(fact: dict) -> None:
    """Évite de présenter une revendication BLF comme un fait confirmé."""
    summary = str(fact.get("Summary") or "").strip()
    status = str(fact.get("Claim_Status") or "").strip()
    if not summary or status == "confirmed":
        return
    replacements = {
        "claimed": (
            ("Données concernées :", "Données revendiquées selon BonjourLaFuite :"),
            ("Éléments documentés :", "Éléments revendiqués selon BonjourLaFuite :"),
        ),
        "unconfirmed": (
            ("Données concernées :", "Données signalées mais non confirmées :"),
            ("Éléments documentés :", "Éléments signalés mais non confirmés :"),
        ),
    }
    for prefix, replacement in replacements.get(status, ()):
        if summary.startswith(prefix):
            fact["Summary"] = replacement + summary[len(prefix):]
            return


_BLF_STATUS = {"🟢": "confirmed", "🟠": "claimed", "🔴": "unconfirmed"}


def _from_bonjourlafuite(item: Item, entry: RawEntry, spec: SourceSpec) -> dict | None:
    fact = _blank_fact(item, spec)
    evidence: dict = {}
    meta = entry.source_metadata or {}

    claim_status_raw = str(meta.get("claim_status_raw") or "").strip()
    if claim_status_raw:
        fact["Claim_Status_Raw"] = claim_status_raw
        fact["Claim_Status"] = _BLF_STATUS.get(claim_status_raw, "")
        evidence["Claim_Status_Raw"] = claim_status_raw

    data_types_raw = str(meta.get("data_types_raw") or "").strip()
    structured = meta.get("data_types")
    data_types: list[str] = []
    if isinstance(structured, list):
        for value in structured:
            cleaned = str(value or "").strip()
            if cleaned and cleaned not in data_types:
                data_types.append(cleaned)
    elif data_types_raw:
        data_types = _split_list(data_types_raw)
    if data_types:
        fact["Data_Types_JSON"] = _dumps_json(data_types)
        evidence["Data_Types_JSON"] = data_types if isinstance(structured, list) else data_types_raw

    count, unit, raw_count = _parse_count_phrase(entry.summary)
    if not count:
        count, unit, raw_count = _parse_count_phrase(data_types_raw or " ; ".join(data_types))
    if count:
        fact["Affected_Count"] = count
        fact["Affected_Unit"] = unit
        fact["Affected_Count_Raw"] = raw_count
        evidence["Affected_Count_Raw"] = raw_count

    _derive_summary(fact, evidence)
    _apply_blf_summary_certainty(fact)

    source_urls = meta.get("source_urls") or []
    if source_urls:
        fact["Evidence_URLs_JSON"] = _dumps_json(source_urls)
    return _finalize(fact, item, entry, evidence)


_CLAIM_STATUS_MAP = (
    (re.compile(r"\bnon\s+confirm[ée]e?\b", re.I), "unconfirmed"),
    (re.compile(r"\bd[ée]menti[e]?\b", re.I), "denied"),
    (re.compile(r"\bconfirm[ée]e?\b", re.I), "confirmed"),
    (re.compile(r"\brevendiqu[ée]e?\b", re.I), "claimed"),
)
_ACTOR_PATTERNS = tuple(re.compile(pattern, re.I) for pattern in (
    r"revendiqu[ée]e?\s+par\s+le\s+groupe\s+([A-Za-z0-9][\w.&'’+-]{1,40})",
    r"\bgroupe\s+([A-Za-z0-9][\w.&'’+-]{1,40})\s+a\s+revendiqu[ée]",
    r"revendiqu[ée]e?\s+par\s+([A-Za-z0-9][\w.&'’+-]{1,40})",
))
_THIRD_PARTY_PATTERNS = tuple(re.compile(pattern, re.I) for pattern in (
    r"\bvia\s+la\s+plateforme\s+([A-Za-z0-9][\w.&'’+-]{1,40})",
    r"\bvia\s+le\s+prestataire\s+([A-Za-z0-9][\w.&'’+-]{1,40})",
    r"\bvia\s+l['’]h[ée]bergeur\s+([A-Za-z0-9][\w.&'’+-]{1,40})",
))


def _claim_status(text: str) -> tuple[str, str]:
    # Le statut doit qualifier l'événement décrit par la phrase, pas un titre
    # interrogatif ni un rappel historique présent ailleurs dans l'article.
    # Les sources éditoriales mêlent fréquemment « incident 2023 confirmé » et
    # « nouvelle fuite 2026 revendiquée » dans le même contexte.
    historical = re.compile(
        r"\b(?:ancien(?:ne)?|pr[ée]c[ée]dent(?:e)?|rappel|historique|"
        r"[ée]poque|en\s+20(?:1\d|2[0-5]))\b",
        re.I,
    )
    sentences = [part.strip() for part in re.split(r"(?<=[.!?])\s+|\n+", text or "") if part.strip()]
    conditional = re.compile(
        r"\b(?:d[ée]terminer|savoir|v[ée]rifier)\s+si\b|"
        r"\bsi\b.{0,100}\b(?:confirme|contient|concern|comprend|inclut)\w*\b|"
        r"\b(?:pourrait|pourraient|peut|peuvent)\b.{0,80}\b(?:confirmer|contenir|concern|r[ée]cup[ée]r)",
        re.I,
    )
    current = [
        sentence for sentence in sentences
        if "?" not in sentence and not historical.search(sentence) and not conditional.search(sentence)
    ]
    for sentence in current:
        for pattern, canonical in _CLAIM_STATUS_MAP:
            match = pattern.search(sentence)
            if match:
                return canonical, match.group(0)
    return "", ""


def _first_valid_match(patterns, text: str, validator, organisation: str) -> tuple[str, str]:
    for pattern in patterns:
        match = pattern.search(text or "")
        if not match:
            continue
        value = validator(match.group(1), organisation)
        if value:
            return value, match.group(0).strip()
    return "", ""


_FB_SECTOR_RE = re.compile(
    r"\bSecteur\s*[:\-]?\s*([A-Za-zÀ-ÖØ-öø-ÿ/&'’ -]{2,60}?)(?=\s+(?:Fuite|Incident|Qu['’]|Donn[ée]es|Publi[ée]|Victime|Description|Risques?)\b|[.;]|$)",
    re.I,
)


def _native_frenchbreaches_sector(text: str) -> str:
    # Une rubrique sur sa propre ligne appartient à cet article, sans exiger
    # de description métier ni absorber le titre situé sur la ligne suivante.
    line = re.search(r"(?im)^\s*[—–-]?\s*Secteur\s*[:—–-]?\s*([^\n]{2,60})$", text or "")
    match = line or _FB_SECTOR_RE.search(text or "")
    return " ".join(match.group(1).split()).strip(" -:;.") if match else ""


def _apply_semantic_enrichment(fact: dict, evidence: dict, ai_result: dict) -> None:
    initial_access, initial_evidence = _ai_initial_access(ai_result)
    if initial_access:
        fact["Initial_Access"] = initial_access
        evidence["Initial_Access"] = initial_evidence

    summary, summary_evidence = _ai_text(ai_result, "summary")
    if summary:
        fact["Summary"] = summary
        evidence["Summary"] = summary_evidence

    impact, impact_evidence = _ai_text(ai_result, "impact")
    if impact:
        fact["Impact"] = impact
        evidence["Impact"] = impact_evidence

    value, proof = _ai_text(ai_result, "fine_location")
    if value and not fact.get("Fine_Location"):
        fact["Fine_Location"] = value
        evidence["Fine_Location"] = proof

    rich: dict[str, list[dict]] = {}
    incident_summary = ai_result.get("incident_summary") if isinstance(ai_result, dict) else None
    if isinstance(incident_summary, list) and incident_summary:
        rich["incident_summary"] = [
            dict(paragraph) for paragraph in incident_summary
            if isinstance(paragraph, dict) and paragraph.get("value")
        ][:2]
    for key in ("affected_counts", "data_volumes", "file_counts"):
        values = _ordered_ai_evidence(ai_result, key)
        if values:
            rich[key] = values
            evidence[key] = [str(value.get("evidence") or "") for value in values]
    for key in ("affected_systems", "affected_datasets"):
        values = ai_result.get(key) if isinstance(ai_result, dict) else None
        if isinstance(values, list):
            records = [{"value": str(value.get("value") or ""), "status": "confirmed", "evidence": str(value.get("evidence") or "")} for value in values if isinstance(value, dict) and value.get("value")]
            if records:
                rich[key] = records
                evidence[key] = [record["evidence"] for record in records]
    if rich:
        fact["_Rich_Facts"] = rich


def semantic_promotion_gaps(
    fact: dict,
    semantic: source_facts_ai.SemanticExtraction | None,
) -> list[str]:
    """Retourne les champs LLM sourcés qui n'ont pas atteint le fait source.

    Ce contrôle ne devine rien : un champ vide n'est pas un écart. Il protège
    uniquement la frontière cache/SourceFacts/publication contre une perte de
    valeur déjà validée et citée.
    """
    if semantic is None:
        return []
    fields = semantic.fields if isinstance(semantic.fields, dict) else {}
    metadata = _loads_json(str(fact.get("Source_Metadata_JSON") or ""))
    metadata = metadata if isinstance(metadata, dict) else {}
    rich = metadata.get("rich_facts") if isinstance(metadata.get("rich_facts"), dict) else {}
    scalar = {
        "summary": "Summary",
        "initial_access": "Initial_Access",
        "impact": "Impact",
        "threat_actor": "Threat_Actor",
        "third_party": "Third_Party",
        "fine_location": "Fine_Location",
        "data_types": "Data_Types_JSON",
        "activity_description": "Activity_Description",
        "activity_sector_match": "Activity_Sector_Match",
    }
    rich_fields = {
        "incident_summary",
        "affected_counts",
        "data_volumes",
        "file_counts",
        "affected_systems",
        "affected_datasets",
    }
    gaps: list[str] = []
    for key, value in fields.items():
        if value in (None, "", [], {}):
            continue
        if key in scalar and not fact.get(scalar[key]):
            gaps.append(key)
        elif key in rich_fields and not rich.get(key):
            gaps.append(key)
        elif key == "threat_candidate" and not metadata.get("threat_tentative"):
            gaps.append(key)
    return sorted(set(gaps))


def sanitize_source_facts(facts: list[dict]) -> tuple[list[dict], list[str]]:
    """Retire des colonnes publiques les faits contredits par leur preuve.

    Le fait brut reste traçable dans les métadonnées riches ; seules les
    projections susceptibles d'être présentées comme certaines sont vidées.
    Cette passe répare aussi les snapshots antérieurs sans nouvel appel LLM.
    """
    from . import editorial_corrections

    changed: list[str] = editorial_corrections.apply_source_facts(facts)
    for fact in facts:
        evidence = _loads_json(str(fact.get("Evidence_JSON") or ""))
        evidence = evidence if isinstance(evidence, dict) else {}
        metadata = _loads_json(str(fact.get("Source_Metadata_JSON") or ""))
        metadata = metadata if isinstance(metadata, dict) else {}
        semantic_statuses = metadata.get("_source_facts_semantic_status")
        semantic_statuses = dict(semantic_statuses) if isinstance(semantic_statuses, dict) else {}
        touched = False

        if not parse_date(fact.get("Attack_Date")):
            attack_date, attack_evidence = _attack_date_from_rich(metadata)
            if attack_date:
                fact["Attack_Date"] = attack_date
                evidence["Attack_Date"] = attack_evidence
                touched = True

        from .sector_activity import describes_incident
        activity = str(fact.get("Activity_Description") or "")
        if activity and describes_incident(activity):
            metadata["rejected_activity_description"] = {
                "value": activity, "evidence": evidence.get("Activity_Description", ""),
                "reason": "ACTIVITY_NOT_DESCRIBED",
            }
            for column, field in (("Activity_Description", "activity_description"),
                                  ("Activity_Sector_Match", "activity_sector_match")):
                fact[column] = ""
                evidence.pop(column, None)
                semantic_statuses[field] = "rejected_quality"
            touched = True

        actor = str(fact.get("Threat_Actor") or "").strip()
        if actor and not _valid_actor(actor):
            fact["Threat_Actor"] = ""
            evidence.pop("Threat_Actor", None)
            semantic_statuses["threat_actor"] = "rejected_quality"
            touched = True

        access_proof = " ".join(_evidence_values(evidence.get("Initial_Access")))
        if str(fact.get("Initial_Access") or "").strip() and (
            source_facts_ai._INITIAL_ACCESS_UNKNOWN_RE.search(access_proof)
            or source_facts_ai._INITIAL_ACCESS_UNCERTAIN_RE.search(access_proof)
        ):
            fact["Initial_Access"] = ""
            evidence.pop("Initial_Access", None)
            semantic_statuses["initial_access"] = "rejected_quality"
            touched = True

        tentative = metadata.get("threat_tentative")
        if isinstance(tentative, dict):
            value = str(tentative.get("value") or "").strip()
            proof = str(tentative.get("evidence") or "").strip()
            if value and classify_threat(proof) != value:
                metadata.pop("threat_tentative", None)
                semantic_statuses["threat_candidate"] = "rejected_quality"
                touched = True

        if touched:
            if semantic_statuses:
                metadata["_source_facts_semantic_status"] = semantic_statuses
            fact["Evidence_JSON"] = _dumps_json(evidence)
            fact["Source_Metadata_JSON"] = _dumps_json(metadata)
            changed.append(str(fact.get("Item_ID") or ""))
    return facts, sorted({item_id for item_id in changed if item_id})


_INITIAL_ACCESS_LABELS = {
    "phishing": "un hameçonnage",
    "compromised_credentials": "des identifiants compromis",
    "vulnerability_exploitation": "l’exploitation d’une vulnérabilité",
    "remote_access": "un accès distant compromis",
    "third_party": "la compromission d’un tiers",
    "malware": "un logiciel malveillant",
    "other": "un vecteur documenté",
}


def _format_int_fr(value: str) -> str:
    try:
        return f"{int(str(value).strip()):,}".replace(",", " ")
    except (TypeError, ValueError):
        return str(value or "").strip()


def _join_fr(values: list[str]) -> str:
    values = [str(value).strip() for value in values if str(value).strip()]
    if not values:
        return ""
    if len(values) == 1:
        return values[0]
    if len(values) == 2:
        return f"{values[0]} et {values[1]}"
    return ", ".join(values[:-1]) + f" et {values[-1]}"


def _evidence_values(value) -> list[str]:
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, dict):
        return [str(item).strip() for item in value.values() if str(item).strip()]
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def _structured_summary(fact: dict, evidence: dict) -> tuple[str, list[str]]:
    details: list[str] = []
    proofs: list[str] = []

    affected_raw = str(fact.get("Affected_Count_Raw") or "").strip()
    affected_unit = str(fact.get("Affected_Unit") or "").strip()
    if affected_raw:
        details.append(affected_raw)
        proofs.extend(_evidence_values(evidence.get("Affected_Count_Raw")) or [affected_raw])

    file_count = str(fact.get("File_Count") or "").strip()
    if file_count and affected_unit != "files":
        details.append(f"{_format_int_fr(file_count)} fichiers")
        proofs.extend(_evidence_values(evidence.get("File_Count")))

    data_types = _loads_json(str(fact.get("Data_Types_JSON") or ""))
    if not isinstance(data_types, list):
        data_types = []
    data_types = [str(value).strip() for value in data_types if str(value).strip()][:3]
    if data_types:
        proofs.extend(_evidence_values(evidence.get("Data_Types_JSON")))

    # Un seul type de donnée sans volume ni comptage est trop pauvre pour
    # justifier une carte de synthèse. On préfère l'abstention à un doublon UI.
    if not details and len(data_types) < 2:
        return "", []

    if details:
        summary = "Éléments documentés : " + _join_fr(details)
        if data_types:
            summary += " ; données concernées : " + _join_fr(data_types)
        summary += "."
    else:
        summary = "Données concernées : " + _join_fr(data_types) + "."
    return summary, proofs


def _derive_summary(fact: dict, evidence: dict) -> None:
    if fact.get("Source_ID") in source_facts_ai.TARGET_SOURCES:
        return
    if str(fact.get("Summary") or "").strip():
        return
    parts: list[str] = []
    proofs: list[str] = []
    initial = str(fact.get("Initial_Access") or "").strip()
    if initial:
        parts.append(f"Vecteur d’entrée documenté : {_INITIAL_ACCESS_LABELS.get(initial, initial)}.")
        proof = evidence.get("Initial_Access")
        if isinstance(proof, str) and proof:
            proofs.append(proof)
    impact = str(fact.get("Impact") or "").strip()
    if impact:
        parts.append("Impact documenté : " + impact.rstrip(" .") + ".")
        proof = evidence.get("Impact")
        if isinstance(proof, str) and proof:
            proofs.append(proof)
    if parts:
        summary = " ".join(parts)
    else:
        summary, structured_proofs = _structured_summary(fact, evidence)
        proofs.extend(structured_proofs)
        if not summary:
            return
    if len(summary) > source_facts_ai.MAX_SUMMARY_CHARS:
        summary = summary[:source_facts_ai.MAX_SUMMARY_CHARS - 1].rsplit(" ", 1)[0].rstrip(" ,;:") + "…"
    fact["Summary"] = summary
    if proofs:
        evidence["Summary"] = " | ".join(dict.fromkeys(proofs))[:source_facts_ai.MAX_EVIDENCE_CHARS]


from .source_facts_handlers import (
    _CO_INITIAL_ACCESS_PATTERNS,
    _CO_THIRD_PARTY_RE,
    _CO_THREAT_ACTOR_RE,
    _EXTRACTORS,
    _WEBSITE_RE,
    _from_cyberattaque_org,
    _from_frenchbreaches,
    _from_ransomware_live,
    _from_veillellm,
    extract_source_fact,
    merge_source_facts,
)
