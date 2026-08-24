"""Extraction multi-faits de tous les articles Cyberattaque.org.

Le premier passage est déterministe. Un second passage LLM, optionnel et validé
mécaniquement, n'est déclenché que pour les articles riches/ambigus. Les faits
restent auxiliaires dans source_metadata et ne modifient jamais les champs
canoniques Threat/Sector/Location.
"""
from __future__ import annotations

import re

from ..normalize import searchable
from .cyberattaque_org import CyberattaqueOrgCollector
from . import cyberattaque_semantic
from .base import entry_allowed_before_enrichment

STATUSES = {"confirmed", "reported", "claimed", "hypothesis", "denied", "negated", "unknown"}
_STATUS_PRIORITY = {"confirmed": 7, "reported": 6, "claimed": 5, "hypothesis": 3, "denied": 2, "negated": 1, "unknown": 0}
_HYPOTHESIS = re.compile(r"\b(?:pourrait|pourraient|susceptible|potentiellement|possible|hypoth[èe]se|serait|seraient|aurait|auraient)\b", re.I)
_NEGATION = re.compile(r"\b(?:n['’ ](?:a|ont|est|sont)\s+pas|ne\s+.{0,40}\s+pas|aucun(?:e)?|sans\s+(?:preuve|confirmation)|non\s+touch[ée]|pas\s+touch[ée])\b", re.I)
_DENIED = re.compile(r"\b(?:d[ée]ment|d[ée]menti|nie|nient|conteste|contestent)\b", re.I)
_CONFIRMED = re.compile(r"\b(?:confirme|confirm[ée]e?s?|reconna[iî]t|reconnu|admet|admis|officiellement)\b", re.I)
_CLAIMED = re.compile(r"\b(?:revendiqu[ée]e?s?|affirme|affirment|dit\s+avoir|selon\s+(?:l['’]?attaquant|le\s+groupe|les\s+pirates?))\b", re.I)
_REPORTED = re.compile(r"\b(?:rapport[ée]e?s?|indique|indiquent|selon\s+(?:le|la|les|un|une)\s+)\b", re.I)

_COUNT_RE = re.compile(r"(?P<number>\d[\d\s\u202f.,]*\d|\d)\s*(?P<scale>millions?|milliers?|mille)?\s*(?:de\s+|d['’])?\s*(?P<unit>comptes?|personnes?|utilisateurs?|clients?|lignes?|enregistrements?|dossiers?|fichiers?|victimes?|agents?|employ[ée]s?)\b", re.I)
_UNIT_MAP = {
    "compte":"accounts","comptes":"accounts","personne":"people","personnes":"people","victime":"people","victimes":"people","agent":"people","agents":"people","employe":"people","employes":"people","employee":"people","employees":"people",
    "utilisateur":"users","utilisateurs":"users","client":"clients","clients":"clients","ligne":"records","lignes":"records","enregistrement":"records","enregistrements":"records","dossier":"files","dossiers":"files","fichier":"files","fichiers":"files",
}
_VOLUME_RE = re.compile(r"(?P<number>\d+(?:[.,]\d+)?)\s*(?P<unit>Ko|Mo|Go|To|KB|MB|GB|TB)\b", re.I)
_DATE_RE = re.compile(r"\b(?:le\s+)?(?P<day>\d{1,2})\s+(?P<month>janvier|f[ée]vrier|mars|avril|mai|juin|juillet|ao[uû]t|septembre|octobre|novembre|d[ée]cembre)\s+(?P<year>20\d{2})\b", re.I)
_MONTHS = {"janvier":1,"fevrier":2,"mars":3,"avril":4,"mai":5,"juin":6,"juillet":7,"aout":8,"septembre":9,"octobre":10,"novembre":11,"decembre":12}
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)

_DATA_TYPES = (
    ("adresses e-mail", re.compile(r"\b(?:adresses?\s+)?e-?mails?|courriels?\b", re.I)),
    ("numéros de téléphone", re.compile(r"\b(?:num[ée]ros?\s+de\s+)?t[ée]l[ée]phones?\b", re.I)),
    ("adresses postales", re.compile(r"\badresses?\s+(?:postales?|physiques?)\b", re.I)),
    ("noms et prénoms", re.compile(r"\bnoms?\b.{0,30}\bpr[ée]noms?\b|\bpr[ée]noms?\b", re.I)),
    ("dates de naissance", re.compile(r"\bdates?\s+de\s+naissance\b", re.I)),
    ("identifiants", re.compile(r"\bidentifiants?(?:\s+de\s+connexion)?\b", re.I)),
    ("mots de passe", re.compile(r"\bmots?\s+de\s+passe|passwords?\b", re.I)),
    ("données bancaires", re.compile(r"\b(?:donn[ée]es?|coordonn[ée]es?)\s+bancaires?|\bIBAN\b|\bRIB\b", re.I)),
    ("données de santé", re.compile(r"\bdonn[ée]es?\s+(?:de\s+sant[ée]|m[ée]dicales?)\b", re.I)),
    ("pièces d'identité", re.compile(r"\bpi[èe]ces?\s+d['’ ]identit[ée]|passeports?\b", re.I)),
    ("données cadastrales", re.compile(r"\bdonn[ée]es\s+cadastrales\b", re.I)),
    ("données fiscales", re.compile(r"\bdonn[ée]es\s+fiscales\b", re.I)),
    ("données RH", re.compile(r"\b(?:donn[ée]es?|documents?)\s+(?:RH|ressources\s+humaines)\b", re.I)),
    ("secrets cloud", re.compile(r"\b(?:secret|cl[ée]|token|credentials?)\s+(?:AWS|Azure|cloud)\b", re.I)),
)
_SCOPE_PATTERNS = (
    ("SPDC", re.compile(r"\b(?:Serveur\s+Professionnel\s+de\s+Donn[ée]es\s+Cadastrales|SPDC)\b", re.I), "system"),
    ("Pilot / pilot.sport2000.fr", re.compile(r"\bpilot\.sport2000\.fr\b|\b(?:outil|application|plateforme|syst[èe]me)\s+(?:interne\s+)?Pilot\b", re.I), "system"),
    ("cloud.numerique.gouv.fr", re.compile(r"\bcloud\.numerique\.gouv\.fr\b", re.I), "system"),
    ("Metabase", re.compile(r"\bMetabase\b", re.I), "system"),
    ("WordPress", re.compile(r"\bWordPress\b", re.I), "system"),
    ("ERP", re.compile(r"\bERP\b", re.I), "system"),
    ("données cadastrales", re.compile(r"\bdonn[ée]es\s+cadastrales\b", re.I), "dataset"),
    ("successions vacantes", re.compile(r"\bsuccessions?\s+vacantes?\b", re.I), "dataset"),
    ("données fiscales", re.compile(r"\bdonn[ée]es\s+fiscales\b", re.I), "dataset"),
    ("réservations", re.compile(r"\br[ée]servations?\b", re.I), "dataset"),
    ("données clients", re.compile(r"\bdonn[ée]es\s+clients?\b", re.I), "dataset"),
)
_EVENT_TRIGGER = re.compile(r"\b(?:attaque|cyberattaque|intrusion|compromission|fuite|exfiltr|vol[ée]?|publi|revendiqu|confirm|d[ée]tect|notifi|corrig|restaur|isol|chiffr|ransomware|secret|vuln[ée]rabilit)\w*\b", re.I)
_THIRD_PARTY = re.compile(r"\b(?:via|chez|par)\s+(?:le|la|l['’])?\s*(?:prestataire|fournisseur|h[ée]bergeur|sous[- ]traitant|plateforme)\s+([A-Z][\w.&'’+-]{2,60})", re.I)
_ACTOR = re.compile(r"\b(?:groupe|collectif|gang)\s+([A-Z0-9][\w.&'’+-]{2,60})\b", re.I)


def _sentences(text: str) -> list[str]:
    return [p.strip() for p in re.split(r"(?<=[.!?])\s+|\n+", text or "") if p.strip()]


def _status(sentence: str) -> str:
    if _NEGATION.search(sentence): return "negated"
    if _DENIED.search(sentence): return "denied"
    if _HYPOTHESIS.search(sentence): return "hypothesis"
    if _CONFIRMED.search(sentence): return "confirmed"
    if _CLAIMED.search(sentence): return "claimed"
    if _REPORTED.search(sentence): return "reported"
    return "unknown"


def _date(sentence: str) -> str:
    m = _DATE_RE.search(sentence or "")
    if not m: return ""
    month = _MONTHS.get(searchable(m.group("month")))
    return f"{int(m.group('year')):04d}-{month:02d}-{int(m.group('day')):02d}" if month else ""


def _number(raw: str, scale: str) -> int | None:
    cleaned = (raw or "").replace("\u202f", "").replace(" ", "")
    scale = searchable(scale or "")
    try:
        if scale.startswith("million"): return int(round(float(cleaned.replace(",", "."))*1_000_000))
        if scale.startswith("millier") or scale == "mille": return int(round(float(cleaned.replace(",", "."))*1_000))
        return int(cleaned.replace(".", "").replace(",", ""))
    except ValueError:
        return None


def _scope(sentence: str) -> str:
    for label, pattern, _ in _SCOPE_PATTERNS:
        if pattern.search(sentence): return label
    return ""


def _dedupe(rows: list[dict], keys: tuple[str, ...]) -> list[dict]:
    out, seen = [], set()
    for row in rows:
        key = tuple(searchable(str(row.get(k) or "")) for k in keys)
        if key in seen: continue
        seen.add(key); out.append(row)
    return out


def _extract_counts(sentences: list[str]) -> list[dict]:
    rows = []
    for sentence in sentences:
        for m in _COUNT_RE.finditer(sentence):
            value = _number(m.group("number"), m.group("scale") or "")
            unit = _UNIT_MAP.get(searchable(m.group("unit")))
            if value is None or not unit: continue
            rows.append({"value":value,"unit":unit,"raw":m.group(0).strip(),"status":_status(sentence),"scope":_scope(sentence),"date":_date(sentence),"evidence":sentence[:420]})
    rows = _dedupe(rows, ("value","unit","scope","status"))
    rows.sort(key=lambda r:(-_STATUS_PRIORITY.get(r["status"],0),-int(r["value"])))
    return rows


def _extract_volumes(sentences: list[str]) -> list[dict]:
    rows=[]
    for sentence in sentences:
        for m in _VOLUME_RE.finditer(sentence):
            rows.append({"value":float(m.group("number").replace(",",".")),"unit":m.group("unit").upper(),"status":_status(sentence),"scope":_scope(sentence),"date":_date(sentence),"evidence":sentence[:420]})
    return _dedupe(rows,("value","unit","scope","status"))


def _extract_data_types(sentences: list[str]) -> list[dict]:
    rows=[]
    for sentence in sentences:
        status=_status(sentence)
        # Un type cité sans relation à l'incident n'est pas accepté.
        if not re.search(r"\b(?:donn[ée]es?|fuite|vol|expos|comprom|exfiltr|publi|concern|contiend|inclu)\w*\b", sentence, re.I): continue
        for label, pattern in _DATA_TYPES:
            if pattern.search(sentence): rows.append({"value":label,"status":status,"date":_date(sentence),"evidence":sentence[:420]})
    return _dedupe(rows,("value","status"))


def _extract_scopes(sentences: list[str]) -> tuple[list[dict],list[dict]]:
    systems,datasets=[],[]
    for sentence in sentences:
        for label,pattern,kind in _SCOPE_PATTERNS:
            if pattern.search(sentence):
                row={"value":label,"status":_status(sentence),"date":_date(sentence),"evidence":sentence[:420]}
                (systems if kind=="system" else datasets).append(row)
    return _dedupe(systems,("value","status")),_dedupe(datasets,("value","status"))


def _extract_timeline(sentences: list[str]) -> list[dict]:
    rows=[]
    for sentence in sentences:
        date=_date(sentence)
        if date and _EVENT_TRIGGER.search(sentence): rows.append({"date":date,"status":_status(sentence),"event":sentence[:240],"evidence":sentence[:420]})
    return _dedupe(rows,("date","event"))[:20]


def _extract_relations(sentences: list[str]) -> list[dict]:
    rows=[]
    for sentence in sentences:
        actor=_ACTOR.search(sentence)
        if actor and _CLAIMED.search(sentence): rows.append({"subject":actor.group(1),"relation":"claimed_by","object":"incident","status":"claimed","evidence":sentence[:420]})
        third=_THIRD_PARTY.search(sentence)
        if third: rows.append({"subject":"victime","relation":"compromised_via","object":third.group(1).strip(),"status":_status(sentence),"evidence":sentence[:420]})
    return _dedupe(rows,("subject","relation","object","status"))


def _merge_semantic(base: dict, semantic: dict) -> None:
    for key in ("claims","timeline","relations"):
        values=semantic.get(key)
        if not isinstance(values,list): continue
        base[key]=_dedupe((base.get(key) or [])+values, ("type","value","status","evidence") if key=="claims" else (("date","event") if key=="timeline" else ("subject","relation","object","status")))
    for claim in semantic.get("claims") or []:
        ctype=claim.get("type")
        if ctype=="affected_count" and isinstance(claim.get("value"),(int,float)):
            base["affected_counts"].append({"value":int(claim["value"]),"unit":str(claim.get("unit") or "records"),"raw":"","status":claim.get("status","unknown"),"scope":claim.get("scope",""),"date":claim.get("date",""),"evidence":claim.get("evidence","")})
        elif ctype=="data_volume" and isinstance(claim.get("value"),(int,float)):
            base["data_volumes"].append({"value":claim["value"],"unit":claim.get("unit",""),"status":claim.get("status","unknown"),"scope":claim.get("scope",""),"date":claim.get("date",""),"evidence":claim.get("evidence","")})
        elif ctype=="data_type" and claim.get("value"):
            base["data_types"].append({"value":str(claim["value"]),"status":claim.get("status","unknown"),"date":claim.get("date",""),"evidence":claim.get("evidence","")})
        elif ctype=="system" and claim.get("value"):
            base["affected_systems"].append({"value":str(claim["value"]),"status":claim.get("status","unknown"),"date":claim.get("date",""),"evidence":claim.get("evidence","")})
        elif ctype=="dataset" and claim.get("value"):
            base["affected_datasets"].append({"value":str(claim["value"]),"status":claim.get("status","unknown"),"date":claim.get("date",""),"evidence":claim.get("evidence","")})
    for key in ("affected_counts","data_volumes","data_types","affected_systems","affected_datasets"):
        base[key]=_dedupe(base[key],("value","unit","status","scope") if key in {"affected_counts","data_volumes"} else ("value","status"))


def _claims_from_deterministic(base: dict) -> list[dict]:
    claims=[]
    for row in base["affected_counts"]: claims.append({"type":"affected_count",**{k:v for k,v in row.items() if k!="raw"}})
    for row in base["data_volumes"]: claims.append({"type":"data_volume",**row})
    for row in base["data_types"]: claims.append({"type":"data_type",**row})
    for row in base["affected_systems"]: claims.append({"type":"system",**row})
    for row in base["affected_datasets"]: claims.append({"type":"dataset",**row})
    return claims


def enrich_entry_metadata(entry) -> None:
    text="\n".join(part for part in (entry.title,entry.summary,entry.content) if part)
    sentences=_sentences(text)
    systems,datasets=_extract_scopes(sentences)
    base={
        "version":"2",
        "affected_counts":_extract_counts(sentences),
        "data_volumes":_extract_volumes(sentences),
        "data_types":_extract_data_types(sentences),
        "affected_systems":systems,
        "affected_datasets":datasets,
        "timeline":_extract_timeline(sentences),
        "relations":_extract_relations(sentences),
        "vulnerabilities":[{"value":v.upper(),"status":"reported","evidence":next((s[:420] for s in sentences if v.lower() in s.lower()),"")} for v in sorted(set(_CVE_RE.findall(text)))],
    }
    base["claims"]=_claims_from_deterministic(base)
    semantic=cyberattaque_semantic.enrich(text,base)
    if semantic:
        _merge_semantic(base,semantic)
        base["semantic"]={"used":True,"model":semantic.get("model", ""),"prompt_version":semantic.get("prompt_version","")}
    else:
        base["semantic"]={"used":False}
    base["profile"]={
        "chars":len(text),"sentences":len(sentences),"numbers":len(_COUNT_RE.findall(text)),"dates":len(_DATE_RE.findall(text)),
        "claims":len(base["claims"]),"hypotheses":sum(1 for c in base["claims"] if c.get("status")=="hypothesis"),
    }
    if not any(base.get(k) for k in ("claims","timeline","relations","affected_systems","affected_datasets","data_volumes","data_types","vulnerabilities")): return
    metadata=dict(entry.source_metadata or {})
    metadata["rich_facts"]=base
    entry.source_metadata=metadata


class CyberattaqueRichCollector(CyberattaqueOrgCollector):
    name="cyberattaque_org"
    def collect(self,client,spec,window):
        result=super().collect(client,spec,window)
        for entry in result.entries:
            if entry_allowed_before_enrichment(spec, entry):
                enrich_entry_metadata(entry)
        return result
