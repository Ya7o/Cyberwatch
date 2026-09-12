"""Contrat commun de preuve activité/victime, indépendant du transport LLM."""
from __future__ import annotations

import re

from .normalize import searchable

ACTIVITY_FIELDS = {"activity_description", "activity_sector_match"}
_ACTIVITY = re.compile(
    r"\b(?:specialis\w*|commercialis\w*|vend\w*|vente|boutique|negoce|"
    r"distribu\w*|fabric\w*|produi\w*|production|edite\w*|editeur|developp\w*|"
    r"formation|enseignement|teleconsult\w*|transports?|logistique|reexpedition|"
    r"expedition|livraison|restauration|restaurants?|repas|hebergement|hotell\w*|"
    r"logiciels?|applications?|cloud|stockage|chimie|batiment|second oeuvre|"
    r"agric\w*|horticulture|syndica\w*|represente|accompagne|"
    r"municipalite|organisme public|etablissement public|services? publics?|"
    r"services? municipaux|sante|foncier\w*|"
    r"gestion|assurance|banque|conseil|sport\w*|football|mobilite|immobili\w*|"
    r"repar\w*|plomberie|chauffage|climatisation|fidelis\w*|emploi|tourisme)\b"
)
_THIRD_PARTY_NOUN = r"(?:prestataires?|fournisseurs?|partenaires?|clients?|filiales?|sous traitants?)"
_THIRD_PARTY = re.compile(r"\b" + _THIRD_PARTY_NOUN + r"\b")
#: Un tiers n'est l'auteur de l'activité citée que si la phrase le pose comme
#: tel : lieu ou moyen de l'activité (« chez un fournisseur », « fait appel à
#: un partenaire »), tiers qualifié par son propre métier (« un prestataire
#: chargé de… ») ou victime complément du tiers (« un client de X »). Le nom
#: seul ne suffit pas : « gérer leurs relations clients » décrit une offre.
_THIRD_PARTY_ATTRIBUTION = re.compile(
    r"\b(?:chez|via|par|utilise\w*|fait appel a|recours a|client de|confie\w*(?: \w+){0,3} a)"
    r"(?: \w+){0,4}? " + _THIRD_PARTY_NOUN + r"\b"
    r"|\b(?:son|sa|ses|leurs?|un|une|le|la|l|des|du|d un|l un de ses|l un des) "
    + _THIRD_PARTY_NOUN
    + r"(?: \w+){0,2}? (?:charge\w*|specialise\w*|qui|dont|en charge|responsable\w*)\b"
)
_THIRD_PARTY_OWNER = re.compile(r"\b" + _THIRD_PARTY_NOUN + r" (?:de|d|du|des)$")
#: Une offre adressée à un marché décrit un métier même sans terme du lexique
#: `_ACTIVITY` : « fournit aux entreprises des outils… », « propose une
#: plateforme destinée aux clients professionnels ». Le destinataire est un
#: marché, jamais les personnes touchées : « aux clients concernés » n'en est pas un.
_MARKET = (
    r"(?:entreprises|professionnels|particuliers|collectivites|organisations|administrations|"
    r"pme|tpe|commercants|marques|clients professionnels)"
)
_OFFERING = r"(?:outils?|solutions?|plateformes?|services?|produits?|logiciels?)"
_OFFER = re.compile(
    r"\b" + _OFFERING + r"(?: \w+){0,3}? (?:destine\w* aux|a destination des|aux|pour les) "
    + _MARKET + r"\b"
    r"|\b(?:aux|a destination des) " + _MARKET + r" (?:des|de|d|un|une|les) " + _OFFERING + r"\b"
)
#: Désignations institutionnelles admises comme sujet à la place du nom de
#: la victime. Volontairement limitée : « la mairie » et « la municipalité »
#: sont les deux anaphores que la collecte RUN-20260910T125214 a fait
#: apparaître, et chacune reste conditionnée à un rattachement explicite.
_INSTITUTIONAL_SUBJECT = re.compile(
    r"^(?:la |l )?(?:mairie|municipalite)(?:\s+d(?:e|u|es)?\s+\w+(?:-\w+)*)?\b"
)
#: Une collectivité *nommée* dans la fenêtre de rattachement. Un « la mairie »
#: sans nom n'en est pas une : c'est précisément l'anaphore à résoudre.
_NAMED_COLLECTIVITY = re.compile(
    r"\b(?:[Mm]airie|[Mm]unicipalité|[Cc]ommune|[Vv]ille|[Cc]ommunauté\s+d['’]agglomération"
    r"|[Cc]ommunauté\s+de\s+communes|[Mm]étropole|[Dd]épartement|[Rr]égion|[Pp]réfecture)"
    r"\s+(?:de\s+|du\s+|des\s+|d['’])?"
    r"([A-ZÉÈÀÂÎÔÛÇ][\w'’-]*(?:[- ][A-ZÉÈÀÂÎÔÛÇ][\w'’-]*)*)"
)
#: Articles et préfixes génériques retirés pour isoler le nom propre d'une
#: collectivité : « Le Tampon » et « Ville du Tampon » désignent « tampon ».
_ORG_PREFIXES = re.compile(
    r"^(?:la |le |les |l |ville de |ville du |ville d |commune de |commune du |commune d |"
    r"mairie de |mairie du |mairie d |municipalite de |municipalite du |municipalite d )+"
)
_PREFIX = re.compile(
    r"(?:(?:la |le |l |une |un )?(?:societe|entreprise|reseau|plateforme) ?|"
    r"(?:une |la )?(?:importante |nouvelle )?(?:fuite(?: de donnees)?|cyberattaque|attaque) "
    r"(?:visant|attribuee a|contre|touche|touchant)|la|le|l)?$"
)
_SUBJECT = re.compile(
    r"^(?:est|sont|etait|entreprise|societe|reseau|plateforme|service|dispositif|"
    r"cooperative|organisme|etablissement|association|groupe|specialis\w*|"
    r"commercialis\w*|vend\w*|propose|fournit|fournissent|permet|intervient|exerce|assure|"
    r"developp\w*|edite\w*|editeur|fabrique|represente|accompagne|"
    r"transporte|distribue|gere|informe|confirme|le service|la plateforme)\b"
)
#: Une forme juridique postposée n'est pas le prédicat de la phrase : « Salt
#: Mobile SA est un opérateur… » a le même sujet que « Salt Mobile est un
#: opérateur… ». Sans ce retrait, le corps analysé commence par « sa », que
#: `_SUBJECT` ne reconnaît pas, et une preuve littérale valide est perdue. Le
#: retrait n'a lieu qu'en TÊTE de corps, juste après le nom de la victime :
#: `as`, `se` et `ab` sont des mots courants ailleurs dans la phrase.
_LEGAL_LEAD = re.compile(
    r"^(?:sa|sas|sasu|sarl|scop|spa|ag|gmbh|ltd|llc|inc|plc|bv|nv|se|srl|ab|oy|as|kg)\b\s*"
)
#: Le récit de la victimisation reste hors du contrat de preuve, y compris par
#: le chemin générique ci-dessous : « est une entreprise touchée par la
#: cyberattaque » décrit l'incident, pas le métier.
_INCIDENT_TERM = re.compile(
    r"\b(?:victimes?|cibles?|ciblee?s?|touchee?s?|concernee?s?|piratee?s?|attaquee?s?|"
    r"attaquants?|compromis\w*|intrusion|cyberattaques?|failles?|fuites?|rancongiciels?|"
    r"ransomware|incidents?|breche\w*|violation\w*|subi\w*|exfiltr\w*|revendiqu\w*)\b"
)
#: L'appartenance à un groupe n'est pas une activité. La règle est déjà portée
#: par le prompt d'extraction ; elle est répétée ici parce que le chemin
#: générique contourne le lexique `_ACTIVITY` qui l'appliquait implicitement.
_MEMBERSHIP = re.compile(
    r"\b(?:filiales?|appartient|appartenant|detenue?|propriete|marque du groupe)\b"
)
#: Une tête de phrase purement catégorielle (« est une société ») ne dit rien
#: du métier : elle n'est retenue que complétée (« une société DE transport »).
_GENERIC_HEAD = re.compile(
    r"^(?:est|sont)\s+(?:un|une|des)\s+(?:societes?|entreprises?|groupes?|structures?|"
    r"organisations?|firmes?|compagnies?|marques?|enseignes?|pme|tpe|start up|startups?|"
    r"acteurs?)\b"
)
#: Déterminant INDÉFINI seul : « est un opérateur de… » prédique une identité
#: métier, « est l'une des principales communes » est un partitif qui situe la
#: victime dans un ensemble sans la décrire.
_PREDICATIVE = re.compile(r"^(?:est|sont)\s+(?:un|une|des)\s+\w+")
_COMPLEMENT = re.compile(r"\b(?:de|d|en|dans|pour|specialis\w*)\b\s+\w+")


def business_predicate(body: str) -> bool:
    """Identité métier prédiquée, quand aucun terme du lexique fermé ne figure.

    `_ACTIVITY` est une liste d'activités réellement observées : elle ne peut
    pas couvrir l'ensemble des métiers — aucun terme télécom n'y figure, d'où
    le rejet mesuré de « Salt Mobile SA est un opérateur suisse de téléphonie
    mobile ». Ce chemin accepte la *forme grammaticale* de l'identité métier,
    « X est un <nom> … », plutôt que son vocabulaire, sous trois gardes : pas
    de récit d'incident, pas de simple appartenance à un groupe, pas de tête
    catégorielle vide de complément.

    Volontairement limité à la copule. Une variante verbale (verbe conjugué +
    complément d'objet, pour couvrir « conçoit des systèmes… ») a été mesurée
    sur le corpus : elle accepte « Brevo confirme une faille… » et « Printemps
    informé le 20 août ». Elle est écartée et ne doit pas être réintroduite.
    """
    if _INCIDENT_TERM.search(body) or _MEMBERSHIP.search(body):
        return False
    generic = _GENERIC_HEAD.search(body)
    if generic:
        return bool(_COMPLEMENT.search(body[generic.end():]))
    return bool(_PREDICATIVE.search(body))


def organisation_span(organisation: str, evidence: str) -> tuple[int, int] | None:
    """Normalized spelling, including spaces and a final plural ``s`` variant."""
    org = searchable(organisation)
    proof = searchable(evidence)
    if not org:
        return None
    compact = org.replace(" ", "")
    base = compact[:-1] if len(compact) >= 6 and compact.endswith("s") else compact
    plural = "s?" if len(base) >= 6 else ""
    pattern = r"(?<!\w)" + r"\s*".join(re.escape(c) for c in base) + plural + r"(?!\w)"
    match = re.search(pattern, proof)
    return match.span() if match else None


def describes_incident(value: str) -> bool:
    """Un récit de victimisation ne décrit pas le métier de l'organisation."""
    normalized = searchable(value)
    event = re.search(r"\b(?:est|etait|a ete) (?:victime|touchee?|concernee?|affectee?)\b", normalized)
    # Une apposition métier avant le récit reste une preuve d'activité :
    # « Acme, plateforme dédiée à l'emploi, est concernée » est exploitable.
    return bool(event and not _ACTIVITY.search(normalized[:event.start()]))


def supported_activity(organisation: str, value: str, evidence: str) -> bool:
    proof = searchable(evidence)
    segments = re.split(r"(?<=[.!?;])\s+|\n+", evidence)
    if len(segments) > 1:
        return any(supported_activity(organisation, value, part) for part in segments if part.strip())
    span = organisation_span(organisation, evidence)
    if span is None:
        # Keep the existing, controlled institutional acronym contract.
        from .source_facts import _activity_evidence_matches_organisation
        if not _activity_evidence_matches_organisation(organisation, evidence):
            return False
        body = proof
    else:
        if _THIRD_PARTY.search(proof[:span[0]]):
            return False
        body = _LEGAL_LEAD.sub("", proof[span[1]:].strip())
        if not _SUBJECT.search(body):
            return False
    if describes_incident(value):
        return False
    if re.search(r"\b(?:son|ses|le|un|du|d un) (?:prestataire|fournisseur|partenaire|client)\b", body):
        return False
    if re.search(r"\b(?:utilise|fait appel|client de|via)\b", body):
        return False
    return bool(value and (_ACTIVITY.search(body) or _OFFER.search(body)
                           or business_predicate(body)))


def contextual_proof(organisation: str, evidence: str, context: str) -> str:
    """Étend la citation à sa phrase si la victime en est le sujet explicite."""
    org = searchable(organisation)
    needle = searchable(evidence)
    if not org or not needle:
        return ""
    for sentence in re.split(r"(?<=[.!?;])\s+|\n+", context):
        normalized = searchable(sentence)
        if needle not in normalized or len(sentence) > 300:
            continue
        span = organisation_span(organisation, sentence)
        if span is None or not _PREFIX.fullmatch(normalized[:span[0]].strip()):
            continue
        if supported_activity(organisation, sentence, sentence):
            return sentence.strip()
    return ""


def activity_from_text(organisation: str, *texts: str) -> tuple[str, str]:
    from . import config
    from .sector import classify_sector_activity

    candidates = []
    for text in texts:
        for sentence in re.split(r"(?<=[.!?;])\s+|\n+", text or ""):
            proof = contextual_proof(organisation, sentence, sentence)
            if proof:
                # Prefer a classifiable, explicit business activity over an
                # ambiguous teaser. Keep source order on equally strong proofs.
                known = classify_sector_activity(proof) != config.SECTOR_UNKNOWN
                concrete = bool(re.search(r"\b(?:commercialis\w*|vend\w*|fabrique|edite|intervient)\b", searchable(proof)))
                candidates.append(((known, concrete), proof))
    if not candidates:
        return "", ""
    proof = max(candidates, key=lambda pair: pair[0])[1]
    return proof, proof


def names_third_party(organisation: str, evidence: str) -> bool:
    """La citation attribue l'activité décrite à un prestataire ou un client.

    La seule présence d'un nom de tiers n'attribue rien : il faut que la phrase
    fasse du tiers le sujet, le lieu ou le moyen de l'activité, ou de la
    victime son complément.
    """
    proof = searchable(evidence)
    if _THIRD_PARTY_ATTRIBUTION.search(proof):
        return True
    span = organisation_span(organisation, evidence)
    return bool(span and _THIRD_PARTY_OWNER.search(proof[:span[0]].strip()))


def victim_is_identifiable(organisation: str, evidence: str) -> bool:
    """La citation désigne la victime, par son nom ou par le contrat d'acronymes."""
    if organisation_span(organisation, evidence) is not None:
        return True
    from .source_facts import _activity_evidence_matches_organisation

    return bool(_activity_evidence_matches_organisation(organisation, evidence))


def organisation_core(organisation: str) -> str:
    """Nom propre d'une collectivité, articles et préfixes génériques retirés."""
    core = _ORG_PREFIXES.sub("", searchable(organisation)).strip()
    return core if len(core) >= 4 else ""


def _names_victim(organisation: str, text: str) -> bool:
    if organisation_span(organisation, text) is not None:
        return True
    core = organisation_core(organisation)
    return bool(core and re.search(rf"(?<!\w){re.escape(core)}s?(?!\w)", searchable(text)))


def _competing_collectivity(organisation: str, window: str) -> bool:
    """Une autre collectivité est nommée dans la fenêtre de rattachement."""
    return any(
        not _names_victim(organisation, match.group(1))
        for match in _NAMED_COLLECTIVITY.finditer(window)
    )


def institutional_proof(organisation: str, evidence: str, context: str) -> str:
    """Citation dont « la mairie » ou « la municipalité » désigne bien la victime.

    Le rattachement doit être établi par la phrase elle-même ou par celle qui la
    précède immédiatement, et la fenêtre ne doit nommer aucune autre
    collectivité : deux communes citées côte à côte rendent l'anaphore
    indécidable, et une activité mal attribuée vaut moins qu'une abstention.
    """
    needle = searchable(evidence)
    if not needle or not searchable(organisation):
        return ""
    sentences = [part for part in re.split(r"(?<=[.!?;])\s+|\n+", context) if part.strip()]
    for index, sentence in enumerate(sentences):
        normalized = searchable(sentence)
        if needle not in normalized or len(sentence) > 300:
            continue
        subject = _INSTITUTIONAL_SUBJECT.match(normalized)
        if not subject:
            continue
        body = normalized[subject.end():].strip()
        if not _SUBJECT.search(body) or not _ACTIVITY.search(body):
            continue
        window = " ".join(sentences[max(0, index - 1):index + 1])
        if not _names_victim(organisation, window):
            continue
        if _competing_collectivity(organisation, window):
            continue
        return sentence.strip()
    return ""
