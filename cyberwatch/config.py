"""Constantes et tables de référence de la méthode OBS-FR-OI.

Toutes les valeurs normatives de la méthodologie sont regroupées ici afin qu'une
évolution de méthode se traduise par un diff lisible dans un seul fichier.
"""

from __future__ import annotations

METHOD_ID = "OBS-FR-OI-SIMPLE-SOURCING-2"

# --------------------------------------------------------------------------
# Périmètre géographique (§10)
# --------------------------------------------------------------------------

LOC_FRANCE = "France métropolitaine"
LOC_REUNION = "La Réunion"
LOC_MAYOTTE = "Mayotte"
LOC_MAURICE = "Maurice"
LOC_MADAGASCAR = "Madagascar"
LOC_SEYCHELLES = "Seychelles"
LOC_COMORES = "Comores"
LOC_INCONNU = "Inconnu"

LOCATIONS = [
    LOC_FRANCE,
    LOC_REUNION,
    LOC_MAYOTTE,
    LOC_MAURICE,
    LOC_MADAGASCAR,
    LOC_SEYCHELLES,
    LOC_COMORES,
    LOC_INCONNU,
]

# Territoires du focus « Réunion / Mayotte » du dashboard.
FOCUS_LOCATIONS = [LOC_REUNION, LOC_MAYOTTE]

# --------------------------------------------------------------------------
# Taxonomie des menaces (§8) — l'ordre de la liste EST l'ordre de priorité.
# Les motifs sont écrits sans accents : le texte est désaccentué avant test.
# --------------------------------------------------------------------------

THREAT_RANSOMWARE = "Ransomware"
THREAT_DDOS = "DDoS"
THREAT_MALWARE = "Malware"
THREAT_ACCOUNT = "Compromission de compte / messagerie"
THREAT_INTRUSION = "Intrusion"
THREAT_LEAK = "Fuite de données"
THREAT_PHISHING = "Phishing / fraude"
THREAT_THIRD_PARTY = "Incident tiers"
THREAT_OTHER = "Autre cyber"
THREAT_UNKNOWN = "Inconnu"

THREATS = [
    THREAT_RANSOMWARE,
    THREAT_DDOS,
    THREAT_MALWARE,
    THREAT_ACCOUNT,
    THREAT_INTRUSION,
    THREAT_LEAK,
    THREAT_PHISHING,
    THREAT_THIRD_PARTY,
    THREAT_OTHER,
    THREAT_UNKNOWN,
]

# Groupes ransomware fréquemment cités : leur seule mention qualifie la menace.
RANSOMWARE_GROUPS = [
    "lockbit", "alphv", "blackcat", "clop", "cl0p", "play", "akira", "8base",
    "medusa", "rhysida", "black basta", "royal", "bianlian", "hunters",
    "qilin", "inc ransom", "ransomhub", "cactus", "noescape", "everest",
    "stormous", "trigona", "vice society", "conti", "revil", "hive",
    "blackbyte", "daixin", "dragonforce", "safepay", "brain cipher",
]

THREAT_RULES: list[tuple[str, list[str]]] = [
    (THREAT_RANSOMWARE, [
        "ransomware", "rancongiciel", "rancon", "ransom",
        "chiffrement des donnees", "donnees chiffrees",
    ] + RANSOMWARE_GROUPS),
    (THREAT_DDOS, [
        "ddos", "d dos", "deni de service", "denial of service",
        "attaque par saturation",
    ]),
    (THREAT_MALWARE, [
        "malware", "logiciel malveillant", "virus informatique", "trojan",
        "cheval de troie", "spyware", "infostealer", "rootkit", "botnet",
    ]),
    (THREAT_ACCOUNT, [
        "messagerie compromise", "compte compromis", "comptes compromis",
        "boite mail piratee", "compte pirate", "usurpation de compte",
        "identifiants voles", "credential", "account takeover",
        "compromission de la messagerie", "piratage de compte",
    ]),
    (THREAT_INTRUSION, [
        "intrusion", "acces non autorise", "compromission du systeme",
        "compromission si", "systeme d information compromis",
        "unauthorized access", "piratage informatique", "cyberattaque",
        "cyber attaque", "attaque informatique", "hacking", "piratage",
        "attaque par un groupe",
    ]),
    (THREAT_LEAK, [
        "fuite de donnees", "fuite massive", "exfiltration", "data breach",
        "donnees exposees", "donnees personnelles exposees", "base de donnees exposee",
        "vol de donnees", "donnees derobees", "leak", "violation de donnees",
        "mis en vente", "mise en vente", "en vente", "donnees diffusees",
        "diffusees publiquement", "donnees revendiquees", "documents exposes",
        "comptes exposes", "utilisateurs exposes", "coordonnees exposees",
        "pieces d identite exposees",
    ]),
    (THREAT_PHISHING, [
        "phishing", "hameconnage", "fraude", "arnaque", "escroquerie",
        "scam", "smishing", "faux site", "usurpation d identite",
    ]),
    (THREAT_THIRD_PARTY, [
        "prestataire", "sous traitant", "fournisseur", "chez son hebergeur",
        "third party", "supply chain", "chaine d approvisionnement",
    ]),
]

# Vocabulaire prouvant qu'un texte parle bien de cyber (sinon : hors périmètre).
#
# Ces marqueurs doivent rester discriminants. Des termes trop généraux
# (« numérique », « données », « informatique » seuls) laisseraient entrer toute
# la rubrique Numérique d'un média local dans la base.

#: Racines de mots, testées en début de mot : « cyber » attrape « cyberattaque »,
#: « pirat » attrape « piratage », « piraté », « pirates ».
CYBER_PREFIXES = [
    "cyber", "pirat", "hack", "ransomware", "rancongiciel", "phish",
    "hameconn", "malware", "ddos", "intrusion", "exfiltr", "rgpd", "cnil",
    "spyware", "botnet", "keylogger", "cryptolock",
]

#: Vocabulaire du cambriolage et de l'effraction. « Intrusion » désigne aussi
#: bien une intrusion informatique qu'une intrusion nocturne chez un
#: commerçant : en présence de ces mots, un marqueur cyber ambigu ne suffit
#: plus, il faut un terme sans équivoque.
PHYSICAL_MARKERS = [
    "cambriolage", "cambriolages", "cambrioleur", "cambrioleurs", "cambriole",
    "effraction", "effractions", "nocturne", "nocturnes", "s introduire",
    "porte fracturee", "vitre brisee", "coffre fort", "burglary", "break in",
    "voleurs", "malfaiteurs", "domicile", "commercant",
    # Vocabulaire de fait divers relevé sur des faux positifs réels.
    "fourriere", "interpellation", "interpellations", "interpelles",
    "garde a vue", "gendarmerie", "commissariat", "degradations",
    "vol de materiel", "squat", "squatteurs", "grillage", "entrepot",
]

#: Racines dont la seule présence ne suffit pas à qualifier un contenu de cyber
#: lorsque le contexte est manifestement physique.
AMBIGUOUS_PREFIXES = ["intrusion", "hack"]

#: Expressions exactes, testées sur limites de mots.
CYBER_PHRASES = [
    "fuite de donnees", "vol de donnees", "violation de donnees",
    "donnees personnelles", "donnees exposees", "donnees volees",
    "base de donnees exposee", "data breach", "data leak",
    "incident informatique", "incident de securite", "security incident",
    "securite informatique", "securite des systemes", "attaque informatique",
    "systeme d information", "logiciel malveillant", "deni de service",
    "denial of service", "messagerie compromise", "compte compromis",
    "comptes compromis", "usurpation d identite", "identifiants voles",
    "acces non autorise", "unauthorized access", "arnaque en ligne",
    "escroquerie en ligne", "faux site",
]

# --------------------------------------------------------------------------
# Secteurs (§9) — l'ordre EST l'ordre de priorité, premier motif trouvé gagne.
# --------------------------------------------------------------------------

SECTOR_ADMIN = "Administration / Collectivité"
SECTOR_HEALTH = "Santé"
SECTOR_EDUCATION = "Éducation / Formation"
SECTOR_FINANCE = "Finance / Assurance"
SECTOR_TRANSPORT = "Transport / Logistique"
SECTOR_SPORT = "Sport"
SECTOR_RETAIL = "Commerce / Distribution"
SECTOR_TECH = "Numérique / Technologie"
SECTOR_ENERGY = "Énergie / Utilities"
#: Extensions au §9, ajoutées après mesure : elles couvrent les deux premiers
#: secteurs victimes de rançongiciel au monde, que la liste d'origine laissait
#: tomber dans « Inconnu ».
SECTOR_INDUSTRY = "Industrie / Manufacture"
SECTOR_CONSTRUCTION = "Construction / BTP"
SECTOR_SERVICES = "Services aux entreprises"
SECTOR_UNKNOWN = "Inconnu"

SECTORS = [
    SECTOR_ADMIN,
    SECTOR_HEALTH,
    SECTOR_EDUCATION,
    SECTOR_FINANCE,
    SECTOR_TRANSPORT,
    SECTOR_SPORT,
    SECTOR_RETAIL,
    SECTOR_TECH,
    SECTOR_ENERGY,
    SECTOR_INDUSTRY,
    SECTOR_CONSTRUCTION,
    SECTOR_SERVICES,
    SECTOR_UNKNOWN,
]

#: Correspondance des libellés d'activité anglophones de ransomware.live vers
#: la taxonomie française. Appliquée uniquement au secteur explicitement fourni
#: par la source, jamais au texte libre d'un article.
ACTIVITY_TO_SECTOR = {
    "manufacturing": SECTOR_INDUSTRY,
    "industrial machinery": SECTOR_INDUSTRY,
    "machinery": SECTOR_INDUSTRY,
    "metals mining": SECTOR_INDUSTRY,
    "chemicals": SECTOR_INDUSTRY,
    "automotive": SECTOR_INDUSTRY,
    "aerospace defense": SECTOR_INDUSTRY,
    "electronics": SECTOR_INDUSTRY,
    "food beverages": SECTOR_INDUSTRY,
    "agriculture": SECTOR_INDUSTRY,
    "construction": SECTOR_CONSTRUCTION,
    "real estate": SECTOR_CONSTRUCTION,
    "business services": SECTOR_SERVICES,
    "consumer services": SECTOR_SERVICES,
    "legal services": SECTOR_SERVICES,
    "law firms": SECTOR_SERVICES,
    "accounting": SECTOR_SERVICES,
    "staffing recruiting": SECTOR_SERVICES,
    "healthcare": SECTOR_HEALTH,
    "hospital health care": SECTOR_HEALTH,
    "pharmaceuticals": SECTOR_HEALTH,
    "biotechnology": SECTOR_HEALTH,
    "education": SECTOR_EDUCATION,
    "finance": SECTOR_FINANCE,
    "financial services": SECTOR_FINANCE,
    "banking": SECTOR_FINANCE,
    "insurance": SECTOR_FINANCE,
    "retail": SECTOR_RETAIL,
    "wholesale": SECTOR_RETAIL,
    "consumer goods": SECTOR_RETAIL,
    "transportation": SECTOR_TRANSPORT,
    "logistics supply chain": SECTOR_TRANSPORT,
    "shipping": SECTOR_TRANSPORT,
    "airlines aviation": SECTOR_TRANSPORT,
    "government": SECTOR_ADMIN,
    "government administration": SECTOR_ADMIN,
    "public administration": SECTOR_ADMIN,
    "non profit": SECTOR_ADMIN,
    "it services": SECTOR_TECH,
    "information technology": SECTOR_TECH,
    "software": SECTOR_TECH,
    "telecommunications": SECTOR_TECH,
    "media internet": SECTOR_TECH,
    "energy utilities": SECTOR_ENERGY,
    "energy": SECTOR_ENERGY,
    "utilities": SECTOR_ENERGY,
    "oil gas": SECTOR_ENERGY,
    "hospitality": SECTOR_RETAIL,
    "sports": SECTOR_SPORT,
}

# Motifs testés sur limites de mots, texte désaccentué et en minuscules.
SECTOR_RULES: list[tuple[str, list[str]]] = [
    (SECTOR_ADMIN, [
        "mairie", "ville de", "commune", "communaute d agglomeration",
        "departement", "region", "ministere", "prefecture", "prefet",
        "collectivite", "municipalite", "conseil departemental",
        "conseil regional", "gouvernement", "government", "administration",
        "caf", "cgss", "securite sociale", "caisse d allocations",
        "mairie de", "council", "municipal",
        # Sécurité civile et forces de l'ordre, fréquentes dans la base réelle.
        "police", "gendarmerie", "pompiers", "sdis", "sapeurs pompiers",
        "service departemental d incendie", "protection civile",
        "ambassade", "consulat", "prefectorale", "agence nationale",
    ]),
    (SECTOR_HEALTH, [
        "chu", "chr", "hopital", "hospitalier", "clinique", "sante",
        "laboratoire", "ehpad", "medical", "medecine", "pharmacie",
        "hospital", "health", "ars",
    ]),
    (SECTOR_EDUCATION, [
        "universite", "university", "ecole", "college", "lycee",
        "enseignement", "academie", "rectorat", "formation", "campus",
        "school", "education", "institut",
    ]),
    (SECTOR_FINANCE, [
        "banque", "bank", "assurance", "insurance", "mutuelle", "courtage",
        "finance", "financier", "credit", "tresor", "impots", "fiscal",
        "douane", "revenue authority", "microfinance",
    ]),
    (SECTOR_TRANSPORT, [
        "compagnie aerienne", "airlines", "airways", "air ", "aeroport",
        "airport", "port maritime", "grand port", "portuaire", "transport",
        "logistique", "logistics", "fret", "maritime", "shipping",
    ]),
    (SECTOR_SPORT, [
        "federation", "club sportif", "sport", "fitness", "stade",
        "olympique", "football",
    ]),
    (SECTOR_RETAIL, [
        "cci", "chambre de commerce", "commerce", "distribution", "enseigne",
        "supermarche", "hypermarche", "magasin", "retail", "boutique",
        "e commerce", "chambre de metiers",
        # Concessions et négoce, relevés dans la base réelle.
        "concession", "concessionnaire", "automobiles", "garage",
        "grande surface", "centre commercial", "negoce", "grossiste",
    ]),
    (SECTOR_TECH, [
        "technologies", "technology", "systemes", "systems", "reseaux",
        "digital", "web", "editeur de logiciels", "esn",
        "cloud", "logiciel", "software", "saas", "numerique", "telecom",
        "telecommunication", "operateur mobile", "internet", "technologie",
        "tech", "informatique", "hebergeur", "datacenter", "orange", "sfr",
        "zeop", "emtel", "telma", "airtel",
    ]),
    (SECTOR_ENERGY, [
        "energie", "energy", "electricite", "electricity", "edf", "eau",
        "water", "assainissement", "utilities", "jirama", "runeo", "cise",
        "petrole", "gaz",
    ]),
    (SECTOR_CONSTRUCTION, [
        "batiment", "btp", "travaux publics", "construction", "immobilier",
        "maconnerie", "charpente", "promoteur immobilier",
        "immo", "habitat", "logement", "hlm", "bailleur social", "foncier",
    ]),
    (SECTOR_INDUSTRY, [
        "industrie", "industriel", "manufacture", "usine", "fonderie",
        "metallurgie", "chimie", "agroalimentaire", "automobile",
        "aeronautique", "fabricant",
    ]),
    (SECTOR_SERVICES, [
        "cabinet d avocats", "cabinet comptable", "expertise comptable",
        "notaire", "huissier", "conseil en", "interim", "recrutement",
        "nettoyage", "securite privee",
        # Structures associatives et ordres professionnels.
        "association", "ordre des", "syndicat", "avocats", "mutuelle",
        "groupement", "cooperative", "chambre syndicale",
    ]),
]

# --------------------------------------------------------------------------
# Déduplication et dates (§11, §12)
# --------------------------------------------------------------------------

# Écart maximal, en jours, entre deux items successifs d'une même organisation
# pour qu'ils appartiennent au même incident.
INCIDENT_GAP_DAYS = 14

# Chevauchement rejoué à chaque MAJ (§6).
MAJ_OVERLAP_DAYS = 30

DATE_BASIS_EVENT = "EVENT"
DATE_BASIS_PUBLICATION = "PUBLICATION"

# --------------------------------------------------------------------------
# Budgets et plafonds durs — garantissent qu'aucun run ne dérape (§5 du plan)
# --------------------------------------------------------------------------

HTTP_TIMEOUT_SECONDS = 20
HTTP_MAX_RETRIES = 2
HTTP_POLITE_DELAY_SECONDS = 1.0
# L'API publique ransomware.live limite certains endpoints à une lecture par
# minute. Ce délai est employé seulement par son collecteur et entre les deux
# CREATE du Live Repeat ; il ne modifie pas la collecte quotidienne.
RANSOMWARE_LIVE_RATE_LIMIT_SECONDS = 65
HTTP_USER_AGENT = (
    "CyberwatchBot/1.0 (+https://github.com/Ya7o/Cyberwatch; "
    "observatoire cyber France - Océan Indien)"
)

#: Agent de repli, utilisé uniquement lorsqu'un site répond 403 à l'agent
#: ci-dessus alors que son `robots.txt` autorise le chemin demandé. Beaucoup de
#: pare-feux applicatifs refusent indistinctement tout agent qui ne commence pas
#: par « Mozilla/5.0 ». Le repli conserve l'identification du projet : on se
#: présente toujours, on ne se déguise pas en navigateur anonyme.
HTTP_USER_AGENT_FALLBACK = (
    "Mozilla/5.0 (compatible; CyberwatchBot/1.0; "
    "+https://github.com/Ya7o/Cyberwatch)"
)

#: Termes interrogés dans l'API de recherche d'un média sous WordPress.
#: Un flux RSS ne porte qu'une semaine ; l'API, elle, accepte un filtre de date
#: et rouvre tout l'historique — à condition de lui dire quoi chercher, sous
#: peine de rapatrier le journal entier. Cette liste est un filet de rappel
#: volontairement large : la pertinence est tranchée ensuite par `looks_cyber`,
#: qui reste seul juge de ce qui entre en base. Elle est fixe, donc le jeu de
#: requêtes est reproductible d'un run à l'autre (§22).
MEDIA_SEARCH_TERMS = [
    "cyberattaque",
    "piratage",
    "rançongiciel",
    "ransomware",
    "données personnelles",
    "informatique",
]

MAX_REQUESTS_PER_SOURCE = 60
MAX_PAGES_PER_SOURCE = 50
MAX_SECONDS_PER_SOURCE = 180

MAX_REQUESTS_PER_RUN = 800
MAX_SECONDS_PER_RUN = 45 * 60

# --------------------------------------------------------------------------
# Couches de sourcing (§2)
# --------------------------------------------------------------------------

LAYER_CORE = "CORE_DIRECT"
LAYER_LOCAL_MEDIA = "LOCAL_MEDIA_DIRECT"
LAYER_ENTITY_WATCH = "ENTITY_WATCH"
LAYER_REGIONAL_WATCH = "REGIONAL_WATCH"
LAYER_DISABLED = "CANDIDATE_DISABLED"

# Groupes de couches sélectionnables en ligne de commande (--layers).
LAYER_GROUPS = {
    "core": [LAYER_CORE],
    "local_media": [LAYER_LOCAL_MEDIA],
    "watch": [LAYER_ENTITY_WATCH, LAYER_REGIONAL_WATCH],
    "all": [LAYER_CORE, LAYER_LOCAL_MEDIA, LAYER_ENTITY_WATCH, LAYER_REGIONAL_WATCH],
}
