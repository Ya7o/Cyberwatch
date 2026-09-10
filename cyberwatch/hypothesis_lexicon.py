"""Vocabulaire de l'hypothèse, en trois paliers assumés.

Deux lexiques distincts avaient divergé : celui de l'extraction connaît
« possible » et « éventuel », celui de la publication non. C'est par cet écart
que l'impact Printemps « des attaques ciblées possibles via des e-mails ou
appels frauduleux » a franchi la porte de publication (audit du 10/09/2026).

Les fusionner en bloc détruit des faits réels : mesuré sur le corpus, ajouter
les termes manquants à toute la porte de publication modifie 5 incidents sur 74
et supprime « données bancaires », « base de données clients » et un
`initial_access` sourcé. Les paliers restent donc séparés, et le vocabulaire
élargi ne s'applique qu'à l'impact — où il ne change rien au corpus existant
tout en rejetant le cas Printemps.
"""

from __future__ import annotations

import re

#: Palier extraction : refuse une valeur proposée par le modèle.
EXTRACTION_RE = re.compile(
    r"\b(?:pourrait|pourraient|peut[- ]?[êe]tre|possibles?|possiblement|potentiellement|probables?|probablement|"
    r"hypoth[èe]se|sc[ée]nario|suspect[ée]?|suppos[ée]?|envisag[ée]?|pr[ée]sum[ée]e?s?|semblerait|"
    r"serait|agirait|aurait|auraient|susceptible(?:s)?|non\s+confirm[ée]|sans\s+confirmation|reste\s+inconnu|"
    r"risques?\s+(?:de|d['’])|expose(?:nt|rait|raient)?\s+(?:à|a)|augmente(?:nt|rait|raient)?\s+le\s+risque|"
    r"laisse(?:nt|rait|raient)?\s+craindre|accroit(?:re|s|)?\s+le\s+risque)\b",
    re.I,
)

#: Palier publication : refuse une preuve trop faible pour un fait publié.
PUBLICATION_RE = re.compile(
    r"\b(?:pourrait|pourraient|permettrait|potentielle?|peut par exemple|"
    r"ne signifie toutefois pas)\b|"
    r"\brisque\b.{0,50}\bd(?:e|['’])\b|"
    r"\b(?:peut|peuvent)\b.{0,100}\bpermettre\b|"
    r"\b(?:peut|peuvent)\b.{0,100}\b(?:chercher|tenter|r[ée]cup[ée]r|obtenir|contenir|confirmer)|"
    r"\b(?:d[ée]terminer|savoir|v[ée]rifier)\s+si\b|"
    r"\bsi\b.{0,100}\b(?:[ée]t[ée]|avait|confirme|contient|concerne|comprend|inclut)|"
    r"\bil ne serait (?:donc )?pas justifi[ée]\b",
    re.I,
)

#: Palier impact : le contrat interdit explicitement le risque futur, la
#: conséquence potentielle et la mise en garde. Le vocabulaire y est donc plus
#: strict qu'ailleurs, côté valeur comme côté preuve.
_IMPACT_ONLY = (
    r"\b(?:possible(?:s)?|possiblement|[ée]ventuel(?:le)?(?:s)?|[ée]ventuellement|"
    r"susceptible(?:s)?|probable(?:s|ment)?|hypoth[èe]se)\b"
)
IMPACT_RE = re.compile(f"{PUBLICATION_RE.pattern}|{_IMPACT_ONLY}", re.I)
