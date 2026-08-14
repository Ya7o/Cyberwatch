# Validation P0 Cyberattaque.org

Pipeline : `NEGATED → MULTI → DIRECT → NO_VICTIM`. Aucun resolver DB ni
fallback `find_known_entity` ne s'applique à cette source.

Le benchmark HEAD-only offline lit les deux fixtures versionnées (408 articles,
408 décisions) et produit 367 matchs, 41 divergences, 3 NEGATED, 6 MULTI, 392
DIRECT et 7 NO_VICTIM. Hash reproductible :
`6de6ca333d1ebc6c04a6b99742b22155c1871c8642de45c613176103f438a9a2`.

## Revue aliases P0

Enseignement catholique, Union européenne, Handisport, OFI, Saint-Étienne,
Quiberon, Roubaix, FFMOTO, Sapeurs Pompiers, Centres Sociaux et Amis Police :
**REJECT_OTHER** dans ce patch. Ces libellés sont soit des différences de
sémantique/service, soit nécessitent la vérification d'une forme exacte dans un
article. Aucun alias global n'est ajouté sans preuve locale. ARS est
**REJECT_AMBIGUOUS**. Aucun service n'est mappé vers son opérateur.

P1 inchangés : Hugging Face, Pierrefitte-sur-Loire, Orisha/CIM.
