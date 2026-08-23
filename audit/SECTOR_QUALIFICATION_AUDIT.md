# Audit — Qualification Sector (2026-08-22)

Statut : **diagnostic, aucune modification du moteur**

Périmètre : pourquoi 59,9 % des incidents et 61,9 % des items portent `Secteur = Inconnu`.

Méthode : lecture seule sur `data/` (1053 items, 873 incidents), exécution de
`scripts/audit_sector_coverage.py`, reconstruction offline du registre et de la
file d'enrichissement. Aucune collecte, aucun appel LLM, aucun accès réseau.

## 1. Mesure

| Périmètre | Total | Inconnu | Couverture |
|---|---:|---:|---:|
| Items | 1053 | 652 | **38,1 %** |
| Incidents | 873 | 523 | **40,1 %** |

Couverture par source :

| Source | Items | Inconnu | Couverture |
|---|---:|---:|---:|
| RANSOMWARE_LIVE | 184 | 47 | 74,5 % |
| FRENCHBREACHES | 100 | 67 | 33,0 % |
| CYBERATTAQUE_ORG | 427 | 295 | 30,9 % |
| BONJOURLAFUITE | 330 | 242 | 26,7 % |
| VEILLE_LLM | 12 | 1 | 91,7 % |

Point important : **les 523 incidents `Inconnu` ont tous une organisation nommée.**
Le problème n'est pas l'identification de la victime, c'est l'absence de preuve
d'activité rattachable à cette victime. On y trouve des entités non ambiguës —
DINUM, DGFiP, SFR, SUEZ, Capgemini, IRD.

Seule RANSOMWARE_LIVE dépasse 70 % : c'est la seule source qui publie un secteur
structuré. Les trois sources éditoriales plafonnent autour de 30 %.

## 2. Décomposition des 652 items inconnus

La file d'enrichissement reconstruite partitionne exactement les 652 items :

| Catégorie | Orgs | Items | Part |
|---|---:|---:|---:|
| `NO_EVIDENCE` | 290 | 330 | 50,6 % |
| `JSON_CHALLENGER` | 126 | 186 | 28,5 % |
| `KNOWN_ITEM_REVIEW` | 60 | 78 | 12,0 % |
| `RAW_SECTOR_UNMAPPED` | 43 | 48 | 7,4 % |
| `CONSENSUS_REVIEW` | 2 | 6 | 0,9 % |
| `REGISTRY_CONFLICT` | 3 | 4 | 0,6 % |

La dispersion est forte : 524 organisations inconnues pour 652 items, dont 111
seulement apparaissent plus d'une fois. Le maximum est de 5 items (DGFiP). Il n'y
a donc **aucun gros lot** : aucune correction unitaire ne déplace l'agrégat.

## 3. Causes

### 3.1 Le canal challenger est structurellement mort (186 items, 28,5 %)

`data/qualification_provenance.csv` contient 174 décisions `Sector`, dont 167 via
`LLM_SOURCE_FALLBACK`. Résultat :

- 157 `REJECTED_IDENTITY_EVIDENCE`
- 7 `REJECTED_POLICY_DISABLED`
- 2 `REJECTED_SECTOR_CONFLICT`
- 1 `REJECTED_NO_STRONG_EVIDENCE`
- 7 `APPLIED` (via `ORG_CONTEXT_SECTOR`, pas le challenger)

**Les 157 rejets `REJECTED_IDENTITY_EVIDENCE` ont tous une preuve vide.** Aucun
n'est un désaccord de clé d'organisation : `_official_identity_evidence`
(`source_llm_fallback.py:210`) ne retient jamais la moindre URL.

Le portail `_sector_gate` (`source_llm_fallback.py:244`) exige trois conditions
cumulatives :

1. une URL officielle tierce dont le **nom d'hôte** contient un token du nom
   de l'organisation ;
2. un texte d'activité indépendant classable vers un secteur **unique**, lu
   exclusivement dans `sector_evidence_text` / `sector_evidence_texts` ;
3. l'accord entre ce secteur dérivé et le secteur déclaré par le challenger.

Or les exports challenger ne portent ni (1) ni (2) :

```
FRENCHBREACHES   : 710 enreg. — 509 avec secteur déclaré —   3 avec preuve exploitable
CYBERATTAQUE_ORG : 415 enreg. — 247 avec secteur déclaré —   9 avec preuve exploitable
```

**756 secteurs déclarés, 12 preuves utilisables (1,6 %).** Le champ `sources` de
ces exports ne contient que l'article d'origine, retiré par `_external_evidence`
comme non tiers. Le champ `sector_evidence_text` attendu par le portail devait
être alimenté par un enrichisseur amont qui n'a jamais tourné à l'échelle.

Le portail n'est pas trop strict par erreur — il est correct. C'est la chaîne
d'approvisionnement en preuves qui est vide. Le canal produit donc des candidats
qui ne peuvent structurellement jamais être acceptés.

Note secondaire : la condition (1) resterait fragile même approvisionnée. Le test
« le nom d'hôte contient un token du nom » échoue sur toute entité dont le domaine
diffère de la raison sociale — `DGFiP` → `impots.gouv.fr`, `DINUM` →
`numerique.gouv.fr`.

### 3.2 Le stock de preuves entreprise est quasi vide (330 items, 50,6 %)

`data/org_enrichment_cache.csv` contient **60 lignes pour 524 organisations
inconnues**. Sur les 290 organisations classées `NO_EVIDENCE`, **6 ont un
enregistrement d'enrichissement**. Ces 330 items ne sont pas rejetés par une
règle : aucun candidat n'a jamais été produit pour eux.

Le budget n'explique pas le trou : `ORG_ENRICHMENT_MAX_CALLS_PER_RUN` vaut 200 par
défaut. Les 60 lignes sont par ailleurs toutes `MATCHED` — **les échecs de
résolution ne sont pas persistés**. Il n'existe donc aucune trace de « on a
cherché et on n'a pas trouvé », et chaque run réinterroge les mêmes absents sans
mémoire ni traçabilité du coût.

### 3.3 La politique de canaux est plus fermée que le code (84 items, 12,9 %)

`data/sector_auto_policy.json` désactive 7 canaux sur 8. Seul `manual_reference`
est actif. Le `DEFAULT_POLICY` de `sector_registry.py:41` considère pourtant
`structured_source` comme sûr et activé par défaut : **le fichier de données est
plus restrictif que le code**, sur un canal qui alimente 123 organisations.

Registre reconstruit — 508 organisations, 172 `AUTO`, 327 `REVIEW`, 9 `CONFLICT` :

| Canal | Décision | Orgs | Items inconnus récupérables |
|---|---|---:|---:|
| `registry_exact_naf` | REVIEW | 25 | 27 |
| `structured_source` | REVIEW | 118 | 26 |
| `known_item_single` | REVIEW | 146 | 25 |
| `consensus_multi_source` | REVIEW | 38 | 6 |

Débloquer **tous** les canaux gelés ne rapporte que **84 items** : 38,1 % → 46,1 %.
La majorité des lignes `REVIEW` concerne des organisations dont les items sont
déjà qualifiés par ailleurs. Ce levier est réel mais **secondaire** — il ne faut
pas le confondre avec la cause principale.

**Mise à jour du 2026-08-23 — mesure effective, correction d'une hypothèse de cet
audit.** `scripts/evaluate_sector_registry.py`, qui mesure chaque canal contre le
golden set (`data/golden/qualification_golden.csv`), ne pouvait pas tourner : ce
fichier avait été supprimé par un reset à froid le 2026-08-21 et jamais reconstitué
(`zero_reset.py` le traite comme état métier régénérable, pas comme référentiel
protégé). Une copie antérieure au reset a été retrouvée dans les archives du dépôt
(`bench/results/golden_v2/qualification_golden_v2.csv`, 98 organisations),
validée sans anomalie par `golden.validate_file` — y compris sa version de
taxonomie, toujours à jour — puis restaurée à son emplacement canonique.

Résultat de la mesure sur les 7 canaux gelés :

| Canal | Cas | Précision | Verdict |
|---|---:|---:|---|
| `structured_source` | 6 | 83,33 % | **échoue** (précision et volume) |
| `known_item_single` | 24 | 91,67 % | **échoue** (précision) |
| `consensus_multi_source` | 12 | 83,33 % | **échoue** (précision) |
| `registry_exact_naf` | 3 | 100 % | **échoue** (volume : 3 < 10 cas minimum) |
| `official_subject_activity`, `registry_llm`, `legacy_official_site` | 0 | — | **échoue** (aucun cas mesurable) |

**Aucun des 7 canaux ne passe la barre.** L'hypothèse §3.3 ci-dessus, qui
présentait `structured_source` comme le levier « sûr » parce qu'activé par
défaut dans le code, ne survit pas à la mesure : 83,33 % de précision observée,
avec un cas nommé faux — `eiffage` classé `Transport / Logistique` au lieu de
`Construction / BTP`. C'est exactement ce que le seuil de 95 % est censé
empêcher, et c'est la preuve que la lecture du code seul (sans mesure) aurait
conduit à une recommandation incorrecte.

Le levier « rouvrir la politique de canaux » n'est donc pas simplement à
« mesurer avant d'agir » comme l'avançait la première version de cet audit — sur
l'échantillon disponible aujourd'hui (98 organisations), **aucun canal
n'est mesurable comme sûr**. Deux voies pour la suite, aucune tranchée ici :
élargir le golden set pour donner à `registry_exact_naf` (100 % sur seulement 3
cas) la chance d'atteindre le seuil de volume, ou accepter que ce levier reste
fermé tant que l'échantillon ne grandit pas.

Les 7 rejets `REJECTED_POLICY_DISABLED` sont, eux, franchement coûteux : le
portail les avait pleinement validés (site officiel + activité concordante), et
`neutralize_sector_fallback` (`qualification.py:184`) les annule via la constante
codée en dur `_SECTOR_FALLBACK_AUTO_APPLY = False`. Exemples :
`efcformation.com` → Éducation, `onpp.fr` → Santé, `batipro33.fr` → BTP.

### 3.4 Table de correspondance incomplète sur la seule source structurée (48 items, 7,4 %)

`classify_source_sector` (`sector.py:39`) fait une correspondance **exacte** sur
`searchable(valeur brute)`. Cinq libellés RANSOMWARE_LIVE ne sont pas dans la
table :

| Libellé brut | Clé normalisée | Items inconnus | Cible dans la taxonomie |
|---|---|---:|---|
| `Hospitality` | `hospitality` | 14 | `Hébergement / Tourisme / Restauration` — **existe** |
| `Agriculture and Food Production` | `agriculture and food production` | 11 | **absente de la taxonomie** |
| `Government & Defense` | `government defense` | 8 | `Administration / Collectivité` — **existe** |
| `Not Found` | `not found` | 7 | légitimement Inconnu |
| `Other` | `other` | 6 | légitimement Inconnu |

`Hospitality` et `Government & Defense` sont de vrais trous de table : la
taxonomie contient déjà la cible, et `ACTIVITY_TO_SECTOR` contient déjà
`hebergement`, `restauration`, `tourisme`, `government`, `aerospace defense` —
seule la variante anglophone exacte manque. Ce sont **22 items** récupérables par
correspondance déterministe stricte, sans inférence.

`Agriculture and Food Production` (11 items) est différent : aucun secteur cible
n'existe. Le classer serait une invention.

### 3.5 Artefacts de pilotage jamais produits

`qualification.py:279` construit le registre **en mémoire** et ne l'écrit jamais.
`sector_registry.write_outputs` n'est appelé que depuis
`scripts/audit_sector_coverage.py`. Conséquences :

- `data/organisation_sector_registry.csv`, documenté comme fichier canonique
  dans `CLAUDE.md`, **n'existe pas** ;
- `data/sector_enrichment_queue.csv` n'existe pas non plus.

C'est le nœud du blocage : le seul canal autorisé est `manual_reference`, et la
file qui devrait alimenter cette revue manuelle n'est jamais écrite. Le seul
levier ouvert n'a aucune entrée. La couverture est structurellement figée.

## 4. Conclusion

La qualification Sector n'est pas cassée : 1217 tests passent, l'arbitrage est
déterministe et la provenance est traçable. Le taux d'`Inconnu` n'est pas un
défaut d'arbitrage, c'est un **déficit d'approvisionnement en preuves**.

Trois constats se cumulent :

1. **Les preuves n'arrivent pas.** 98,4 % des secteurs déclarés par les
   challengers arrivent sans le champ de preuve exigé ; 98,9 % des organisations
   inconnues n'ont aucun enregistrement d'enrichissement entreprise. C'est
   l'essentiel des 652 items — et c'est un problème de **sources**, pas de moteur.
2. **Ce qui arrive est bloqué par une politique plus fermée que le code**, sans
   trace de la mesure de précision qui justifierait ces verrous. Levier réel mais
   borné à 84 items.
3. **La boucle de rattrapage manuel est ouverte mais non branchée** : le seul
   canal autorisé dépend d'une file que le pipeline n'écrit pas.

Correction de cadrage utile : rouvrir la politique de canaux est le geste le plus
visible, mais il plafonne à 46,1 %. Le reste — près de 500 items — ne se débloque
qu'en alimentant réellement l'enrichissement entreprise et en persistant les
échecs de résolution.

## 5. Pistes, par rapport valeur / risque

Aucune n'est appliquée ici ; chacune touche un domaine `FROZEN` et demande un
arbitrage explicite.

| # | Piste | Gain | Risque | Domaine | Statut (2026-08-23) |
|---|---|---:|---|---|---|
| 1 | Mapper `government defense` (mesuré 8/8) ; `hospitality` réexaminé et écarté (précision mitigée, voir mise à jour §3.1) | +8 items | Très faible — correspondance exacte, mesurée | Qualification | **Fait** |
| 2 | Écrire le registre et la file dans le pipeline (`write_outputs`) | 0 direct | Très faible — deux fichiers dérivés, débloque la revue manuelle | Qualification | **Fait** |
| 3 | Persister les échecs de résolution entreprise | 0 direct | Faible — supprime la réinterrogation aveugle, rend le trou mesurable | Enrichissement | Ouvert |
| 4 | Aligner `structured_source` sur le `DEFAULT_POLICY` du code | — | **Mesuré et refusé** : 83,33 % de précision sur 6 cas, sous le seuil de 95 % (voir mise à jour §3.3) | Politique | **Mesuré, non applicable** |
| 5 | Réexaminer `_SECTOR_FALLBACK_AUTO_APPLY` pour les 7 cas pleinement validés | +7 items | Moyen — cas les mieux prouvés du corpus, mais constante codée en dur | Qualification | Ouvert |
| 6 | Alimenter `sector_evidence_text` en amont des exports challenger | jusqu'à +186 items | Élevé — vrai chantier ; sans lui le canal restera mort | Sources | Ouvert |
| 7 | Ajouter `Agriculture / Agroalimentaire` à la taxonomie | +11 items | Décision produit, tranchée | Méthodologie | **Fait** |

Les pistes 1 à 3 étaient des corrections de câblage : elles ne rouvraient aucun
arbitrage et ne créaient aucune couche. Les pistes 1, 2, 3 et 7 sont
implémentées (voir `git log` sur cette branche). La piste 4 a été mesurée en
suivant sa propre procédure (`scripts/evaluate_sector_registry.py` contre le
golden set restauré) : le résultat est négatif, ce n'est plus une piste
ouverte mais une conclusion. Les pistes 5 et 6 restent des décisions non
prises.

## 6. Défaut annexe constaté

`python -m pytest tests/ -q` — commande de validation générique documentée dans
`CLAUDE.md` — **écrit dans les données canoniques**. Après exécution,
`data/llm_usage.json` et `data/performance_runs.json` sont modifiés : la
télémétrie réelle est remplacée par des valeurs de fixtures (`calls_attempted`
28 → 5, la tâche `cyberattaque_semantic` disparaît). Ces fichiers ont été
restaurés ; l'arbre est propre. À corriger indépendamment du sujet Sector, car la
commande de validation recommandée corrompt silencieusement la traçabilité des
coûts LLM.

## Reproduction

```bash
python scripts/audit_sector_coverage.py --output ""   # lecture seule
```

Sans `--output ""`, le script écrit `data/sector_quality.json`,
`data/organisation_sector_registry.csv` et `data/sector_enrichment_queue.csv`.
