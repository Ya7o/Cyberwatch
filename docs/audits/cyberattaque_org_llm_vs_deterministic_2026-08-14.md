# Cyberattaque.org — benchmark LLM vs règles déterministes

Date de référence : 2026-08-14  
Source : `https://www.cyberattaque.org/type/attaque/`  
Corpus : 408 articles  
Règles déterministes comparées : commit `dbd85eaa790f10fa581a1dbbb349cddc0749f305` (`fix: preserve Cyberattaque.org primary organisation`)

## Référence persistante

Le golden set LLM est dans :

`tests/fixtures/cyberattaque_org_llm_reference_2026-08-14.json`

Il est épinglé sur les 407 items `CYBERATTAQUE_ORG` du commit `dbd85ea`, auxquels s'ajoute l'article des `678 438 lignes de données fiscales`, vu dans les 408 articles mais absent du snapshot matérialisé.

Toutes les lignes non présentes dans `overrides` ont été relues et le `Organisation_Raw` de la baseline a été accepté. Les overrides contiennent les cas où le LLM retient un autre nom, un statut MULTI, NEGATED, UNATTRIBUTED, DISPUTED ou THIRD_PARTY_EFFECT.

Le script :

`scripts/materialize_cyberattaque_llm_reference.py`

reconstruit les 408 décisions en CSV sans refaire de passe LLM et peut comparer un futur export déterministe avec `--compare`.

## Sémantique du benchmark

`Organisation` désigne l'organisation principalement concernée/affectée par l'article. Un prestataire, composant ou vecteur technique ne remplace pas automatiquement l'organisation principale. Les articles couvrant plusieurs victimes distinctes sont marqués `MULTI`. Une attribution explicitement infirmée est marquée `NEGATED`.

## Résultat de la comparaison

Comparaison statique du golden set avec le comportement de `dbd85ea` : **40 différences exactes sur 408 décisions**. Parmi elles, **37 sont à confiance HIGH** dans le benchmark et **3 à confiance MEDIUM**.

Ces 40 différences ne sont pas toutes des bugs. Elles se répartissent en quatre familles.

### 1. Canonicalisation / précision du nom — 12

La règle déterministe identifie globalement la bonne entité mais sous un libellé moins précis ou éditorial :

- Enseignement catholique → Secrétariat général de l’enseignement catholique
- Union européenne → Commission européenne
- Handisport → Fédération Française Handisport
- Office français de l’immigration → Office français de l’immigration et de l’intégration
- Saint-Étienne → Ville de Saint-Étienne
- Quiberon → Ville de Quiberon
- Roubaix → Ville de Roubaix
- FFMOTO → Fédération Française de Motocyclisme
- La Région Occitanie → Région Occitanie
- Sapeurs Pompiers → Fédération nationale des sapeurs-pompiers de France
- Centres Sociaux de France → Fédération des Centres sociaux et Socioculturels de France
- Amis de la Police → Amicale Police et Patrimoine

Ces cas doivent être traités par des alias/références validés plutôt que par de nouvelles regex générales.

### 2. Service / programme / fichier vs organisation opératrice — 15

Le titre nomme un service, fichier ou programme alors que le benchmark identifie son organisation porteuse :

- FICOBA → DGFiP
- Diplôme de Compétence en Langue → Ministère de l’Éducation nationale
- EduConnect → Ministère de l’Éducation nationale
- Parcoursup → Ministère de l’Enseignement supérieur, de la Recherche et de l’Espace
- Service Civique → Agence du Service Civique
- Action Populaire → La France insoumise (MEDIUM)
- Certificat CléA → Certif’Pro
- Osmose → DINUM
- Tchap → DINUM
- France Services → ANCT
- Apps.education.fr → Ministère de l’Éducation nationale
- Génération #HDF → Région Hauts-de-France
- Vaccination scolaire en Auvergne-Rhône-Alpes → SYADEM
- BANATIC → Ministère de l’Intérieur
- I-CAD → Ingenium animalis

**Ne pas convertir globalement ces 15 cas dans `Organisation` sans décision de modèle de données.** Plusieurs services distincts du même ministère peuvent subir des incidents différents à quelques jours d'intervalle. Les rabattre sur un même ministère peut créer de faux merges dans le dédoublonnage. Si ces liens sont exploités en production, privilégier un référentiel `Affected_Entity -> Operator` séparé plutôt qu'un alias global.

### 3. Articles multi-victimes / agrégés — 7

- ARS : plusieurs ARS régionales
- Son-Video.com & EasyLounge : deux entités
- G7 d’Évian : plusieurs collectivités/services
- Polices municipales : trois collectivités
- Rennes : Ville de Rennes + Rennes Métropole
- Fuite de données scolaires : 19 établissements
- 4 SDIS frappés : quatre SDIS

Le comportement actuel est hétérogène : certains deviennent une pseudo-organisation (`ARS`, `G7 d’Évian`, `Polices municipales`, `Rennes`, `Son-Video.com & EasyLounge`) alors que d'autres sont rejetés (`4 SDIS`, fuite scolaire).

Recommandation simple : détecter explicitement `MULTI` et **ne pas créer d'ITEM unique** tant que Cyberwatch ne sait pas éclater proprement un article en plusieurs victimes. C'est plus cohérent et plus sûr que de conserver une pseudo-organisation.

### 4. Écarts fonctionnels à corriger en priorité — 6

1. `Mon Espace Santé (DMP)` : le benchmark conclut `NEGATED`; l'article remet explicitement en cause l'attribution au DMP. La règle actuelle peut encore créer un item `Mon Espace Santé`.
2. `Une IA d’OpenAI ... pirate Hugging Face` : le benchmark identifie `Hugging Face`; le test déterministe impose actuellement un rejet vide.
3. `Chat Control` : ce n'est pas une organisation; la règle actuelle accepte le préfixe comme organisation.
4. `Le site de Pierrefitte-sur-Loire...` : la mairie est l'organisation affectée, même si l'attaque directe vise son hébergeur non nommé. Le test actuel impose un rejet vide.
5. `Orisha Insurance : ... frappe CIM` : l'article désigne explicitement la filiale CIM comme entité affectée; le préfixe parent est actuellement prioritaire.
6. `678 438 lignes de données fiscales...` : la DGFiP confirme être victime mais l'article n'est pas matérialisé dans la baseline; il faut couvrir les variantes `X confirme avoir été/être victime` et pas seulement `X confirme avoir subi`.

## Comparaison avec les tests ciblés actuels

Les tests de `dbd85ea` sont corrects sur :

- Steam → Steam
- Spiko → Spiko
- OpenAI (article TanStack) → OpenAI
- Toulouse FC → Toulouse FC
- Lidl → Lidl
- Gagny → Ville de Gagny
- Drancy → Mairie de Drancy
- Eyguières → Mairie d’Eyguières
- Domaine des Tournels → Domaine des Tournels
- Fédération Française de Bridge
- École Directe / Association.fr : rejet des démentis

Le golden set diffère volontairement de quatre attentes de test :

- article OpenAI/Hugging Face : test = vide, LLM = Hugging Face
- Pierrefitte-sur-Loire : test = vide, LLM = Mairie de Pierrefitte-sur-Loire (`THIRD_PARTY_EFFECT`)
- 4 SDIS : test = vide, LLM = quatre victimes (`MULTI`)
- fuite scolaire : test = vide, LLM = 19 établissements (`MULTI`)

Pour les deux derniers, le rejet reste acceptable dans l'architecture actuelle à condition d'être diagnostiqué explicitement comme `MULTI`, et non comme simple `no_victim`.

## Améliorations proposées

### P0 — sûres et peu complexes

1. Étendre les démentis Cyberattaque.org avec des formulations strictes de l'article Mon Espace Santé, par exemple `aucune preuve technique ne permet de confirmer` / `il ne s'agit pas d'une fuite confirmée`, uniquement lorsque la conclusion porte sur l'entité attribuée.
2. Étendre la relation forte `X confirme ... victime` à `X confirme avoir été victime` et `X confirme être victime`. Cela doit récupérer la DGFiP sur l'article des 678 438 lignes.
3. Ajouter une détection `MULTI` source-spécifique avant `_safe_prefix` pour éviter les pseudo-organisations évidentes : `ARS` générique dans cet article, `Polices municipales`, `G7 d’Évian`, préfixes contenant plusieurs organisations (`&`) et titres chiffrés multi-victimes.
4. Rejeter `Chat Control` comme sujet/campagne non organisationnelle.
5. Ajouter les alias déterministes validés de la famille 1, sans alias global `ARS`.

### P1 — à tester contre le golden set

6. Ajouter un fallback narratif `... pirate X` / `... compromet X` uniquement si `X` est une entité connue ou référencée. Cela permet Hugging Face sans ouvrir une extraction libre de groupes nominaux.
7. Pour une collectivité explicitement affectée par l'attaque de son prestataire (`site de X ... attaque de son hébergeur`), permettre `Organisation=X` avec menace `Incident tiers`, ce qui rend Pierrefitte cohérent avec Lidl/Toulouse FC.
8. Gérer une filiale explicitement nommée (`incident affectant sa filiale X`) uniquement si X est une entité connue; sinon conserver le parent. CIM sert de cas de test.

### À ne pas faire pour l'instant

- ne pas mapper tous les services publics vers leur ministère via `organisation_aliases.csv`;
- ne pas créer de fuzzy matching;
- ne pas utiliser le benchmark LLM dans le pipeline de production;
- ne pas éclater automatiquement tous les articles MULTI tant que la règle de création de plusieurs ITEMS n'est pas explicitement conçue.

### Seuil de réexamen de `_SCOPE_PATTERNS`

La liste fermée de systèmes reste appropriée tant qu'elle couvre des cas rares
et explicitement vérifiés. Consigner chaque ajout manuel sur les runs réels
2026. Réexaminer une extraction générique uniquement si **trois ajouts ou plus
sur un même mois** concernent des systèmes distincts, ou si deux ajouts
consécutifs échouent pour la même structure syntaxique. Le réexamen devra
inclure un échantillon de faux positifs et des tests de non-régression ; ce
seuil n'autorise pas, à lui seul, une généralisation automatique.

## Utilisation future

Matérialiser le golden set :

```bash
python scripts/materialize_cyberattaque_llm_reference.py --output /tmp/cyberattaque_llm.csv
```

Comparer un export déterministe :

```bash
python scripts/materialize_cyberattaque_llm_reference.py --compare /tmp/cyberattaque_deterministic.csv
```

Le benchmark doit rester un oracle de test hors production. Toute évolution des règles Cyberattaque.org peut ainsi être mesurée sur les mêmes 408 décisions sans nouvelle qualification LLM.
