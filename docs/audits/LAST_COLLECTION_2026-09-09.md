# Audit de la dernière collecte — 9 septembre 2026, 17 h 15

**Verdict : publication techniquement réussie, mais données métier invalides.** Les deux nouvelles observations FrenchBreaches de Citadium et Printemps auraient dû enrichir les incidents homonymes déjà collectés. Citadium est correctement regroupé. Printemps est fusionné à tort avec SAD'S Interim : le site publie désormais deux fiches nommées Printemps, dont une porte le ransomware Rhysida, les données de santé et les sources de SAD'S Interim. Cette erreur P0 est persistée dans les registres de déduplication et d'identité.

**Correction appliquée le 10 septembre 2026.** Printemps est de nouveau regroupé avec ses deux sources sous `INC-AFF157A4627F` et SAD'S Interim est restauré sous `INC-61993D19E8E2`. Citadium et Printemps sont qualifiés `Commerce / Distribution`, en `France métropolitaine`, avec une menace `Fuite de données`. Les volets détail ne conservent que les noms, prénoms, adresses e-mail et numéros de téléphone comme données exposées ; Shipup reste un tiers, la CVE reste une mention de contexte et les événements de chronologie sont bornés à leur victime. Après correction, les secteurs inconnus représentent 7/74 incidents (9,46 %) et les localisations inconnues 3/74 (4,05 %).

Les protections ajoutées rejettent le score flou neutre de 0,5, exigent une justification couvrant les deux victimes avant toute identité `SAME`, bloquent une paire à menaces contradictoires sans signal structurel, appliquent les rapprochements déterministes avant les arêtes LLM, rechargent le registre d'identité avant la génération du site et filtrent les catégories issues d'une remédiation, d'un risque futur ou du rôle d'un prestataire. La recette complète passe avec 1 097 tests, Ruff, mypy, `cyberwatch check`, `validate-business` et deux générations successives du site sans différence.

## Périmètre

| Élément | Valeur |
|---|---|
| Run | `RUN-20260909T171543` |
| GitHub Actions | [34355934869](https://github.com/Ya7o/Cyberwatch/actions/runs/34355934869) |
| Commit de départ | `ee9d70158be5cb9ab1cff31dbaef9e10db605d86` |
| Commit publié | `a5396e0ddd02e8e860d3a449553f774c8a2f289f` |
| Fenêtre | 8–9 septembre 2026 |
| Corpus après collecte | 128 observations, 74 incidents |
| Delta réel | 2 observations, 0 nouvel incident attendu |
| Durée / requêtes | 60,4 s / 19 |
| Appels LLM / coût | 9 / 0,005831 $ |

Les observations ajoutées sont :

- `ITM-3a1f12b53d6e809e`, Citadium, FrenchBreaches ;
- `ITM-56fe2e286f88ef44`, Printemps, FrenchBreaches.

Le run annonce bien `+0 nouveaux` au niveau incident. Aucun identifiant d'incident n'est ajouté ou retiré entre les deux commits. Seules les fiches Citadium, Printemps et SAD'S Interim devaient être susceptibles d'évoluer.

## Logs de la chaîne

Les quatre sources directes sont `OK` à 100 % : FrenchBreaches collecte 6 éléments avec 8 requêtes, BonjourLaFuite 2 avec 1 requête, Cyberattaque.org 6 avec 3 requêtes et Ransomware.live 2 avec 7 requêtes. `VEILLE_LLM` reste `PARTIAL` à 99 % : son snapshot du 2 septembre a sept jours d'ancienneté pour une limite de deux jours et ne fournit aucun élément dans la fenêtre.

Les 9 appels LLM réussissent sans erreur, délai dépassé, réponse 429/5xx ni blocage budgétaire. Huit appels concernent `source_facts` et un appel batch traite cinq décisions de déduplication. Le modèle effectif est `gpt-4o-mini` malgré `gpt-5-nano` demandé. Parmi 24 observations éligibles aux faits sémantiques, 16 sont entièrement servies par le cache et 4 partiellement. Les reprises de champs produisent 35 nouvelles abstentions et aucune récupération.

Les commandes `cyberwatch check` et `validate-business` passent. Le suivi de production signale cependant `REVIEW_REQUIRED`, 26 paires en attente, 12,16 % de secteurs inconnus et 5,41 % de localisations inconnues. Le statut global reste `OK` et le compteur `Dedup_Known_False_Merges` reste à zéro, alors que l'audit du delta établit une fusion erronée. Ce compteur ne couvre que le corpus fixe de validation, pas les nouvelles décisions appliquées au corpus vivant.

## Déduplication — erreur P0

### Citadium

Le regroupement est correct et conserve l'identifiant `INC-F7B381806AEC` :

- `ITM-297a7e21d0f7da49`, Cyberattaque.org ;
- `ITM-3a1f12b53d6e809e`, FrenchBreaches.

Même victime, même date de publication, même prestataire Shipup et même exposition de données de contact : les deux observations décrivent bien le même incident.

### Printemps et SAD'S Interim

La paire `ITM-56fe2e286f88ef44|ITM-ec4d0cdfab6fa8df` reçoit le verdict LLM `SAME/SAME` à 0,90. Elle rapproche pourtant :

- Printemps / FrenchBreaches / incident tiers Shipup / 9 septembre ;
- SAD'S Interim / Cyberattaque.org / ransomware Rhysida / 8 septembre.

Tous les signaux transmis par le générateur de candidats sont négatifs : `exact_key=false`, `compact_match=false`, `token_permutation=false`, `containment=false`, `acronym_match=false`, aucun domaine ni identifiant d'entreprise partagé, et un score flou neutre de 0,5. La justification du modèle ne cite que SAD'S Interim, Rhysida et la date du 8 septembre ; elle n'apporte aucune preuve concernant Printemps. Une autre paire du même batch, opposant la même observation Printemps à l'observation Ransomware.live de SAD'S Interim, est correctement classée `DIFFERENT/UNKNOWN` à 0,5.

Le validateur automatique ne contrôle que le statut, `SAME`, la confiance minimale de 0,85 et la proximité temporelle. Il ne requiert aucun signal positif d'identité, aucune mention des deux victimes dans les preuves et aucun accord de menace. Le verdict crée alors deux lignes persistantes :

- alias d'organisation `printemps -> sad s interim` dans `organisation_identity_registry.csv` ;
- fusion de paire `ITM-56fe2e286f88ef44|ITM-ec4d0cdfab6fa8df` dans `incident_dedup_registry.csv`.

Les arêtes LLM sont appliquées avant les rapprochements déterministes par nom canonique. La nouvelle observation Printemps rejoint donc SAD'S Interim en priorité. La fusion correcte avec l'observation Cyberattaque.org de Printemps est ensuite bloquée par le veto « deux éléments Cyberattaque.org avec des identifiants source différents » présent dans la composante contaminée.

Conséquences publiques :

- `INC-AFF157A4627F` reste une fiche Printemps « Fuite de données » avec une seule observation ;
- `INC-61993D19E8E2`, auparavant SAD'S Interim, est renommé Printemps et reçoit trois sources, dont l'URL FrenchBreaches de Printemps ;
- le site présente donc deux Printemps, l'un en fuite de données et l'autre en ransomware Rhysida avec passeports, données de santé, paie et données bancaires ;
- SAD'S Interim disparaît comme libellé de carte alors que son résumé et ses faits restent publiés sous le second Printemps.

## Reproductibilité — erreur P0

Les incidents et les volets détail sont générés avec deux états différents du registre d'identité. Le fichier d'incidents voit l'alias LLM appliqué pendant le run, tandis que la construction initiale des détails utilise encore le registre chargé avant cette décision.

Un `build-site` isolé depuis le seul commit `a5396e0` modifie immédiatement trois artefacts versionnés : `facts.json`, `incidents.json` et `latest.json`. Les faits FrenchBreaches de Printemps quittent `INC-AFF157A4627F` et rejoignent `INC-61993D19E8E2`. Le commit publié n'est donc pas reproductible sans aucune nouvelle donnée ni aucun appel externe.

## Audit des incidents touchés

### Citadium — `INC-F7B381806AEC` — correction P1

La menace « Fuite de données — Confirmé », le tiers Shipup et la localisation générale France métropolitaine sont cohérents. Aucun acteur malveillant nommé, volume ou lieu précis n'est établi. `CVE-2026-72898` est correctement classée comme vulnérabilité seulement mentionnée, pas comme faille prouvée de cet incident.

Le secteur reste `Inconnu`, alors que Citadium est une enseigne de magasins et de commerce électronique du groupe Printemps. Le secteur attendu est `Commerce / Distribution`. La [page officielle du groupe](https://www.groupe-printemps.com/profil-chiffres-cles) décrit explicitement Citadium parmi ses enseignes et magasins de mode urbaine.

Le volet détail publie encore deux catégories non étayées :

- `informations de commandes`, déduites du rôle de Shipup dans le suivi des commandes et livraisons, sans preuve que ces informations ont été exposées ;
- `identifiants`, extraits d'une phrase de remédiation indiquant que Shipup a renouvelé ses clés et identifiants, pas d'une liste de données clients exposées.

Les données effectivement documentées sont noms, prénoms, adresses e-mail et numéros de téléphone. Les mots de passe et données bancaires apparaissent encore dans les claims bruts comme objets d'un risque futur de phishing, mais le résolveur les écarte correctement de la liste publique pour Citadium.

La chronologie contient aussi un événement propre à Printemps (« informé le 20 août ») et deux formulations redondantes sur les correctifs Metabase du 6 août. L'extracteur de page ne borne pas les faits à la victime courante lorsqu'un article décrit plusieurs clients de Shipup.

Sources : [Cyberattaque.org](https://www.cyberattaque.org/citadium-des-informations-clients-recuperees-lors-de-la-cyberattaque-contre-shipup/), [FrenchBreaches](https://frenchbreaches.com/alertes/citadium-shipup-mtu3vt912q1i17on3ex).

### Printemps — `INC-AFF157A4627F` — correction P1

Cette fiche est la bonne base : la menace est une fuite de données liée à Shipup. Elle reste toutefois séparée de l'observation FrenchBreaches correspondante. Son statut est seulement `reported`, sa localisation reste `Inconnu` et son secteur reste `Inconnu`. Après regroupement correct, la menace doit être `confirmed`, la localisation générale `France métropolitaine` et le secteur `Commerce / Distribution`. Le [site officiel du groupe Printemps](https://www.groupe-printemps.com/printemps) qualifie directement Printemps d'acteur du commerce de la mode, du luxe, de la beauté et du lifestyle.

Le détail contient plusieurs fausses qualifications :

- acteur revendicateur `prestataire`, alors que Shipup est le tiers compromis et qu'aucun attaquant nommé n'est publié ;
- `identifiants`, issu du renouvellement des clés et sessions de Shipup ;
- `données bancaires`, issu d'une conséquence possible et d'une recommandation de ne pas communiquer ses coordonnées bancaires ;
- indicateur `high_sensitivity_data_exposed=true` et type sensible « données bancaires », produits par ce dernier faux positif ;
- `informations de commandes`, déduit du rôle opérationnel du prestataire plutôt que de la liste des données exposées.

Les données soutenues sont les noms, prénoms, adresses e-mail et numéros de téléphone. Le tiers Shipup est correct. `CVE-2026-72898` reste une mention de contexte et ne doit pas être présentée comme exploitation établie pour Printemps. Aucun lieu précis ne doit être déduit de l'adresse du magasin Haussmann ou du siège.

Sources : [Cyberattaque.org](https://www.cyberattaque.org/printemps-les-donnees-clients-derobees-apres-une-cyberattaque-chez-shipup/), [FrenchBreaches](https://frenchbreaches.com/alertes/printemps-shipup-mtu3svqcg9dj6ir9dd5).

### SAD'S Interim — `INC-61993D19E8E2` — restauration P0

Avant la collecte, cet identifiant portait correctement SAD'S Interim, deux observations et les sources Cyberattaque.org et Ransomware.live. La menace ransomware, l'acteur Rhysida, le secteur `Services aux entreprises` et la localisation France métropolitaine sont cohérents avec cette victime.

La collecte remplace seulement son libellé par Printemps, ajoute l'URL FrenchBreaches de Printemps et fait passer le nombre d'observations de deux à trois. Le résumé et le détail restent ceux de SAD'S Interim dans le commit publié. Un rebuild y ajoute en plus les faits de contact de Printemps. Il faut restaurer le nom SAD'S Interim, retirer l'observation et la source Printemps, puis conserver les deux observations historiques de SAD'S Interim.

## Secteurs et localisations indéterminés

Le taux de secteurs inconnus reste à 9 incidents sur 74, soit 12,16 %, au-dessus de la cible de 10 %. Les neuf fiches sont Citadium, Printemps, Medikwestindies, Les Curistes, SPA du Pays de Montbéliard, Accent Rouge, Tisséo, Géofoncier et LebonSiege. Les deux nouvelles observations affichent `NO_ACTIVITY_EVIDENCE` : les appels sémantiques demandent bien `activity_description` et `activity_sector_match`, mais terminent en `miss`. Citadium et Printemps sont immédiatement résolubles en `Commerce / Distribution` avec la référence officielle du groupe.

Le taux de localisations inconnues passe de 5/74 à 4/74, soit 5,41 %, encore au-dessus de la cible de 5 %. Les fiches concernées sont Printemps, SPA du Pays de Montbéliard, Dropbox et Stade Montois Omnisports. L'amélioration d'une unité correspond à Citadium. L'observation FrenchBreaches de Printemps porte bien `France métropolitaine`, mais la fausse fusion l'empêche d'enrichir la bonne fiche Printemps.

## Causes racines

1. Le générateur envoie au LLM des paires sans aucun signal positif d'identité : tous les indicateurs peuvent être faux avec un score flou neutre de 0,5.
2. Le validateur autorise une fusion `SAME/SAME` à partir de la seule confiance déclarée par le modèle, sans exiger que les preuves couvrent les deux organisations ni vérifier une contradiction de noms ou de menaces.
3. Une identité LLM erronée devient un alias global persistant et une fusion d'incident persistante dans le même run.
4. Les arêtes LLM ont priorité sur les rapprochements déterministes par nom, ce qui permet à une mauvaise fusion de bloquer ensuite la bonne.
5. Le registre est persisté avant la construction du site, mais l'état d'identité déjà chargé en mémoire n'est pas rechargé ; incidents et détails ne partagent donc pas la même vue du registre.
6. L'extraction de catégories ne distingue pas encore assez les données exposées, les fonctions du prestataire, les mesures de remédiation et les risques futurs.
7. L'extraction de pages multi-victimes laisse passer dans Citadium des dates propres à Printemps.
8. Les contrôles métier mesurent un corpus fixe et ne recherchent pas les contradictions des regroupements nouvellement appliqués au corpus réel.

## Recette de correction

- supprimer les deux décisions persistées `printemps -> sad s interim` et `ITM-56fe2e286f88ef44|ITM-ec4d0cdfab6fa8df` ;
- regrouper les deux observations Printemps et restaurer la composante SAD'S Interim ;
- interdire l'application d'un verdict LLM `SAME` sans au moins un signal positif d'identité et une preuve mentionnant les deux libellés ;
- opposer un veto aux noms normalisés nettement différents et aux menaces incompatibles lorsque le modèle n'apporte aucune preuve d'alias ;
- appliquer les arêtes exactes/canoniques avant les arêtes LLM ;
- persister et recharger les registres avant toute reconstruction d'incidents ou de faits, puis ajouter un test de rebuild sans diff ;
- filtrer les données issues de remédiations, de risques futurs et de descriptions fonctionnelles ;
- borner la chronologie à la victime courante ;
- ajouter Citadium et Printemps aux références sectorielles en `Commerce / Distribution` ;
- ajouter ce faux rapprochement et les deux volets détail au corpus de régression vivant.
