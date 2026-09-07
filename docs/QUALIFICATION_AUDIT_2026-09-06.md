**Audit de la qualification secteur, menace et localisation — 6 septembre 2026**

**Mise en œuvre locale du 7 septembre 2026.** Les sept constats techniques de
ce rapport sont corrigés dans le checkout local : résolution sectorielle
branchée, négations et priorités de menace stabilisées, rattachement territorial
durci, lieux fins transmis, cohérence activité/citation contrôlée, faits périmés
révoqués et file de reprise persistante ajoutée. Les contre-exemples `T1` à
`R2` passent désormais. Cette mention ne signifie ni commit, ni push, ni
déploiement ; l'analyse de la version publique ci-dessous reste le constat
historique effectué le 6 septembre.

Validation de la mise en œuvre : **1 056 tests**, Ruff, mypy sur 14 modules,
budget de complexité, syntaxe JavaScript, corpus métier de 22 cas, audit
sectoriel et matérialisation du cache sans écart.

**Verdict : la chaîne publiée n'est pas suffisamment qualifiée pour considérer les prochaines collectes comme fiables sur ces trois dimensions.** La correction sectorielle locale améliore la transmission des faits, mais elle n'est pas intégrée au `main` distant vérifié. Le code local présente encore des erreurs reproductibles de menace, de territoire et de validation des activités. Un taux faible d'inconnus ne mesure pas l'exactitude.

Audit réalisé en lecture seule du corpus et des services publics. Aucun appel LLM, aucune collecte réelle, aucune modification du code métier, aucun commit ni déploiement. Les seuls livrables créés sont ce rapport et le dossier `audit/qualification_2026-09-06/`.

**Périmètre et mesures observées**

Le checkout local repose sur `374c9d66b42f9cbe135480cbad2e5aabd9961306`, avec de nombreuses modifications préexistantes. `git ls-remote` donne `d664601c6b14777fba725c0c9c7606ed49c97631` pour le `main` distant. Le code de ce commit et les JSON GitHub Pages ont été capturés le 6 septembre vers 17:00 UTC ; le snapshot servi est daté du 6 septembre.

| Mesure | Site publié / main distant | Corpus local |
|---|---:|---:|
| Incidents | 62 | 35 |
| Secteur inconnu | **43 / 62 — 69,4 %** | 0 / 35 — 0 % |
| Localisation inconnue | **7 / 62 — 11,3 %** | 1 / 35 — 2,9 % |
| Menace inconnue | 0 / 62 | 0 / 35 |
| Menaces classées « Fuite de données » | 55 / 62 | 22 / 35 |

Ces corpus sont différents : ce tableau n'est pas un avant/après de correction. Les 54 observations locales disposent de 54 lignes de faits. Aucun écart de transmission sectorielle n'est signalé sur ce snapshot par le contrôle existant.

Sur les 54 décisions sectorielles locales, 24 reposent sur `REFERENCE_EXACT` et 13 portent encore la provenance historique `EXISTING_SECTOR` / `confirmed`. En retirant expérimentalement les références exactes et les anciennes valeurs de secteur, tout en conservant faits, règles nominatives, watchlists et registres de déduplication, **21 des 35 incidents restent inconnus**. Cette ablation mesure une dépendance au travail historique ; elle ne prédit pas un taux futur d'inconnus et ne constitue pas une mesure d'exactitude.

Le résolveur sémantique SourceFacts vise FrenchBreaches et Cyberattaque.org. Les autres sources utilisent surtout leurs données natives et les règles déterministes. Le référentiel peut classer une organisation connue, mais ne remplace pas une extraction correcte pour une nouvelle victime.

**Constats classés par priorité**

**1. P1 — Les prochaines collectes distantes n'utiliseront pas les corrections sectorielles locales.**

Au commit distant examiné, `cyberwatch/sector_resolution.py`, `cyberwatch/threat_resolution.py` et `data/sector_resolution.csv` sont absents. La fonction distante `finalize_snapshot(items)` enrichit les items sans recevoir les faits extraits. La rupture de transmission décrite dans l'audit du 5 septembre n'est donc pas corrigée dans cette version publiée. Les JSON servis et le CSV distant concordent sur les 43 secteurs inconnus.

Action : préparer une intégration revue du chemin de qualification corrigé sur la version distante, puis une reprise ciblée du corpus existant. Une simple prochaine collecte aujourd'hui/hier ne reprend pas l'extraction de tout l'historique. Ne pas publier aveuglément l'ensemble des modifications locales.

Preuve : [code distant capturé](../audit/qualification_2026-09-06/public/main/cyberwatch/enrichment.py), [manifeste HTTP et empreintes](../audit/qualification_2026-09-06/public/manifest.json), [JSON effectivement servi](https://ya7o.github.io/Cyberwatch/assets/data/incidents.json).

**2. P1 — La stabilisation des menaces réintroduit des négations et écrase des informations spécifiques.**

Trois contre-exemples atteignent le champ `Incident.Menace` :

| Entrée | Résultat attendu | Résultat observé localement |
|---|---|---|
| « intrusion dans la messagerie, aucune fuite de données identifiée » | Intrusion | **Fuite de données** |
| « intrusion confirmée, aucun ransomware détecté » | Intrusion | **Ransomware** |
| Flux FrenchBreaches : titre « Acme », résumé mentionnant un ransomware avec exfiltration, défaut natif « Fuite de données » | Ransomware | **Fuite de données** |

Dans le premier cas, la normalisation initiale renvoie correctement Intrusion. La recherche brute du mot « fuite » dans `stabilize_threats` annule ensuite la négation. Dans le troisième, le ransomware est également reconnu à l'ingestion, puis écrasé par `Threat_Raw`, qui contient le défaut du flux. Le résolveur local ne recherche pas le ransomware dans les résumés et impacts des faits pour le rétablir. Sa recherche dans les titres ne traite pas non plus les négations.

La fonction `stabilize_threats` est structurellement identique dans le code local et distant capturé. Les preuves de sortie d'incident portent sur la version locale ; le défaut de stabilisation est aussi présent dans le code distant.

Action : transporter une décision assortie de preuve et de polarité ; appliquer la même politique à l'ingestion et à l'agrégation. Un défaut de source ne doit pas écraser une menace spécifique étayée. Distinguer l'événement, son vecteur et un risque futur.

Points de code : `cyberwatch/enrichment.py:199`, `cyberwatch/threat_resolution.py:135`, `cyberwatch/threat_resolution.py:150`. Reproductions : `T1`, `T2`, `T3`.

**3. P1 — Le territoire peut provenir d'un tiers ou d'un simple nombre ; les conflits sont masqués.**

« Intrusion confirmée en France métropolitaine ; son prestataire est à La Réunion » produit **La Réunion** pour la victime. « Fuite de 97400 comptes clients » produit également **La Réunion**, car le nombre correspond à l'expression régulière d'un code postal.

Deux observations du même incident portant respectivement France métropolitaine et Mayotte sont fusionnées puis qualifiées France métropolitaine : l'égalité est tranchée par ordre alphabétique, sans abstention explicite. Le contrat de priorité VEILLE_LLM existe, mais ne résout pas cette ambiguïté entre sources directes.

Par ailleurs, un `Fine_Location` étayé « Saint-Denis de La Réunion » n'est pas consommé par la qualification de `Incident.Localisation` : une valeur France déjà présente reste France. Ce contre-exemple démontre l'absence de transmission ; il n'établit pas qu'une telle erreur réunionnaise existe dans le corpus actuel, dont les six localisations fines renseignées sont métropolitaines.

Action : rattacher le lieu à la victime et à l'incident, exiger un contexte d'adresse pour les codes postaux, distinguer preuve explicite et défaut de source, puis résoudre les désaccords. Exploiter les faits de lieu lorsque leur rattachement est validé, avec motif, statut et provenance comparables au secteur.

Points de code : `cyberwatch/normalize.py:478`, `cyberwatch/normalize.py:484`, `cyberwatch/dedup.py:395`, `cyberwatch/dedup.py:460`, `cyberwatch/enrichment.py:237`. Les fonctions de localisation examinées sont identiques localement et à distance. Reproductions : `L1` à `L4`.

**4. P1 — Une citation valide peut justifier une activité qui la contredit.**

Avec la citation littérale « Acme commercialise en ligne des chaussures », la réponse sémantique « éditeur de logiciels » + « Numérique / Technologie » est acceptée, sans motif de rejet, puis devient le secteur de l'incident.

Le validateur vérifie que la citation existe, qu'elle nomme la victime et qu'elle contient un vocabulaire d'activité. Il ne vérifie pas la cohérence de l'activité proposée avec cette citation. Le résolveur classe ensuite la description proposée : description et secteur erronés mais cohérents entre eux passent donc ensemble.

Action : comparer également la qualification à la preuve source. Une contradiction explicite entre l'activité de la citation et la description proposée doit entraîner un rejet ou un arbitrage, même avec une confiance LLM élevée. Conserver les contrôles utiles contre l'activité d'un fournisseur.

Points de code : `cyberwatch/sector_activity.py:49`, `cyberwatch/source_facts_ai_activity.py:42`, `cyberwatch/source_facts_ai_activity.py:64`. Reproduction : `S1`. Le cas synthétique prouve une faiblesse du validateur ; il ne mesure pas la fréquence des erreurs du modèle réel.

**5. P1 — Une activité retirée d'un article peut rester qualifiante après deux abstentions.**

Rejeu : un fait d'activité appartient au contenu A. Le contenu B ne permet plus de le valider. Au premier `miss`, la fusion conserve l'activité et remplace le hash A par B. Au deuxième passage sur B, le statut devient `abstained`, mais `content_changed` vaut désormais faux : l'ancienne activité n'est jamais retirée. Le secteur reste Commerce / Distribution dans la reproduction, malgré les deux statuts d'activité `abstained`.

Action : conserver l'identité du contenu qui a justifié chaque valeur, ou un état explicite de revalidation en cours. Le deuxième rejet doit pouvoir invalider la valeur héritée sans nécessiter une nouvelle modification de l'article.

Points de code : `cyberwatch/source_facts_handlers.py:407`, `cyberwatch/source_facts_handlers.py:412`, `cyberwatch/source_facts_handlers.py:428`. Reproduction : `R2`, avec passage par la sanitation puis la finalisation.

**6. P2 — Un mauvais enrichissement sectoriel peut supprimer une donnée native indépendante.**

Un secteur structuré `Manufacturing` correctement normalisé devient Inconnu si un fait d'activité existe mais cite uniquement un fournisseur. Le rejet de l'activité retourne immédiatement une décision inconnue, sans conserver le secteur natif pourtant disponible. C'est une perte de couverture évitable, distincte d'un véritable conflit entre deux preuves valides.

Action : rejeter la mauvaise activité tout en conservant la qualification native au niveau `reported`, sauf contradiction pertinente documentée. Tester aussi les secteurs sémantiques orphelins.

Point de code : `cyberwatch/sector_resolution.py:34`. Reproduction : `S2`.

**7. P2 — Les reprises de qualification sont dépendantes de la courte fenêtre de collecte.**

La limite spécialisée est de 30 appels SourceFacts par processus, avec un plafond financier partagé de 0,03 $ dans le workflow local. Un article riche peut consommer deux passes : 15 articles entièrement non cachés de ce type suffisent à épuiser les 30 appels, avant les autres coûts éventuels. Les sources sont traitées séquentiellement, FrenchBreaches avant Cyberattaque.org.

Les blocages locaux sont désormais tracés, ce qui est utile. Mais la collecte ne possède pas de file persistante de reprise des champs différés comparable à celle de la déduplication. Un article publié hier dont l'extraction est bloquée aujourd'hui sort demain de la fenêtre. Ses faits existants sont conservés ; son contenu n'est plus automatiquement soumis à l'extraction. Une panne, une clé manquante ou un budget épuisé peuvent ainsi laisser une qualification incomplète durablement.

Ce risque est établi par le chemin de contrôle, sans test de charge API ni mesure d'un budget réellement épuisé pendant cet audit. Certains nouveaux champs, dont `fine_location`, passent en outre à `abstained` dès leur première absence normalisée ; le cache ne distingue pas alors une absence réelle d'une valeur rejetée récupérable.

Action : une file bornée par item, hash et champ, avec motif et âge, traitée indépendamment de la fenêtre de nouvelles publications ; priorité aux champs essentiels et répartition explicite du budget. Réessayer les erreurs techniques ou récupérables, pas les absences démontrées.

Points de code : `cyberwatch/source_facts_ai_runtime.py:65`, `cyberwatch/source_facts_ai.py:727`, `cyberwatch/source_facts_ai.py:907`, `cyberwatch/source_facts_ai.py:955`, `cyberwatch/runner.py:635`.

**Validation et portée des résultats**

La suite existante passe : **1 044 tests en 7,21 s**. `cyberwatch check` passe sur les 54 items / 35 incidents. `validate-business` passe ses **18 cas** ; ses contrôles de déduplication retrouvent les 16 doublons attendus sans fusion abusive connue.

Le corpus métier évalue principalement les classificateurs isolés. Il ne protège pas suffisamment les transitions ingestion → stabilisation → faits → agrégation : `classify_threat` peut passer son test de négation puis être contredit par la finalisation.

Le script d'audit contient **10 contre-exemples**, deux témoins positifs et un contrôle montrant que la finalisation recalcule les anciens incidents à partir des faits disponibles. Ce dernier nuance la documentation : conserver les anciennes observations n'équivaut pas à figer leurs qualifications. Les cas adversariaux ont été choisis pour exposer les défauts ; leur ratio d'échec n'est pas un taux d'erreur estimé pour la production.

Les métriques actuelles mesurent surtout les inconnus sur tout le corpus. Elles ne suffisent pas pour suivre les nouvelles organisations, les classements fondés sur un défaut, les preuves rejetées, les contradictions et les reprises en attente. Les deux lignes de métriques de production locales ont les déclencheurs `unknown` et `local` : elles ne prouvent pas sept collectes planifiées consécutives réussies. Les fichiers locaux d'usage LLM consultés n'ont pas de `run_id` ; leurs coûts ne sont pas utilisés ici comme preuve d'efficacité de la version courante.

**Ordre de correction et recette avant mise en service**

1. Corriger les négations et les pertes de menace spécifique, puis les faux territoires et les conflits ; ajouter les cas d'audit comme régressions de bout en bout.
2. Corriger la cohérence activité/citation et la révocation des faits lors des reprises. Conserver la bonne transmission sectorielle déjà présente localement.
3. Préparer une version intégrable depuis le `main` distant, avec reprise ciblée sur une copie de ses 62 incidents et préservation des identifiants. Vérifier les résultats sur ce même corpus avant publication.
4. Ajouter la reprise des champs différés et mesurer les seules nouveautés par source : précision sur cas annotés, couverture étayée, inconnus réels, conflits, défauts utilisés, âge de la file, coût par observation et par qualification utilisable.
5. Vérifier après intégration la correspondance décisions → CSV → JSON servi et suivre sept collectes planifiées. Ne pas assimiler HTTP 200, succès LLM ou zéro inconnu à une qualification correcte.

Critères minimaux : zéro négation transformée en fait positif dans les cas de recette ; zéro menace spécifique perdue derrière un défaut ; zéro localisation attribuée sur un nombre ou un tiers ; contradictions géographiques explicites ; rejet d'une activité contredite par sa citation ; invalidation effective après reprise ; aucune preuve validée perdue jusqu'au JSON. Les cas réellement sans preuve doivent rester inconnus.

**Dossier reproductible**

- [Résultats structurés et empreintes du code / corpus local](../audit/qualification_2026-09-06/evidence.json).
- [Script de reproduction hors ligne](../audit/qualification_2026-09-06/reproduce.py).
- [Sortie de reproduction](../audit/qualification_2026-09-06/reproduction.log).
- [Capture distante et manifeste](../audit/qualification_2026-09-06/public/manifest.json).
- [Script de capture publique en lecture seule](../audit/qualification_2026-09-06/fetch_public.py).

Depuis la racine sous WSL : `rtk proxy .venv/bin/python audit/qualification_2026-09-06/reproduce.py`. Le script écrit uniquement ses résultats d'audit. Son code de sortie zéro signifie que le diagnostic a été exécuté, pas que les contre-exemples ont réussi. `evidence.json` contient les valeurs attendues, observées et le champ `meets_expectation` pour chaque cas.

**État au 7 septembre : correctifs appliqués et validés localement ; aucun push
ni déploiement effectué.**
