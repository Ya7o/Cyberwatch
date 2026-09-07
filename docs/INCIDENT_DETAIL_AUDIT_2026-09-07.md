**Audit de la chaîne de qualification du volet incident — 7 septembre 2026**

**Verdict : la chaîne transporte correctement ses résultats, mais ne garantit pas encore une qualification fiable.** Des erreurs avérées de vecteur, de niveau de preuve et de périmètre des volumes arrivent jusqu'au volet. Une partie du travail d'extraction est ensuite perdue au rendu. La priorité est la fidélité des faits et de leurs preuves avant d'augmenter le nombre de champs renseignés.

Périmètre : checkout local avec ses modifications préexistantes, 54 observations et 35 incidents. Inspection de l'interface locale dans un navigateur, rendu automatisé des 35 fiches, recalcul hors réseau des faits et contre-exemples ciblés. Le site public n'a pas été réaudité : ce rapport ne certifie pas sa version actuelle. Aucun appel LLM, aucune collecte, aucune modification du code métier ou des données canoniques, aucun commit ni déploiement. Seuls ce rapport et `audit/incident_detail_2026-09-07/` sont créés.

**Ce qui fonctionne et ce que les mesures signifient**

Le chemin examiné est extraction → `source_facts.csv` → projection par source → résolution par incident → `facts.json` et `incidents.json` → `openIncident()`.

Les 35 incidents ont tous une fiche au format v3. Le recalcul des 35 détails à partir des observations et faits canoniques reproduit exactement les JSON présents : les défauts décrits ne sont donc pas simplement des artefacts oubliés après une correction. La séparation entre faits source et vue résolue est utile, ainsi que la déduplication des volumes, les garde-fous de propagation et les reprises sémantiques déjà ajoutées. L'ouverture, la fermeture et le découpage du volet fonctionnent sur les deux fiches inspectées visuellement.

| Mesure sur le corpus local | Résultat | Lecture |
|---|---:|---|
| Incidents avec détail v3 | 35/35 | Bonne disponibilité structurelle |
| Écarts entre recalcul et détails présents | 0/35 | Transmission reproductible |
| Champs scalaires présents dans les détails | 49 | Hors menace, secteur et localisation générale |
| Scalaires avec citation conservée dans le JSON | 47/49 | Preuves disponibles mais non exploitées par leurs lignes du volet |
| Scalaires au statut inconnu | 19/49 | Le niveau de preuve n'est pas renseigné, même si la valeur existe |
| Catégories de données au statut inconnu | 113/128 | 88,3 % ; absence de statut masquée par le rendu |
| Volumes au statut inconnu | 16/33 | 48,5 % ; aucune étiquette « Inconnu » affichée |
| Catégories de données supprimées au rendu | 26/128 sur 14 fiches | 20,3 % des entrées acceptées en amont |
| Secteurs inférés ou référencés | 23/35 | Leur ligne affiche le badge générique « Documenté » |

La couverture reste inégale : acteur sur 13 fiches, vecteur sur 5, tiers sur 2, impact sur 15, remédiation sur 1, volumes sur 18 et chronologie sur 23. Aucune date d'attaque scalaire ni vulnérabilité structurée n'est présente. Ces absences ne prouvent pas à elles seules une extraction ratée : il faudrait annoter les articles complets pour distinguer absence de preuve et fait manqué. Aucun taux global d'exactitude ni coût par qualification fiable n'est déduit de ce petit corpus historique.

**1. P1 — Un vecteur contredit par sa citation reste publié.**

Cas réel : **Zéro Logement Vacant** affiche « Exploitation d'une vulnérabilité — Revendiqué ». La preuve associée indique au contraire que l'attaquant ne revendique pas l'exploitation d'une vulnérabilité précise et déclare avoir disposé d'une session superutilisateur valide. Le recalcul reproduit cette sortie sans alerte.

`_initial_access_is_publishable()` reconnaît des marqueurs techniques dans la preuve, mais ne vérifie pas que le vecteur choisi est affirmé positivement. La présence du mot « vulnérabilité » suffit ici à laisser passer la valeur, malgré la négation. La preuve n'est pas passée à `detailField()` pour ce champ, ce qui empêche de détecter la contradiction depuis la ligne du volet.

Correction : vérifier la polarité et la correspondance entre le vecteur et sa preuve, puis réappliquer ce contrôle à la publication des faits historiques. Pour ce cas, retirer le vecteur erroné et conserver la session déclarée avec son statut, sans déduire son mode d'obtention.

Points de code : `cyberwatch/fact_resolution.py:453`, `assets/dashboard-v2.js:672`. Reproduction : `cases.real_vector_negation`.

**2. P1 — Le statut de l'article devient indûment celui des faits ; le résumé perd les réserves.**

Sur la même fiche, les deux étapes du déroulé portent **Confirmé**, alors que leurs preuves sont des déclarations de l'attaquant. `_attack_flow_entries()` applique `claim_status` de la ligne source à toutes les étapes. `resolve_scalar()` fait également hériter ce statut aux champs scalaires, avec quelques exceptions lexicales seulement.

Un contre-exemple isolé conserve ainsi « BlackCat — Confirmé » dans le champ acteur alors que la citation et le claim riche indiquent une attribution hypothétique. Un autre transforme une étape explicitement démentie en étape confirmée. Ces cas prouvent un défaut de frontière de publication ; ils ne mesurent pas sa fréquence en collecte.

Le résumé de Zéro Logement Vacant affirme aussi une exposition de 48 millions de personnes alors que les preuves riches qualifient le volume dédupliqué de revendiqué. `build_display_summary()` valide le caractère publiable du texte sans confronter chaque affirmation aux statuts des faits résolus.

Correction : transporter un statut par affirmation depuis l'extraction, conserver les démentis et hypothèses comme réserves, puis contrôler la cohérence résumé/détail. Le succès technique d'une extraction ne doit pas devenir un niveau de preuve.

Points de code : `cyberwatch/fact_resolution_counts.py:198`, `cyberwatch/fact_resolution.py:588`, `cyberwatch/fact_resolution.py:889`. Reproductions : `scalar_status_inheritance`, `attack_flow_status_inheritance`, et exemple réel Zéro Logement Vacant.

**3. P1 — Un bilan mensuel de groupe est présenté comme le volume d'un incident.**

Cas réel : **Jouvet SAS** affiche « 157 victimes — Revendiqué » dans son volume documenté. La preuve précise que Qilin a revendiqué 157 victimes pendant août 2026 et était le groupe le plus actif du mois. Ce nombre décrit l'activité du groupe, pas les personnes affectées chez Jouvet SAS ; son unité structurée est pourtant `people`.

Le filtre `_incident_count_is_publishable()` cible quelques chiffres de contexte commercial, mais ne contrôle pas le rattachement du nombre à l'organisation et à l'événement. Le compteur riche puis la projection historique traversent la résolution. Le rendu retire ensuite la citation qui aurait révélé l'erreur.

Correction : conserver sujet, unité et périmètre du décompte ; exclure les bilans d'acteur, statistiques sectorielles et autres chiffres de contexte du volume de la victime. Le rejet doit également neutraliser les copies historiques de la même mesure.

Points de code : `cyberwatch/fact_resolution_counts.py:318`, `cyberwatch/fact_resolution_counts.py:658`, `assets/dashboard-v2.js:579`. Reproduction : `real_group_monthly_count`. Vérifié dans le navigateur et dans les données recalculées.

**4. P2 — La fiche perd la traçabilité et une partie des niveaux de preuve.**

Les 47 citations attachées aux scalaires dans `facts.json` ne sont pas transmises aux lignes correspondantes du volet. Les 33 volumes conservent leur preuve dans le JSON, mais le rendu l'ignore. Les citations des catégories de données et des systèmes/périmètres sont déjà supprimées pendant la résolution. Le regroupement des systèmes et jeux de données en simples chaînes retire ensuite leurs statuts.

Les liens « Sources » sont globaux : ils n'indiquent pas quel article justifie chaque valeur. Certaines autres preuves, comme le déroulé ou la chronologie, ne sont disponibles qu'en infobulle. Enfin, `statusBadge()` masque `unknown` et remplace `inferred`/`referenced` par « Documenté ». Le chip du secteur en tête conserve la nuance, mais sa ligne de qualification emploie un autre vocabulaire.

Correction : conserver preuve et source par valeur, proposer un accès compact à ces preuves dans la fiche, préserver les statuts des systèmes fusionnés et employer des libellés explicites et cohérents. La citation peut rester repliée ; elle doit être consultable au clavier et sur écran tactile.

Points de code : `cyberwatch/fact_resolution.py:150`, `cyberwatch/fact_resolution.py:231`, `cyberwatch/fact_resolution.py:527`, `assets/dashboard-v2.js:572`, `assets/dashboard-v2.js:660`.

**5. P2 — La priorité fixe des sources masque les arbitrages et certaines réserves.**

`resolve_scalar()` retient la première valeur selon l'ordre des sources et ne signale pas les valeurs concurrentes. Sur **Jouvet SAS**, le statut inconnu de Ransomware.live est conservé pour Qilin malgré un fait concordant au statut revendiqué chez Cyberattaque.org. Le volet affiche donc le nom sans badge.

Dans le contre-exemple `conflicting_scalar`, une date revendiquée au 1er septembre l'emporte silencieusement sur une date confirmée au 4 septembre. Les sept différences brutes de scalaires trouvées dans le corpus ne sont pas sept contradictions : elles comprennent des reformulations et des variations de casse.

Par ailleurs, les réserves conservées uniquement dans `claims` ne sont pas lues par le volet. Le cas `denial_only` produit une fiche sans la réserve indiquant l'absence de mots de passe exposés. Il n'est pas nécessaire de réintroduire toute l'ancienne liste de claims : les démentis et contradictions utiles peuvent être affichés de manière ciblée.

Correction : distinguer corroboration, contradiction et complément ; justifier le choix d'une valeur quand les preuves divergent, et préserver les réserves qui changent la lecture de l'incident.

Points de code : `cyberwatch/fact_resolution_counts.py:198`, `cyberwatch/fact_resolution.py:525`, `assets/dashboard-v2.js:664`. Reproductions : `conflicting_scalar`, `denial_only`, exemple Jouvet SAS.

**6. P2 — Le classement visuel supprime des catégories déjà acceptées par le serveur.**

Huit libellés distincts, soit 26 entrées réparties sur 14 fiches, sont éliminés par `dataTypeFamily()` : contrats, montants, données comptables, informations de commandes, données personnelles, données RH, clients/pharmacies/revendeurs, commentaires.

Certains libellés méritent une normalisation ou un déplacement vers le périmètre ; cela ne justifie pas leur disparition silencieuse après publication. La fonction retourne `null` si aucune famille ne correspond, puis `dataTypesHtml()` ignore l'entrée. Les contrôles serveur ne peuvent pas détecter cette perte ultérieure.

Correction : canoniser ou rejeter explicitement en amont ; rendre toutes les catégories acceptées, avec un regroupement adapté. Ajouter une vérification de conservation entre JSON et HTML, sans imposer un nouveau panier générique dans l'interface.

Points de code : `assets/dashboard-v2.js:517`, `assets/dashboard-v2.js:539`. Mesure : `render_evidence.json`, `dropped_occurrences` et `affected_incidents`.

**7. P2 — Une panne de chargement devient une absence durable de faits.**

`loadJson()` transforme un échec réseau en `{}`. `ensureFacts()` mémorise cet objet et ne réessaie plus pendant la session. Deux tentatives simulées n'effectuent qu'un seul fetch. Le volet affiche ensuite « Aucun élément structuré supplémentaire », comme si l'incident était réellement pauvre en informations. La qualification détaillée est également cachée puisque tout le bloc dépend de la validité du détail v3.

Correction : distinguer chargement, erreur, absence et résultat disponible ; proposer une reprise et mémoriser uniquement un résultat valide. Garder accessibles les qualifications déjà chargées avec l'incident.

Points de code : `assets/dashboard-v2.js:79`, `assets/dashboard-v2.js:456`, `assets/dashboard-v2.js:658`. Reproduction contrôlée dans `render_probe.cjs`, sans panne réseau réelle.

**8. P2 — Le signal de données de personnes vulnérables ignore les négations.**

Ce défaut concerne les indicateurs associés à la fiche. `data_sensitivity._context()` concatène les claims sans filtrer leur statut. Un claim démentant toute exposition de données d'enfant active malgré tout `vulnerable_people_data_exposed`, `high_sensitivity_data_exposed` et `sensitive_data_exposed`. Les contrôles de cohérence ne le détectent pas car les booléens sont cohérents entre eux.

Correction : calculer les indicateurs sur les affirmations positives rattachées à l'exposition, avec leur statut et leur sujet. Une simple mention d'enfant dans un contexte négatif ne suffit pas.

Points de code : `cyberwatch/data_sensitivity.py:36`, `cyberwatch/data_sensitivity.py:64`. Contre-exemple synthétique `negative_vulnerable_exposure` ; aucune fréquence d'erreur réelle n'est avancée.

**Recette et ordre recommandé**

1. Corriger les trois P1 et reprendre les fiches affectées sur une copie des données : vecteur contraire à sa preuve, confirmation indue, nombre hors périmètre.
2. Fiabiliser le contrat de chaque fait : valeur, statut, sujet/périmètre, citation et source. Réconcilier les résumés avec ces faits et rendre les divergences utiles visibles.
3. Corriger les pertes au rendu et l'état d'erreur de chargement. Conserver le regroupement compact et les sections repliables déjà choisis.
4. Étendre la recette à extraction → résolution → JSON → HTML avec les cas du rapport, puis mesurer sur des articles annotés la précision, le rappel des faits utiles, la fidélité des statuts et le taux de preuves consultables. Rapporter séparément absences réelles, rejets, erreurs techniques et faits acceptés mais perdus.

La suite existante passe : **1 056 tests en 6,58 s**, `cyberwatch check` valide 54 items/35 incidents, et le corpus `validate-business` passe ses **22 cas**. Les tests du volet inspectent principalement des fragments de code : ils vérifient la présence de badges et de sections, sans établir que la preuve soutient la valeur affichée. Ces succès ne réfutent donc pas les contre-exemples.

**Dossier de preuve**

- `audit/incident_detail_2026-09-07/reproduce.py` : mesures, recalcul, cas réels et cas synthétiques ; écrit `evidence.json`.
- `audit/incident_detail_2026-09-07/render_probe.cjs` : exécute les vraies fonctions JavaScript avec un DOM minimal ; écrit `render_evidence.json`, avec HTML des 35 fiches et des cas synthétiques.
- `audit/incident_detail_2026-09-07/reproduction.log` : sortie du script Python.

Rejeu depuis la racine WSL : `rtk proxy .venv/bin/python audit/incident_detail_2026-09-07/reproduce.py`, puis `rtk proxy node audit/incident_detail_2026-09-07/render_probe.cjs`. Le code de sortie zéro signifie que les sondes se sont exécutées ; les résultats attendus et observés s'interprètent selon les constats ci-dessus. Les empreintes du code et des JSON audités sont conservées dans `evidence.json`.
