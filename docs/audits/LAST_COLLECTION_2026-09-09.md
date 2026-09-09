# Audit de la dernière collecte — 9 septembre 2026

**Verdict : la collecte est techniquement réussie et la déduplication des quatre nouveaux incidents est correcte, mais aucune des quatre nouvelles fiches n'est entièrement fiable dans son volet détail.** Les types de menace principaux et les localisations générales sont cohérents. Trois secteurs restent inconnus alors que deux sont directement résolubles et qu'une source officielle permet de résoudre le troisième. Des négations et des risques futurs sont encore publiés comme données exposées ; des CVE seulement contextuelles apparaissent comme « vulnérabilités exploitées ».

## Périmètre

| Élément | Valeur |
|---|---|
| Run | `RUN-20260909T075206` |
| GitHub Actions | [34308754840](https://github.com/Ya7o/Cyberwatch/actions/runs/34308754840) |
| Commit de départ | `a9bba4dd761a7f03bf240703f00eca9c525dac93` |
| Commit publié | `94986c7e70bcaa25d7649ac8c371d690b1a4c7f5` |
| Fenêtre | 8–9 septembre 2026 |
| Corpus après collecte | 124 observations, 72 incidents |
| Ajouts | 7 observations, 4 incidents |
| Durée / requêtes | 107,4 s / 17 |
| Appels LLM / coût | 27 / 0,016522 $ |

L'audit compare le commit précédant la collecte au commit publié, relit les sept nouvelles observations et leurs faits source, examine les traces LLM et les décisions de déduplication, puis exécute réellement `openIncident()` sur les quatre nouvelles fiches avec les JSON publics courants.

La comparaison JSON structurée des 68 incidents préexistants et de leurs volets détail ne trouve **aucune modification publiée** : aucun identifiant n'est retiré et aucun champ d'une ancienne fiche ne change. Les 23 appels `source_facts` ont donc alimenté les caches et reprises sans régression visible sur l'historique. Le delta public se limite exactement aux quatre incidents ajoutés ci-dessous.

Un premier lancement, [34308433114](https://github.com/Ya7o/Cyberwatch/actions/runs/34308433114), s'est arrêté avant publication parce que le contrôle de transport interprétait cinq suppressions éditoriales volontaires comme des pertes accidentelles. Le correctif `a9bba4d` a rendu ces suppressions explicites. Le run audité est le second lancement, réussi et publié ; l'échec précédent n'a ajouté aucune observation.

## Logs de la chaîne

Les quatre sources directes sont `OK` à 100 % : FrenchBreaches (4 items), BonjourLaFuite (2), Cyberattaque.org (4) et Ransomware.live (2). `VEILLE_LLM` reste `PARTIAL` à 99 % : son snapshot régional date du 2 septembre, soit sept jours d'ancienneté pour une limite de deux jours, et n'apporte aucun item dans la fenêtre demandée.

Les 27 appels LLM ont tous réussi : 23 pour `source_facts`, 3 pour l'extraction sémantique Cyberattaque.org et 1 pour la revue dédup. Aucun appel n'a échoué, expiré ou été bloqué par le plafond. Le modèle effectif est `gpt-4o-mini`, malgré `gpt-5-nano` demandé par la configuration. Sur 26 items éligibles aux faits sémantiques, 3 sont entièrement servis par le cache et 23 font l'objet d'un appel. Les métriques enregistrent 35 premiers échecs de champ, 33 reprises de champ, 2 récupérations et 94 nouvelles abstentions.

Les contrôles `cyberwatch check` et les 22 cas métier passent. La surveillance signale toutefois `REVIEW_REQUIRED`, 19 paires de déduplication en attente et 13,89 % de secteurs inconnus, au-dessus de la cible interne de 10 %. La localisation inconnue reste dans la cible à 4,17 %.

## Déduplication

Les regroupements des nouvelles observations sont corrects :

- Aroma-Zone : Cyberattaque.org + FrenchBreaches, 2 observations ;
- Financière d'Uzès : Cyberattaque.org + Ransomware.live, 2 observations ;
- Vision2i : Cyberattaque.org + FrenchBreaches, 2 observations ;
- Proshop FFT : FrenchBreaches seul, 1 observation.

Le filet LLM examine 15 paires, dont 7 depuis le cache. Il ne propose aucune fusion et n'en applique aucune. Les quatre comparaisons impliquant une nouvelle observation opposent Aroma-Zone à Micromania ou Aveyron, et Financière d'Uzès à La financière d'Orion. Les réponses `DIFFERENT` à 0,5 restent `UNKNOWN`, conformément au nouveau seuil : elles sont non concluantes mais ne bloquent aucun regroupement légitime observé ici. Aucun doublon manqué n'est établi parmi les quatre nouveaux incidents.

## Audit des quatre incidents

### Aroma-Zone — `INC-2AF4C7544CC3` — correction P1

Le regroupement et la menace finale « Fuite de données — Confirmé » sont cohérents. L'observation Cyberattaque.org porte encore `Phishing / fraude`, mais le résolveur d'incident corrige ce défaut grâce au résumé et à l'impact. Shipup est correctement identifié comme tiers compromis et la France métropolitaine est cohérente.

Le volet publié contient cependant plusieurs erreurs :

- acteur revendicateur « prestataire — Revendiqué », alors qu'aucun attaquant nommé n'est établi ;
- mots de passe, données bancaires, identifiants et informations de commandes affichés comme données concernées ;
- `CVE-2026-72898` affichée sous « Vulnérabilités exploitées » sans preuve qu'elle est la faille de l'incident Aroma-Zone ;
- secteur inconnu.

Les preuves disent au contraire que les mots de passe, données bancaires, paiements, historiques de commandes et détails de livraison ne seraient pas concernés. Une autre phrase explique seulement que de futurs messages frauduleux pourraient chercher à obtenir des identifiants, mots de passe ou données bancaires. Ces passages de négation et de risque sont transformés en catégories exposées. Les données étayées sont les noms, prénoms, adresses e-mail et numéros de téléphone. Le secteur attendu est `Commerce / Distribution`, activité confirmable par le site officiel d'Aroma-Zone ; la proposition LLM Commerce a été rejetée parce que sa citation ne démontrait pas l'activité.

Sources : [Cyberattaque.org](https://www.cyberattaque.org/aroma-zone-une-cyberattaque-chez-shipup-expose-les-donnees-de-clients/), [FrenchBreaches](https://frenchbreaches.com/alertes/aroma-zone-shipup-mtt6j96rnh5ec06x7w).

### Financière d'Uzès — `INC-09D2AFD7707B` — correction P1

Le regroupement, la menace Ransomware, le secteur Finance / Assurance et la localisation France métropolitaine sont cohérents. Le volume de 70 Go et l'acteur Panzer proviennent d'une revendication.

Le volet transforme néanmoins cette revendication en faits plus forts :

- résumé « La Financière d'Uzès a déclaré avoir subi une cyberattaque », alors que l'article indique qu'aucune confirmation publique de la victime n'a été identifiée ;
- jeu de données « données clients — Confirmé », extrait d'une phrase conditionnelle demandant précisément si les 70 Go contiennent des données clients ;
- localisation précise « Paris — Revendiqué », déduite d'une liste de six bureaux et sans lien avec le lieu de l'incident ;
- volume de 70 Go affiché `Inconnu` et acteur Panzer `Inconnu`, alors que leurs statuts doivent être `Revendiqué`.

La qualification correcte est une revendication de ransomware par Panzer portant sur 70 Go, sans confirmation de la victime ni contenu des données établi. La localisation générale France peut rester ; le lieu précis doit être vide.

Source : [Cyberattaque.org](https://www.cyberattaque.org/financiere-duzes-70-go-de-donnees-volees-apres-une-cyberattaque/).

### Proshop FFT — `INC-72E15EC21567` — correction P1

La menace « Fuite de données », l'acteur LunarisSec et la localisation France métropolitaine sont cohérents. Le texte et les échantillons étayent la présence de données de commandes, noms, adresses et téléphones, tout en conservant la revendication sur le volume total.

Trois informations importantes sont mal publiées :

- le secteur reste inconnu malgré la mention explicite « place de marché de la Fédération Française de Tennis » et le secteur source Commerce ; `Commerce / Distribution` est directement étayé ;
- les 118 000 commandes, acceptées par l'extraction sémantique comme volume revendiqué, disparaissent entièrement du volet parce que l'unité `commandes` n'est pas transportée par le résolveur des volumes affectés ;
- la menace apparaît `Inconnu` au lieu de `Revendiqué`.

Le volet affiche aussi `identifiants` dans les données concernées. Les preuves distinguent des identifiants ou références de commande des identifiants de connexion et disent explicitement que les échantillons ne justifient pas d'affirmer la présence d'identifiants de connexion ou de données bancaires. Le libellé doit rester « références/identifiants de commande », sans signaler des secrets d'authentification.

Sources : [FrenchBreaches](https://frenchbreaches.com/alertes/proshop-fft-mtt46t1ddrdidq2nzgd), [site officiel Proshop FFT](https://proshop.fft.fr/).

### Vision2i — `INC-06870EC77814` — correction P1

Le regroupement, la menace « Fuite de données — Revendiqué », l'acteur Sophia et la localisation France métropolitaine sont cohérents. L'absence de volume est justifiée : aucun nombre total de contacts n'est donné.

Le détail publié est trompeur sur les données et le vecteur :

- `mots de passe — Inconnu` est affiché alors que les deux sources expliquent que le champ `hash` ne doit pas être assimilé à un mot de passe et qu'aucun mot de passe en clair n'est observé ;
- `CVE-2026-12757`, `CVE-2026-1651` et `CVE-2026-81290` sont affichées sous « Vulnérabilités exploitées » ;
- un CVSS 6,5/10 est rattaché à l'incident ;
- les sources disent explicitement qu'aucun élément ne permet d'établir qu'une de ces failles est le vecteur et que le scénario reste inconnu ;
- la chronologie duplique plusieurs formulations éditoriales, conserve un fragment Markdown `**` et affiche la publication de la CVE comme événement de l'incident ;
- le secteur reste inconnu.

Le validateur a correctement supprimé le vecteur `vulnerability_exploitation` proposé par le LLM, car sa preuve constatait seulement la publication d'une CVE. En revanche, la liste générique des CVE contourne cette validation et le renderer les présente toutes comme exploitées. Le secteur proposé `Numérique / Technologie` était fondé uniquement sur l'utilisation de WordPress et a été correctement rejeté. Le site officiel décrit Vision2i comme une agence de communication et de conseil située à Orvault ; la taxonomie attendue est `Services aux entreprises` avec cette preuve externe.

Sources : [Cyberattaque.org](https://www.cyberattaque.org/vision2i-une-cyberattaque-expose-une-base-de-contacts-de-son-site-wordpress/), [FrenchBreaches](https://frenchbreaches.com/alertes/vision2i-mtt59zu9f60dfx10m5g), [site officiel Vision2i](https://vision2i.fr/).

## Causes communes

1. L'extraction lexicale des catégories de données ne borne pas suffisamment les négations, exclusions et risques futurs. Elle publie ainsi des mots de passe ou données bancaires explicitement absents.
2. La détection de vulnérabilités conserve les CVE mentionnées comme contexte. Leur statut et leur relation avec l'incident disparaissent ensuite, tandis que l'interface les intitule toutes « Vulnérabilités exploitées ».
3. Le statut d'une proposition conditionnelle contenant « confirme » peut devenir `confirmed`, même lorsque la phrase demande si une confirmation existe.
4. Le vocabulaire des volumes affectés ne transporte pas l'unité `commandes`, bien que la réponse LLM soit acceptée et conservée dans les faits riches.
5. Le générateur de résumé n'impose pas que l'acteur grammatical de « a déclaré » soit soutenu par la citation ; une apparition sur un site de ransomware devient une déclaration de la victime.
6. Le validateur sectoriel bloque à raison les preuves qui décrivent WordPress ou Shipup à la place de la victime, mais ne récupère pas automatiquement les preuves valides déjà présentes pour Proshop FFT et ne consulte pas de référence officielle pour Aroma-Zone ou Vision2i.

## Recette attendue

- retirer les catégories issues de négations, d'exclusions et de scénarios de risque ;
- distinguer vulnérabilités mentionnées, vulnérabilités candidates et vulnérabilités effectivement exploitées jusqu'au renderer ;
- transporter `commandes` comme unité de volume d'enregistrements avec le statut revendiqué ;
- refuser les résumés attribuant une confirmation ou une déclaration à la victime sans citation correspondante ;
- ajouter des références d'activité pour Aroma-Zone, Proshop FFT et Vision2i ;
- rejouer les quatre incidents jusqu'au HTML et ajouter ces contre-exemples aux tests métier.

Cet audit n'a modifié ni les données canoniques ni le site publié et n'a lancé aucun appel LLM supplémentaire.
