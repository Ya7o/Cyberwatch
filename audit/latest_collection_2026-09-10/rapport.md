**Audit de la dernière collecte — RUN-20260910T072351**

Collecte locale du 10 septembre 2026 à 07:23:51 UTC+4, fenêtre du 9 au 10 septembre. Code déclaré : `5d5fda27bf04c5b07fdccd579c1c2b9e80fc5a4d`. Audit de l'état local et des artefacts générés ; déploiement distant non vérifié. Le corpus comportait déjà des changements non commités à l'ouverture de l'audit.

**Verdict : la chaîne ne fonctionne pas correctement de bout en bout sur les nouveautés.** Deux sources décrivent la même cyberattaque contre la mairie du Tampon, mais produisent deux incidents distincts et deux menaces spécifiques non étayées. Un vecteur d'accès hypothétique devient même « confirmé ». Les deux localisations sont correctes. L'extraction et la déduplication LLM sont désactivées (`API_KEY_MISSING`).

Le périmètre principal contient exclusivement les deux nouveaux items. Les quatre articles Citadium/Printemps sont mentionnés uniquement parce que leurs extractions en cache ont été réutilisées dans ce run. Tarnos intervient exclusivement comme candidat de déduplication contre un nouvel item. Aucun audit général de l'historique n'a été réalisé.

**Ce que la collecte a effectivement traité**

| Indicateur du run | Valeur | Interprétation |
|---|---:|---|
| Articles repérés dans la fenêtre | 7 | 3 FrenchBreaches + 4 Cyberattaque.org |
| Observations retenues | 6 | 2 nouvelles + 4 déjà présentes ; 1 article sans victime rejeté |
| Nouveaux incidents enregistrés | 2 | Les deux nouvelles fiches du Tampon |
| Appels LLM / tokens / coût | 0 / 0 / 0 $ | Pas d'extraction nouvelle et pas de décision LLM |
| Événements d'extraction désactivée | 8 | Deux passes pour chacun des 4 articles partiellement ou non couverts par le cache |
| Valeurs acceptées réutilisées depuis le cache | 17 | Sur les 4 articles Citadium/Printemps ; aucune sur les 2 nouveaux items |
| Abstentions réutilisées depuis le cache | 40 | Ne représentent pas 40 faits extraits |
| Candidats de déduplication du run | 2 | 0 examiné par le LLM |
| File de qualification avant → après | 2 → 4 | Les 2 nouveaux articles ont été conservés pour une reprise |

`items_eligible=12` compte les passages d'extraction (6 articles × 2 contrats), pas douze articles distincts. Les compteurs de déduplication et d'inconnus portant sur l'ensemble du corpus ne sont pas des scores de qualité des deux nouveautés. Le run est marqué `OK` et `Published=true` malgré la désactivation ; cela constate une exécution et des artefacts locaux, pas une validation sémantique ni un déploiement distant démontré. VEILLE_LLM est `PARTIAL` pour ancienneté du snapshot (8 jours) et n'apporte aucun item dans cette fenêtre.

**Tableau extraction → décision des deux nouveaux items**

| Étape / champ | FrenchBreaches — Ville du Tampon | Cyberattaque.org — Le Tampon | Verdict |
|---|---|---|---|
| Item | `ITM-0c085da888611a12` | `ITM-f2c9b54af4eae1da` | Deux observations d'un même événement |
| Contenu capturé titre + résumé + corps | 6 526 caractères ; détail HTML HYDRATED | 2 847 caractères ; corps de l'article conservé | Les preuves utiles sont présentes |
| Contrôle d'intégrité | SHA-256 identique à la trace du run | SHA-256 identique à la trace du run | Contextes reconstitués fidèlement depuis la file |
| Extraction LLM nouvelle | Aucune ; 2 passes désactivées, 16 champs différés | Aucune ; 2 passes désactivées, 17 champs différés | Échec d'exécution LLM, aucune réponse à noter |
| Cache LLM de ce nouvel item | Aucune entrée | Aucune entrée | Aucun résultat historique à attribuer au modèle |
| Identité normalisée | `ville du tampon` | `le tampon` | Alias non rapprochés |
| Secteur publié | Inconnu ; `NO_ACTIVITY_EVIDENCE` | Administration / Collectivité ; `ORGANISATION_NAME_RULE` | 1/2 correctement qualifié ; le corps du premier article décrit pourtant la mairie |
| Menace publiée | Fuite de données ; statut unknown, `THREAT_SINGLE_LEGACY_VALUE` | Ransomware ; statut reported, `THREAT_EVIDENCE_RANSOMWARE` | 0/2 menaces spécifiques étayées |
| Localisation publiée | La Réunion | La Réunion | 2/2 correctes ; lieu fin absent |
| Vecteur initial | Vide | `vulnerability_exploitation`, publié confirmed | Erreur grave sur la fiche Cyberattaque.org |
| Impact | Perturbations des services municipaux, avec `**` résiduel | Vide | Fait utile disponible mais extraction hétérogène |
| Résumé | Vide | Reprise du titre | Aucun résumé nouveau issu du LLM |
| Date de l'incident | 09/09/2026, base PUBLICATION | 09/09/2026, base PUBLICATION | Début des perturbations également présent dans les timelines ; date de compromission exacte inconnue |
| Volumes, victimes, CVE, données exposées | Aucune valeur publiée | Aucune valeur publiée | Abstention appropriée ; 82 600 habitants ne devient pas un nombre de victimes |
| Incident final | `INC-AF70EBB0A692` | `INC-F7E0A7E8A73F` | Doublon non fusionné |

L'attendu de l'audit est **une seule fiche « Mairie du Tampon », Administration / Collectivité, La Réunion**, décrivant une cyberattaque avec perturbation des services et **nature technique inconnue**. Ni ransomware, ni fuite, ni exploitation de vulnérabilité ne sont établis par ces textes. Le choix éventuel d'une catégorie générique dans la taxonomie doit conserver cette incertitude. Cette ligne attendue est une conclusion humaine de l'audit, pas une extraction LLM.

**Pourquoi la déduplication échoue**

| Paire proposée | Signal | Décision déterministe reproduite | LLM du run | Décision attendue de l'audit |
|---|---|---|---|---|
| Le Tampon ↔ Ville du Tampon | Similarité 0,7619 ; même jour | `NO_DECISION` : clés d'organisation différentes | DISABLED | Même organisation et même incident : fusion |
| Tarnos ↔ Ville du Tampon | Similarité 0,6923 ; 11 jours d'écart | `NO_DECISION` | DISABLED | Organisations différentes : conserver séparées |

La génération de candidats trouve donc le vrai doublon. L'absence de rapprochement déterministe des noms, puis l'arrêt du filet LLM, expliquent son maintien. Le candidat Tarnos est du bruit de similarité ; aucune fausse fusion n'a été appliquée. Aucun veto de date n'est nécessaire pour expliquer la paire du Tampon : le résolveur s'arrête déjà sur les clés d'organisation différentes.

**Causes vérifiées dans le code et par reproduction hors ligne**

1. `normalize.classify_threat` retourne **Ransomware** pour la phrase « Il serait donc prématuré de parler de ransomware ou de fuite de données. ». Les expressions de négation ne couvrent pas cette incertitude. Ensuite `threat_resolution.resolve_component` considère `item.Threat == Ransomware` comme un signal reported, avec pour preuve un titre qui ne dit pourtant pas ransomware.
2. FrenchBreaches conserve le défaut de flux **Fuite de données**. Le résolveur final n'a ni résumé ni affirmation positive d'exfiltration et reprend `THREAT_SINGLE_LEGACY_VALUE`, sans preuve. L'article dit explicitement qu'aucune fuite n'est confirmée.
3. `_deterministic_initial_access` transforme une phrase pédagogique sur plusieurs vecteurs possibles en **vulnerability_exploitation**, confiance interne **1,0**. L'affirmation « aucun point d'entrée n'a encore été rendu public » ne bloque pas cette variante. La fiche finale hérite ensuite de `confirmed`, alors que la confirmation porte sur la cyberattaque, pas sur ce vecteur.
4. `_safe_institutional_name_sector` reconnaît `ville de` et `ville d`, mais pas `ville du`. Le nom Le Tampon est reconnu par la politique nominative ; Ville du Tampon reste inconnu. La catégorie publique visible dans l'article n'a pas été matérialisée dans `Source_Sector_Raw`.
5. Les deux fiches finales présentent `quality_alerts=[]` et aucun champ rejeté dans les faits publiés, malgré ces erreurs. Les compteurs globaux à zéro sur un corpus de référence ne couvrent pas ce nouveau cas.

Repères de code : `cyberwatch/normalize.py:275`, `cyberwatch/normalize.py:333`, `cyberwatch/threat_resolution.py:150`, `cyberwatch/source_facts_ai.py:473`, `cyberwatch/sector.py:140`, `cyberwatch/dedup.py:138`. Les résultats exacts des fonctions et les objets publiés sont figés dans `evidence.json`.

**Le LLM reçoit-il correctement l'article ?**

Pour ce run, **aucun article n'a été envoyé à l'API**. Il faut distinguer la collecte réussie du transport LLM inexécuté.

La préparation d'extraction assemble titre, résumé et contenu, et le prompt ajoute séparément source, victime et date de publication. Les deux contextes du Tampon ont une empreinte conforme à celle du run. Leur taille reste sous la limite par défaut de 10 000 caractères : avec cette limite, aucune troncature ne serait nécessaire. La journalisation du run désactivé ne fige pas un corps de requête ni les paramètres de troncature effectifs ; ces constats ne constituent donc pas une preuve de requête réseau émise.

Les textes capturés contiennent les négations nécessaires. FrenchBreaches conserve un peu de bruit de bas de page et du Markdown ; Cyberattaque.org contient une section pédagogique qu'il faut distinguer de l'incident. Sur les deux articles nouveaux, le problème prouvé porte surtout sur cette distinction sémantique.

Le **filet LLM de déduplication** utilise une autre entrée, beaucoup plus pauvre : titres, identités, dates, menace déjà classée et quelques SourceFacts. Dans les deux objets reconstruits, `Editorial_Evidence` est vide ; le corps de l'article n'est pas transmis. Les champs Sector et Location ne sont pas inclus directement non plus, et Fine_Location est vide. Réactiver le LLM ne suffit donc pas à lui garantir les preuves géographiques et les réserves présentes dans l'article. Repères : `source_facts_ai_api.py:99`, `source_facts_ai.py:128`, `source_facts_ai.py:943`, `dedup_ai.py:339`.

Pour les seuls articles anciens relus pendant ce run, les contextes FrenchBreaches Citadium et Printemps font 11 624 et 12 043 caractères. Ils incluent un article connexe Shipup. Une nouvelle demande avec la limite par défaut couperait le milieu du texte en gardant le début et la fin. Ce risque est constaté dans les entrées conservées, mais aucun nouvel envoi n'a eu lieu ici.

**Les 17 extractions LLM en cache utilisées dans cette collecte**

Toutes les lignes ci-dessous portent `model=gpt-5-nano` comme modèle demandé/cache et **`effective_model=gpt-4o-mini`** comme modèle ayant produit les valeurs. Elles sont antérieures au run et leur état de cache est `accepted`. La confiance est une déclaration de l'extraction, pas une précision mesurée. `∅` désigne un champ plat vide, pas nécessairement une absence dans tous les faits riches. Les citations justificatives sont conservées intégralement dans `llm_cache_extractions.json`.

| Article relu | Champ | Valeur LLM en cache | Confiance déclarée | Valeur actuelle dans SourceFacts |
|---|---|---|---|---|
| Citadium / CYBERATTAQUE_ORG | affected_datasets | bases de données du prestataire Shipup | 0.9 | données clients ; bases de données du prestataire Shipup |
| Citadium / CYBERATTAQUE_ORG | evolution | résolu | 1.0 | résolu |
| Citadium / CYBERATTAQUE_ORG | impact | données personnelles de clients compromises | 1.0 | Des données de contact de clients Citadium ont été consultées et extraites sans autorisation. |
| Citadium / CYBERATTAQUE_ORG | summary | Citadium a informé des clients que leurs données personnelles ont été extraites lors d'une cyberattaque contre Shipup. | 1.0 | Citadium confirme l’exposition de données de contact de certains clients après une cyberattaque contre Shipup. |
| Citadium / CYBERATTAQUE_ORG | third_party | Shipup | 1.0 | Shipup |
| Printemps / CYBERATTAQUE_ORG | affected_datasets | base clients | 0.9 | données clients ; base clients |
| Printemps / CYBERATTAQUE_ORG | attack_flow | exploitation d'une vulnérabilité affectant son outil d’analyse | 0.8 | [{"action":"exploitation d'une vulnérabilité affectant son outil d’analyse","evidence":"une vulnérabilité affectant son outil d’analyse a été exploitée par un tiers non autorisé."}] |
| Printemps / CYBERATTAQUE_ORG | impact | des attaques ciblées possibles via des e-mails ou appels frauduleux. | 0.7 | Des données de contact de clients Printemps ont été consultées et extraites sans autorisation. |
| Printemps / CYBERATTAQUE_ORG | summary | Printemps informe d'une fuite de données clients due à une cyberattaque sur le prestataire Shipup. | 0.9 | Printemps confirme l’exposition de données de contact de certains clients après une cyberattaque contre Shipup. |
| Citadium / FRENCHBREACHES | affected_datasets | données personnelles des clients | 0.9 | données clients ; données personnelles des clients |
| Citadium / FRENCHBREACHES | impact | données personnelles de certains clients exposées | 0.9 | données personnelles de certains clients exposées |
| Citadium / FRENCHBREACHES | summary | Citadium concerné par une cyberattaque visant Shipup, exposant des données personnelles de clients. | 0.9 | Citadium concerné par une cyberattaque visant Shipup, exposant des données personnelles de clients. |
| Citadium / FRENCHBREACHES | third_party | Shipup | 1.0 | Shipup |
| Printemps / FRENCHBREACHES | affected_datasets | données personnelles de clients | 0.8 | données clients ; données personnelles de clients |
| Printemps / FRENCHBREACHES | impact | Accès et extraction non autorisés de données personnelles. | 1.0 | Accès et extraction non autorisés de données personnelles. |
| Printemps / FRENCHBREACHES | summary | Printemps expose des données personnelles de certains clients suite à un incident de sécurité chez son prestataire Shipup. | 1.0 | Printemps expose des données personnelles de certains clients suite à un incident de sécurité chez son prestataire Shipup. |
| Printemps / FRENCHBREACHES | third_party | Shipup | 1.0 | Shipup |

Une anomalie concrète du cache : l'impact Printemps/Cyberattaque.org dit « des attaques ciblées possibles via des e-mails ou appels frauduleux. », avec 0,7 et statut accepted. C'est un risque futur, interdit par le contrat d'impact. Le SourceFacts actuel a une formulation factuelle après correction éditoriale ; le risque ne figure pas comme impact dans la fiche agrégée. **Le résultat final corrigé ne démontre donc pas que l'extraction LLM brute était correcte.** Les 17 valeurs acceptées restent consultables afin de distinguer ces étages.

**Avis sur la performance du modèle et priorités**

La suffisance du modèle est **non démontrée** sur la dernière collecte : zéro inférence nouvelle, zéro latence LLM mesurée, zéro décision de déduplication. Les valeurs en cache montrent un modèle effectif gpt-4o-mini et au moins une erreur sémantique acceptée ; ce petit échantillon ne permet pas d'estimer sa précision globale ni d'affirmer qu'un autre modèle suffirait.

Le prompt exige déjà des preuves, interdit hypothèses et recommandations, et utilise un JSON Schema strict. Cela sécurise la forme, pas la vérité de chaque valeur : [OpenAI Docs — Structured Outputs](https://developers.openai.com/api/docs/guides/structured-outputs) documente cette limite. Pour qualifier un modèle, il faut une comparaison sur des entrées et critères métier identiques, avec appréciation humaine des cas limites : [OpenAI Docs — Evaluation best practices](https://developers.openai.com/api/docs/guides/evaluation-best-practices).

Priorités proposées, sans modification de la production dans cet audit :

1. Corriger les menaces non étayées et le vecteur d'accès faussement confirmé, puis rapprocher les deux fiches du Tampon avec preuve et garde-fous.
2. Rétablir l'exécution LLM dans l'environnement de collecte et rendre sa désactivation visible dans le verdict de qualification ; la file de reprise existe déjà.
3. Corriger les règles de négation, le préfixe institutionnel manquant et la propagation du statut confirmed d'un incident vers des champs non confirmés.
4. Donner au dédoublonnage les preuves pertinentes de chaque article, avec localisation et incertitudes ; isoler les articles connexes avant extraction et troncature.
5. Évaluer séparément **réponse brute → validation → SourceFacts → incident publié**, sur les mêmes textes : reconnaissance du secteur et du territoire, abstention sur menace technique et vecteur inconnus, refus du faux nombre de victimes, vraie fusion Tampon et refus de Tarnos. Zéro fausse affirmation critique sur ce cas est un critère local de réception proposé, pas une garantie générale. Une comparaison de modèles reste à exécuter ; aucune supériorité mesurée n'est revendiquée.

**Traçabilité de l'audit**

`run_snapshot.json` fige les traces, métriques et entrées de reprise du run. `evidence.json` contient les reproductions hors ligne, les objets de déduplication reconstruits, le cache pertinent et les deux fiches publiées localement. `llm_cache_extractions.json` contient les 17 valeurs de cache avec citations et décision de matérialisation. Les fichiers `ITM-…-context.txt` conservent les textes exacts reconstitués. `input_hashes.json` identifie les fichiers canoniques inspectés. Les scripts du dossier sont des outils d'audit ; ils ne lancent ni collecte ni appel LLM. Aucun code métier ni donnée canonique n'a été modifié par cet audit.
