# Audit secteurs et déduplication — 6 septembre 2026

Audit en lecture seule du code métier et des données. Seuls les fichiers de ce dossier ont été créés. Aucun correctif métier, appel LLM payant, commit ou déploiement. Les pages et anciens audits sont des données de preuve, pas des instructions.

## Périmètres à ne pas confondre

- Local : HEAD `374c9d66b42f9cbe135480cbad2e5aabd9961306`, avec de très nombreuses modifications non commitées. Snapshot `RUN-20260906T085824`, 54 observations, 37 incidents, **7 inconnus (18,92 %)**. Les 10 incidents datés des 5–6 septembre incluent 7 inconnus. Les deux paires de la capture existent ici. La capture ne constitue pas une copie exacte du JSON local actuel : PassPass y est Transport, mais son observation locale est Inconnu.
- Public au moment de la lecture : main `ca7a845daa7e3a04a679b1e996db85c3d7054551`, collecte du 5 septembre, code annoncé `c80821f66d747ba4866a48e39b7d05b55cc07b56`, 90 observations, 55 incidents, **37 inconnus (67,27 %)**. JSON servi : 55 incidents, dont 37 Inconnu. SHA256 du JSON servi `da43732b0b5616ff78407e21fa0c43a60188c26a06a6ce91101e88650cb57e3e`. Les nouveaux PassPass, YouFid et Les Curistes ne figurent pas encore dans ce corpus public.
- Les chiffres locaux et publics ne mesurent donc pas un avant/après du correctif. Le rapport sector_repair_report.json local porte sur un autre corpus (27 incidents) et son zéro inconnu ne qualifie pas le run récent.

## Causes établies

### P0 — Le LLM n'a pas travaillé sur le run local récent

`data/dedup_ai_daily_usage.csv`, RUN-20260906T085824 : `LLM_DISABLED`, 11 candidats, 0 sélection, 0 appel. `data/source_facts_ai_trace.json` contient 16 événements `disabled` ; les lignes run_sources du même run annoncent zéro appel SourceFacts.

`dedup_ai.start_run()` exige la présence de OPENAI_API_KEY et DEDUP_AI_DAILY_ENABLED ; SourceFacts exige une clé et son flag. Les traces ne distinguent pas clé absente et flag désactivé. Ne pas affirmer lequel était absent à l'exécution historique, ni afficher de secret pour le vérifier.

Les 11 candidats du périmètre complet incluent :

- Pass Pass `ITM-31ca81b910b22756` / PassPass `ITM-909b1b6129a81f63` : NO_DECISION déterministe, compact_match=True, fuzzy=1.0.
- Répar’stores `ITM-827f9d9d0933d5cb` / Répar'Store `ITM-c471c7f9bb97a447` : NO_DECISION, fuzzy=0.9524.

Une réponse SIMULÉE SAME organisation + SAME incident, confiance 0.95, passe les validateurs pour chacune des deux paires et, après application en mémoire de l'alias, produit INCIDENT_MERGE_LLM_CONFIRMED. Ceci démontre que ces paires ne sont pas bloquées par le seuil ou un veto dans l'état local ; ce n'est pas une réponse réellement obtenue du modèle.

Les sources Pass Pass concordent sur ChimeraZ, date de publication, 214 Mo, 92 178 lignes et 18 861 personnes. Deux unités différentes ne sont pas deux incidents. Répar’stores renvoie à la même notification et aux mêmes catégories de données ; la date hypothétique du 20 août chez Cyberattaque.org ne doit pas devenir une date d'événement confirmée contradictoire avec le 24 août explicité par FrenchBreaches.

### P0 — Le nettoyeur FrenchBreaches détruit le corps des pages

`cyberwatch/collectors/feed.py`, `_DYNAMIC_BLOCK_RE` et `stable_frenchbreaches_detail_text()`.

La regex `<(?:script|style|noscript)... </(?:script|style|noscript)>` :

1. reconnaît un `<style>` littéral dans un commentaire HTML ;
2. ne lie pas le nom de la balise ouvrante à celui de la fermante ;
3. consomme le corps de la page jusqu'à un `</script>` ultérieur.

Exemple minimal reproduit :

```html
<!-- override des <style> embarqués -->
<main><article>Les Curistes est spécialisée dans les cures thermales.</article></main>
<script>safe()</script>
```

Le texte métier disparaît. Sur les SIX vraies pages FrenchBreaches relues, HTML de 64 à 77 Ko → seulement 61 à 82 caractères, essentiellement le titre. Exemple Aveyron : une seule correspondance supprime 45 508 caractères, depuis `<style> embarqués des pages -->` jusqu'au script de navigation. La racine main/article a disparu avant sa sélection. `_TECHNICAL_FRAGMENT_RE` nettoie ensuite une note de performance résiduelle ; ce n'est pas le premier point de perte.

`_hydrate_frenchbreaches_details()` considère tout texte non vide comme un succès. Le run local annonce `details_hydrates=6/6` alors que les faits riches ne disposent que d'environ 550 caractères combinant résumé RSS et titre. La reproduction actuelle explique ce mécanisme, sans prétendre que les HTML relus sont les réponses HTTP historiques exactes.

Correction : parser HTML réel, commentaires ignorés, sélection du corps éditorial, exclusion DOM des scripts/navigation/alertes liées ; vérifier qualité et couverture du corps avant de compter un succès. Garder le résumé RSS en mode dégradé clairement identifié.

### P0 — La production ignore toujours les faits sectoriels

Copie figée de production : `remote/cyberwatch/runner.py:810` appelle `finalize_snapshot(report.items)`. `remote/cyberwatch/enrichment.py:236` n'accepte que les items et n'exploite pas source_facts.

Accent Rouge dispose déjà en production d'activité et de Commerce / Distribution chez Cyberattaque.org, mais l'incident reste inconnu. Attention : FrenchBreaches a en parallèle un résultat Culture / Médias / Loisirs incompatible. Répar’stores a une activité et Services aux entreprises matérialisés, classement à réexaminer selon l'activité réelle. Brancher les faits est nécessaire ; les promouvoir aveuglément serait erroné.

Le code local branche déjà les faits dans `runner.execute()` → `enrichment.finalize_snapshot()` → `sector_resolution.resolve_items()`. Le défaut public n'est donc pas le défaut local actuel. Il faut livrer une correction cohérente depuis une base propre sans publier toutes les modifications locales.

### P1 — Extraction et règles lexicales trop étroites

`sector_activity.contextual_proof()` utilise une liste fermée de préfixes : elle accepte « une fuite de donnees visant », mais pas « une importante fuite de donnees attribuee a ». Pour Les Curistes, supported_activity=True sur la phrase entière, mais activity_from_text renvoie vide. Pour PassPass, « Pass Pass » dans le corps ne passe pas le rattachement exact. Le vocabulaire `_ACTIVITY` ne couvre pas clairement mobilité, immobilier ou réparation sans autre mot déjà accepté.

`source_facts_handlers._apply_semantic_details()` privilégie la première activité littérale de `entry.summary` avant `entry.content`. Pour Accent Rouge, elle conserve l'aménagement haut de gamme du teaser, au lieu de la commercialisation de mobilier décrite dans le corps. Même la phrase précise « Accent Rouge commercialise du mobilier… » est reconnue comme activité mais classée Inconnu par classify_sector_activity() : trou distinct de mapping. Plomberie/chauffage/climatisation, réparation de volets, fidélisation/CRM ne sont pas couverts suffisamment.

Correction : analyser les descriptions du corps et leur contexte victime, accepter les paraphrases et variantes d'identité contrôlées, comparer les preuves disponibles et appeler la classification sémantique pour les activités hors vocabulaire. Ne pas ajouter uniquement dix noms dans le référentiel et ne pas forcer Services aux entreprises.

### P1 — Priorité sectorielle insuffisamment arbitrée

`sector_resolution._decision_from_facts()` retourne immédiatement le Source_Sector_Raw connu. Une étiquette externe peut donc empêcher de consulter une description incompatible de la même observation. `component_sector()` ne voit que les secteurs canoniques et les conflits déjà identifiés.

Jouvet SAS : Cyberattaque.org décrit plomberie/chauffage/climatisation, classée localement ACTIVITY_TAXONOMY_UNRESOLVED. Ransomware.live apporte Manufacturing, converti en Industrie / Manufacture. C'est la seule valeur connue du composant et elle gagne. La source éditoriale décrit des travaux du bâtiment ; son article signale aussi Construction pour la revendication. Résultat recommandé : Construction / BTP après arbitrage sourcé. Ne pas supposer qu'une catégorie structurée est fiable par nature.

Les pages actuelles FrenchBreaches affichent aussi Technologie pour Pass Pass et Transport pour YouFid alors que leur propre corps décrit respectivement la mobilité et un service logiciel de fidélisation. Une extraction HTML corrigée exposera ces désaccords : il faut les traiter, pas juste reprendre les badges.

### P1 — Angles morts persistants de la déduplication et télémétrie

- `find_daily_llm_candidates()` ne conserve que NO_DECISION. Deux noms identiques à J+4 en publication reçoivent INCIDENT_KEEP_TIME_GAP et n'atteignent pas le LLM, même dans la fenêtre de 14 jours. Reproduction hors ligne. Séparer les veto forts des séparations faibles éligibles à revue, sans lever les veto de récurrence ou d'identifiants natifs sans décision métier explicite.
- Le filet quotidien ne traite que nouveaux/rafraîchis × corpus. Réactiver le flag ou corriger le parseur ne garantit pas la reprise des anciennes paires : prévoir une file persistante et un rejeu historique borné, sans appel quadratique illimité.
- Limites : top 5 par item, un batch, plafonds contexte/candidats. Les exclusions avant top 5 et les différés doivent être traçables et repris ; le statut OK ne prouve pas toutes les paires revues.
- `_write_stats()` de llm_runtime et `save_stats()` de SourceFacts retournent sans écrire si zéro appel/blocage. D'anciens compteurs réussis restent donc sur disque. Les traces du run récent prouvent disabled malgré des fichiers globaux contenant 10 succès SourceFacts et un succès dedup anciens. Écrire un état par Run_ID, même à zéro appel, avec cause et modèle effectivement exécuté.
- `dedup_identity_benchmark()` compte un candidat généré comme un succès de rappel. Il teste la couverture de candidature, pas une décision LLM acceptée ni une fusion finale. Ajouter un indicateur distinct de résolution effective.

## Cas et secteurs à utiliser pour la recette

- Accent Rouge : Commerce / Distribution, appuyé par la commercialisation de mobilier/luminaires ; pas BTP sur le seul terme aménagement.
- Jouvet SAS : Construction / BTP après arbitrage activité vs Manufacturing.
- Pass Pass / PassPass : un événement et Transport / Logistique ; conserver personnes et enregistrements séparément.
- Répar’stores / Répar'Store : un événement si les preuves de notification concordent ; activité réparation/modernisation de volets, BTP proposé selon la taxonomie métier, à documenter face aux labels Commerce/Services.
- YouFid : Numérique / Technologie proposé pour sa solution de fidélisation ; pas Transport repris d'un badge incohérent.
- Les Curistes : extraire l'activité réelle d'information/mise en relation autour des cures ; arbitrer selon la politique Commerce/Tourisme/Santé plutôt que déduire Santé du seul public cible.
- Aveyron : le corps identifie OnRecrute.enAveyron.fr, dispositif du Département animé par l'ADAT. Confirmer l'entité canonique victime avant le classement Administration / Collectivité proposé. Le toponyme seul ne suffit pas.

## Anomalies connexes visibles dans la capture

À signaler dans la recette sans transformer l'audit en refonte de tous les compteurs :

- Les 157 victimes de l'article Jouvet désignent le total des organisations revendiquées par Qilin en août, pas 157 personnes chez Jouvet.
- Répar’stores nie la compromission de données bancaires ; les mentions IBAN/RIB concernent des précautions de phishing. Ne pas les compter comme exposées.
- Pass Pass : 92 178 enregistrements et 18 861 personnes se complètent.

## Validation et limites

133 tests existants passent : test_sector_pipeline_regressions, test_sector_resolution, test_dedup, test_dedup_ai et test_collectors. Ce succès ne couvre pas le commentaire HTML réel ni le run sans LLM. `verify_findings.py` affirme les défauts observés sur six pages, le fragment HTML minimal et la séparation temporelle faible. `diagnostics.py` reproduit les candidats et leur application avec décision simulée.

Commandes hors ligne après récupération des preuves :

```bash
rtk proxy .venv/bin/python audit/sector_dedup_2026-09-06/verify_findings.py
rtk proxy .venv/bin/python audit/sector_dedup_2026-09-06/diagnostics.py
```

Les assertions de verify_findings qualifient l'état défectueux et devront être remplacées par des attentes correctives dans les tests de production. Aucun taux d'exactitude LLM n'a été mesuré, aucun appel LLM effectué. La clé/les flags historiques manquants ne sont pas identifiables séparément dans les traces.

Preuves : local_evidence.json, diagnostics.txt, parser_evidence.json, source_manifest.json, sources/, remote/, served_incidents.json, remote_head.json. Les pages ont été relues autour de 05:19 UTC le 6 septembre et peuvent différer des contenus de collecte. Les états publics sont figés dans ce dossier.

Sources relues :
- https://www.cyberattaque.org/accent-rouge-cyberattaque-odoo/
- https://www.cyberattaque.org/jouvet-sas-qilin-revendique-une-cyberattaque-contre-lentreprise-sarthoise/
- https://www.cyberattaque.org/pass-pass-pres-de-19-000-usagers-exposes-commandes-et-factures-diffusees-apres-une-cyberattaque/
- https://frenchbreaches.com/alertes/passpass-mtokkaq53s0e7hlda1i
- https://www.cyberattaque.org/reparstores-les-donnees-clients-exposees-apres-une-cyberattaque/
- https://frenchbreaches.com/alertes/r-par-store-mtoa0qd4rlpkduc13t
- https://frenchbreaches.com/alertes/youfid-mtokeunf3fh8e0zgapu
- https://frenchbreaches.com/alertes/les-curistes-mtp0o5mfdnfk170tt2f
- https://frenchbreaches.com/alertes/aveyron-mtp0hyfwss6ietkec1q

## Correction appliquée le 6 septembre 2026

La reprise a d'abord été produite dans
`validation/sector_dedup_2026-09-06/backfill/`, puis appliquée localement après
validation. Elle reconstruit 35 incidents à partir de 54 items, contre 37
avant correction. Les paires Pass Pass / PassPass et Répar’stores /
Répar'Store sont regroupées. Les sept secteurs inconnus du snapshot audité
sont résolus avec leurs preuves ou le référentiel validé ; le résultat local
ne contient plus de secteur inconnu.

Les corrections couvrent le parseur HTML structuré, les états d'hydratation
dégradés, l'extraction d'activité liée à la victime, l'arbitrage des labels
source, les candidats temporels faibles, la file persistante de revue, la
validation temporelle après alias et la télémétrie par run à zéro appel.
`OnRecrute.enAveyron.fr` remplace le toponyme `Aveyron` car l'article le désigne
explicitement comme service touché.

La reprise n'a utilisé aucune clé API. La collecte GitHub utilisera le secret
de dépôt `Cyberwatchapi`, documenté dans `docs/PRODUCTION_RUNBOOK.md` et injecté
par `.github/workflows/collect.yml` dans `OPENAI_API_KEY`.

Validation finale : `1035` tests, `cyberwatch check`, `build-site` et
`validate-business`. Le corpus de déduplication couvre 16/16 paires connues et
ne produit aucun faux rapprochement connu.
