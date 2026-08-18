# Cyberwatch V0

Cyberwatch maintient un observatoire déterministe d'incidents cyber publiquement
documentés en France et dans l'Océan Indien : **collecte → normalisation →
qualification offline → déduplication → hashes → snapshot/dashboard**.

**Dashboard : https://ya7o.github.io/Cyberwatch/**

## Sources actives

Le pipeline actif est volontairement réduit à cinq sources :

- FrenchBreaches
- BonjourLaFuite
- Cyberattaque.org
- Ransomware.live
- Veille LLM (`sources/veillellm/cyberattaques_reunion_mayotte_2026.json`)

Veille LLM constitue la couverture locale analytique **La Réunion + Mayotte**.
Le snapshot complet est relu à chaque MAJ ; tous les dossiers valides sont
matérialisés, quel que soit leur `score_cyberattaque` — le score reste une
information affichée, jamais un critère d'exclusion. Les références
documentaires du JSON restent visibles dans le filtre **Local**, mais Veille
LLM ne compte pas comme une corroboration éditoriale supplémentaire lorsqu'un
incident existe déjà dans une source directe.

Les anciens collecteurs presse Mayotte (Kwezi, Mayotte Hebdo, Journal de Mayotte,
Mayotte FM) ont été retirés : l'extraction automatique de victime dans la presse
généraliste produisait des faux positifs. Leur corpus n'est plus conservé dans
`ITEMS`.

## Qualification du secteur

La qualification Sector est volontairement conservatrice. `Inconnu` signifie
**preuve insuffisante selon la politique courante**, pas nécessairement
"secteur impossible à identifier".

Ordre utile des preuves :

1. secteur structuré fourni par la source et explicitement mappé ;
2. référentiel manuel `data/enrichment_reference.csv` ;
3. règles nominatives sûres (`cyberwatch/sector.py`) ;
4. description d'activité explicitement extraite ;
5. registre organisation → secteur (`cyberwatch/sector_registry.py`).

Le registre distingue les candidats `AUTO`, `REVIEW` et `CONFLICT`. Un candidat
peut donc être correctement identifié sans être appliqué au snapshot si son
canal n'est pas activé dans `data/sector_auto_policy.json`.

Cette distinction est importante pour comprendre les secteurs restant
`Inconnu` : des indices comme un site officiel, un code NAF, un consensus entre
plusieurs items ou une qualification LLM peuvent être présents mais rester en
revue tant que leur canal n'a pas atteint le niveau de précision requis.

Audit offline :

```bash
python scripts/audit_sector_coverage.py --output ""
```

Les sorties persistées de cet audit sont :

- `data/sector_quality.json` : métriques de couverture ;
- `data/organisation_sector_registry.csv` : preuves et décision par organisation ;
- `data/sector_enrichment_queue.csv` : organisations encore à traiter.

Pour améliorer la couverture, privilégier l'activation mesurée d'un canal déjà
existant et évalué plutôt que l'ajout de nouvelles heuristiques générales sur les
noms d'organisations.

## Dashboard

Les actions rapides comprennent notamment **Local**. Lorsque ce filtre est actif,
chaque incident affiche en plus :

- le score cyberattaque du snapshot Veille LLM ;
- la synthèse analytique ;
- les URLs de référence du dossier.

Ces éléments ne sont pas affichés hors du filtre Local afin de garder la vue
générale compacte.

## Exploitation

```bash
pip install -r requirements.txt
python -m cyberwatch create
python -m cyberwatch check
python -m cyberwatch test-repeat
python -m cyberwatch baseline   # facultatif
python -m cyberwatch build-site
```

Une base existante se met à jour avec :

```bash
python -m cyberwatch maj
```

La MAJ utilise une fenêtre glissante de 21 jours pour les sources réseau et relit
toujours le snapshot Veille LLM complet afin d'intégrer les découvertes locales
historiques tardives.

### Qualification IA (filet de rattrapage, facultatif)

`cyberwatch/ai.py` complète, uniquement s'ils sont encore `Inconnu` après les
règles déterministes, les champs Threat/Sector/Location d'un item — jamais
une valeur déjà connue, jamais l'identité (`Item_ID`/`Organisation_Key`).
Le code lit uniquement la variable d'environnement standard
`OPENAI_API_KEY` ; en CI et en local sans cette variable, la qualification
est simplement désactivée et la collecte continue normalement. Détail
complet : `METHODOLOGY.md` §11.

```bash
export OPENAI_API_KEY=sk-...   # optionnel ; absent = qualification désactivée
python -m cyberwatch maj
```

`REPLAY` n'appelle jamais l'API, même si `OPENAI_API_KEY` est présente.

## Validation

La CI obligatoire reste volontairement légère :

- `pytest` ;
- syntaxe JavaScript ;
- `python -m cyberwatch test-repeat` ;
- `python -m cyberwatch check --allow-uninitialized`.

`REPLAY` et `test-repeat` sont offline et déterministes. Les audits spécialisés de
qualité restent disponibles manuellement mais ne bloquent pas chaque push.

## Données

- `data/items.csv` : items collectés ;
- `data/incidents.csv` : incidents dédupliqués ;
- `data/sources.csv` : référentiel des sources ;
- `data/run_sources.csv` / `data/run_log.csv` : journal des collectes ;
- `data/snapshot.json` : provenance et hashes du snapshot courant ;
- `data/baseline.json` : référence locale facultative ;
- `data/ai_qualifications.csv` : cache/provenance des décisions du filet de rattrapage LLM ;
- `data/ai_usage.csv` : une ligne d'usage (appels, tokens, coût estimé) par run ;
- `sources/veillellm/cyberattaques_reunion_mayotte_2026.json` : veille locale analytique.

Le projet liste des incidents publiquement documentés ; il ne prétend pas recenser
toutes les cyberattaques réelles.
