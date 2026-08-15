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
Le snapshot complet est relu à chaque MAJ ; seuls les dossiers dont le
`score_cyberattaque >= 50` sont matérialisés. Les références documentaires du
JSON restent visibles dans le filtre **Local**, mais Veille LLM ne compte pas
comme une corroboration éditoriale supplémentaire lorsqu'un incident existe déjà
dans une source directe.

Les anciens collecteurs presse Mayotte (Kwezi, Mayotte Hebdo, Journal de Mayotte,
Mayotte FM) ont été retirés : l'extraction automatique de victime dans la presse
généraliste produisait des faux positifs. Leur corpus n'est plus conservé dans
`ITEMS`.

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
