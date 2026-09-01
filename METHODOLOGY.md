# Méthode du prototype

Cyberwatch sert à voir chaque jour les nouveaux incidents cyber, lire une
petite synthèse et ouvrir la fiche détaillée si nécessaire.

## Pipeline

```text
collecte -> identité -> enrichissement -> déduplication -> publication
```

1. **Collecte** — cinq sources publiques fournissent les observations du jour.
2. **Identité** — les noms sont normalisés et quelques alias connus sont
   appliqués sans modifier l'identifiant de l'observation.
3. **Enrichissement** — menace, secteur, localisation et faits utiles sont
   complétés. Une valeur incertaine peut rester `Inconnu`.
4. **Déduplication** — les règles simples regroupent d'abord les observations.
   Un batch LLM final compare seulement les nouveautés à la base et rattrape
   les variantes de nom restantes.
5. **Publication** — `data/` est enregistré puis `assets/data/` est généré pour
   le dashboard GitHub Pages.

## Fenêtre quotidienne

`maj` collecte aujourd'hui et hier, car les sources exposent généralement une
date sans heure précise. Les observations plus anciennes restent disponibles,
mais ne sont ni recollectées ni recalculées.

## Tolérance du prototype

Une source, l'extraction de faits ou le LLM peuvent échouer sans bloquer les
autres. Le déterministe reste le résultat de repli. Les erreurs de secteur,
localisation ou résumé sont acceptables pour ce prototype.

La production utilise uniquement `main`, un workflow quotidien et un dashboard
statique.
