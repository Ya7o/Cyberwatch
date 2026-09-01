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

## Fenêtres

- `create` reconstruit le corpus à partir du 28 août 2026 ;
- `maj` collecte aujourd'hui et hier, car les sources exposent généralement une
  date sans heure précise ;
- les observations plus anciennes déjà en base restent disponibles.

## Tolérance du prototype

Une source, un enrichissement ou le LLM peuvent échouer sans bloquer les autres.
Le déterministe reste le résultat de repli. Les erreurs de secteur,
localisation ou résumé sont acceptables et se corrigent au fil des mises à jour.

La production utilise uniquement `main`, un workflow quotidien et un dashboard
statique.
