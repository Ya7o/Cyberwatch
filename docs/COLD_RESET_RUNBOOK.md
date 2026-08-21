# Cold reset certifié

Le reset total Cyberwatch est une reconstruction des données dérivées et des caches, pas une remise à zéro de l'identité métier.

## Invariants

- `incident_id_registry.csv`, les alias, les référentiels Sector, les golden datasets et les baselines qualité sont protégés.
- Le reset travaille dans `/tmp/cyberwatch-cold-reset`; la base canonique n'est remplacée qu'après certification.
- La publication est désactivée par défaut et exige `publish=true` au déclenchement manuel.
- Toute perte d'un `Item_ID` ou `Incident_ID` déjà publié bloque la promotion.
- Les enrichissements sont exécutés par couches avec budgets indépendants et checkpoints de cache entre passes.

## Avant lancement

Exécuter :

```bash
python -m cyberwatch.cold_reset preflight
python -m cyberwatch.cold_reset manifest --output /tmp/cold-reset-before.json
```

Le préflight doit retourner `GO`. Le manifeste contient les hashes des actifs protégés, caches et sorties dérivées ainsi qu'une estimation de durée/coût basée sur la télémétrie disponible.

## Séquence du workflow

1. tests complets et préflight offline ;
2. archive restaurable du snapshot courant ;
3. staging isolé et purge des seules sorties/caches froids ;
4. reconstruction déterministe sans LLM ni enrichissement réseau ;
5. qualification bornée ;
6. extraction sémantique par passes de 250 appels maximum ;
7. SourceFacts par passes de 250 appels maximum ;
8. enrichissement organisation sans LLM ;
9. golden tests, qualité, répétabilité et contrôles structurels ;
10. gates d'identité/historique ;
11. export des diagnostics ;
12. promotion atomique uniquement si `publish=true`.

## Rollback

Chaque run exporte `cyberwatch-before-reset.tgz` et le manifeste avant reset. En cas d'échec, aucune promotion n'a lieu. Si une promotion doit être annulée après coup, restaurer `data/` et `assets/data/` depuis l'archive correspondant au run puis relancer `python -m cyberwatch check` et `python -m cyberwatch test-repeat` avant commit.

## Point d'attention historique

Une source peut être `OK` tout en n'exposant plus tout son historique. C'est pourquoi la certification compare les identités publiées avant/après et refuse une promotion qui ferait disparaître des items ou incidents existants.
