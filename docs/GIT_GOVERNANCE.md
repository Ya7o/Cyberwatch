# Gouvernance Git

## État au 1er septembre 2026

| Indicateur | Avant entretien | Après `git gc` local |
|---|---:|---:|
| Commits atteignables depuis `main` | 1 137 | 1 137 |
| Commits sur toutes les références locales | 1 147 | 1 147 |
| Tags locaux / distants | 103 / 103 | 103 / 103 |
| Tags `archive/*` | 31 | 31 |
| Packs | 45 | 2 |
| Taille des packs | 245,47 Mio | 12,91 Mio |
| Taille de `.git` | environ 280 Mio | 15 Mio |

Le compactage n’a réécrit aucun commit, supprimé aucun tag et modifié aucune
référence distante. Il a consolidé les packs et supprimé les objets locaux
inaccessibles arrivés à expiration selon la politique normale de Git. Ces
objets inaccessibles ne sont plus récupérables depuis cette copie locale ; les
commits et tags publiés restent disponibles sur `origin`.

## Règles à partir de maintenant

- `main` est la seule branche de production et reste toujours publiable ;
- une évolution de code passe par CI avant fusion ; les données planifiées sont
  le seul cas de commit automatisé directement sur `main` ;
- un commit doit représenter une intention vérifiable, sans tag de sauvegarde
  ad hoc ;
- les nouveaux tags sont réservés aux versions `vMAJEUR.MINEUR.CORRECTIF` ;
- aucun nouveau tag `archive/*` n’est créé ; une branche locale temporaire ou
  un bundle Git hors dépôt remplace ce mécanisme ;
- le dépôt est entretenu avec `git gc` quand il dépasse 5 packs ou 100 Mio de
  packs ; l’audit se fait avec `git count-objects -vH` ;
- une réécriture de `main` ou une suppression de tag distant exige une décision
  explicite du mainteneur, une sauvegarde vérifiée et une fenêtre annoncée.

## Dette historique restante

Les 1 137 commits de `main` ne peuvent être réduits sans réécriture destructive
de l’historique partagé. Les 31 tags `archive/*` et les 72 tags de version sont
également présents sur `origin`. Leur suppression éventuelle doit faire l’objet
d’une opération séparée et explicitement autorisée ; elle n’est pas nécessaire
pour conserver un dépôt local compact.

Trois branches locales non publiées ou de sauvegarde existent encore en plus de
`main` : `backup/local-stabilisation-pre-release-20260816-142624`,
`codex/local-main-backup-20260830` et `codex/sector-evidence-refactor`. Elles ne
sont pas supprimées automatiquement, car elles peuvent contenir un travail de
récupération utile.

## Entretien

```bash
python scripts/git_governance_audit.py
git count-objects -vH
git gc
```

`git gc --prune=now`, la suppression massive de tags et les réécritures de
type `filter-repo` ne font pas partie de l’entretien courant.
