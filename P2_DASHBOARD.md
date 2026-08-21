# P2 — Dashboard / Produit

Le P2 transforme le dashboard statique en outil d'exploration sans modifier le moteur de collecte ni introduire de backend.

## Expérience livrée

- recherche plein texte sur organisation, menace, secteur, territoire, source, synthèses et faits publiés ;
- filtres combinables Threat / Sector / Location / Source / période ;
- tri par date, organisation ou niveau de corroboration ;
- état de vue persisté dans l'URL et lien partageable ;
- résumé analytique de la sélection courante ;
- tendances 30 / 90 / 365 jours ;
- couverture des sept territoires méthodologiques avec avertissement explicite sur les zéros ;
- fiche incident avec date, base de date, provenance, première/dernière observation, références et faits structurés ;
- fiche organisation avec chronologie, menaces et sources observées ;
- distinction légère mono-source / multi-source ;
- rendu responsive et utilisable au clavier.

## Architecture

`assets/app.js` reste le runtime historique et continue à produire les KPI, graphiques et l'état des sources. `assets/p2.js` est une couche de progressive enhancement : elle lit les mêmes `assets/data/incidents.json` et `assets/data/status.json`, injecte l'expérience produit et masque uniquement l'ancien explorateur lorsque son initialisation réussit.

Ainsi, une erreur dans la couche P2 ne rend pas le dashboard inutilisable : la toolbar et la table historiques restent le fallback.

Aucune nouvelle donnée canonique n'est créée. Aucun agrégat métier n'est précalculé et aucun appel réseau autre que le chargement des deux JSON statiques existants n'est ajouté.

## Contrat de simplicité

Le P2 ne doit pas introduire React/Vue, backend, base serveur, authentification, API applicative, WebSocket ou moteur de recherche externe. Les fonctions analytiques restent des calculs navigateur sur le snapshot statique tant que les volumes du produit le permettent.

## Définition de DONE

P2 est considéré clos lorsque la CI vérifie les deux runtimes JavaScript et les tests garantissent : chargement progressif, URL partageable, vues incident/organisation, signalement des angles morts et comportement mobile. Les évolutions ultérieures du dashboard doivent répondre à un usage produit observé, pas à une volonté de sophistication frontend.
