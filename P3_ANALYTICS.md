# P3 — Analytics / Intelligence

P3 transforme les incidents publiés en signaux interprétables sans rouvrir les moteurs gelés.

## Principes

- calculs déterministes avant toute narration ;
- aucun signal sur un échantillon inférieur à 3 incidents ;
- une accélération exige au moins +2 incidents et +50 % par rapport à la période précédente ;
- un nouveau couple menace × secteur exige au moins 2 observations ;
- la confiance combine taille d'échantillon, corroboration multi-source et complétude Threat/Sector/Location ;
- « aucune observation » ne signifie jamais « absence réelle d'incident » ;
- le frontend reste statique, sans backend ni framework.

## Moteur

`cyberwatch.analytics.build_analytics()` produit les fenêtres 7/30/90/365 jours, les répartitions, les organisations récurrentes, les signaux et une narration factuelle templatisée. Il ne fait aucun accès réseau et ne modifie aucune donnée.

## Dashboard

`assets/p3.js` ajoute une section Intelligence en progressive enhancement. Elle affiche les volumes comparés, le taux multi-source, les signaux étayés, les principaux contextes par menace/secteur/territoire et permet de revenir aux incidents justificatifs.

## LLM

Le LLM n'est pas requis pour P3. Une future narration LLM ne pourra consommer que les métriques/signaux calculés et devra conserver les références d'incidents. Elle ne devra jamais introduire de causalité ou de tendance absente du payload déterministe.

## Clôture

P3 est considéré clos lorsque le moteur et le runtime passent la CI, que les petits échantillons ne déclenchent pas de tendance et que chaque signal expose sa fenêtre, son delta, son niveau de confiance et ses incidents de preuve.
