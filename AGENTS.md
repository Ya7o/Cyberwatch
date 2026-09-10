# Commandes opérationnelles Cyberwatch

Quand l'utilisateur demande **MAJ**, exécuter `python -m cyberwatch MAJ`
depuis la racine du dépôt, avec le Python du projet (`.venv/bin/python`
si disponible). La collecte conserve le corpus et lit les publications
d'hier et d'aujourd'hui, y compris sur une base neuve ou purgée.

Quand l'utilisateur demande **PURGE**, exécuter `python -m cyberwatch PURGE`.
Cette demande autorise à vider le corpus, les caches, files d'attente et
journaux de collecte, puis à générer un dashboard vide. Ne pas lancer MAJ
automatiquement après PURGE : attendre une demande de MAJ ou la collecte
planifiée. Les sources et référentiels sont conservés.

Ces commandes agissent sur la copie locale. Pour une demande concernant
explicitement la production, utiliser le workflow COLLECT et son entrée
`operation` (`MAJ` ou `PURGE`), qui publie les données sur `main`.

Les instructions de développement et de validation sont dans `CLAUDE.md`.
