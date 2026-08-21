"""Cyberwatch — observatoire des incidents cyber France / Océan Indien.

Implémentation exécutable de la méthodologie OBS-FR-OI : collecte multi-sources,
base déterministe reproductible, et dashboard statique publié sur GitHub Pages.
"""

import os

# Compatibilité de transition : plusieurs modules historiques construisent leur
# clé de cache à partir de variables d'environnement spécifiques. Les defaults
# sont alignés ici avec la politique centrale afin que le modèle inscrit dans la
# clé de cache soit le même que celui réellement utilisé par llm_runtime.
# Un override utilisateur explicite reste prioritaire via setdefault.
if not os.getenv("OPENAI_MODEL", "").strip():
    os.environ.setdefault("SOURCE_FACTS_AI_MODEL", "gpt-4o-mini")
    os.environ.setdefault("CYBERATTAQUE_SEMANTIC_MODEL", "gpt-4o-mini")
    os.environ.setdefault("EDITORIAL_SEMANTIC_MODEL", "gpt-4o-mini")
    os.environ.setdefault("DEDUP_AI_MODEL", "gpt-4o-mini")

from .config import METHOD_ID
from .sector_completion import install as _install_sector_completion
from .incremental_performance import install as _install_incremental_performance
from .incremental_performance_contract import install as _install_incremental_performance_contract
from .incremental_runtime import install as _install_incremental_runtime

_install_sector_completion()
_install_incremental_performance()
_install_incremental_performance_contract()
_install_incremental_runtime()

__all__ = ["METHOD_ID"]
__version__ = "1.0.0"
