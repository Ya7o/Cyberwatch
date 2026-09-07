"""Print only non-secret LLM configuration flags."""
import json
import os

print(json.dumps({
    "api_key_present": bool(os.getenv("OPENAI_API_KEY", "").strip()),
    "dedup_enabled": os.getenv("DEDUP_AI_DAILY_ENABLED", "default"),
    "source_facts_enabled": os.getenv("SOURCE_FACTS_AI_ENABLED", "default"),
}, indent=2))
