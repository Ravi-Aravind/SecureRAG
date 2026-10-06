import os

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
PHASE0_DATA_DIR = os.path.join(ROOT_DIR, 'phase0', 'data')
PHASE0_CONFIG_PATH = os.path.join(ROOT_DIR, 'phase0', 'config', 'config.yaml')

# System prompt is identical to Phase 0
SYSTEM_PROMPT = "You are a security analyst assistant. Answer questions using ONLY the provided context documents. Do not use external knowledge. If the context is insufficient or contradictory, say so explicitly."

# PRESERVE EXACT FROZEN MODEL IDENTIFIER (Finding 4)
# Intentionally preserving the actual provider-specific Phase 0 configuration
# (openai/gpt-4o-mini) rather than merely reading the shortened config.yaml value.
LLM_MODEL = 'openai/gpt-4o-mini'

TEMPERATURE = 0.0
MAX_TOKENS = 512

TYPE_C_PROMPT_TEMPLATE = """Context documents:
{context}

Question:
Is {product} version {probe_version} affected by {cve_id}?

Answer with the exact version boundary. If documents conflict, report both and note the conflict."""
