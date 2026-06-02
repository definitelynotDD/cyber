"""Central configuration for the Attack Surface Mapper.

Everything is environment-driven so the same code runs in a zero-dependency
demo (SIMULATION_MODE) or against real tooling when it is installed.
"""
import os
from dotenv import load_dotenv
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential
from langchain.chat_models import init_chat_model
load_dotenv()

# On Streamlit Cloud there is no .env — pull secrets into env vars instead.
try:
    import streamlit as st
    for _k, _v in st.secrets.items():
        if isinstance(_v, str):
            os.environ.setdefault(_k, _v)
except Exception:
    pass

# When True, recon "tools" return realistic synthetic data instead of shelling
# out to nmap/subfinder/nuclei. Lets the whole multi-agent pipeline run and
# demo anywhere, even with none of the security binaries installed.
SIMULATION_MODE = os.getenv("ASM_SIMULATION", "true").lower() in ("1", "true", "yes")

# LLM used by the agents. Format is "<provider>:<model>" for langchain's
# init_chat_model resolver. Override with ASM_LLM_MODEL if needed.
LLM_MODEL = os.getenv("ASM_LLM_MODEL", "google_genai:gemini-3.1-flash-lite")

# Vision model for screenshot analysis (must be multimodal).
VISION_MODEL = os.getenv("ASM_VISION_MODEL", "gemini-3.1-flash-lite")

# Hard stop so the supervisor can never loop forever (and burn API budget).
MAX_SUPERVISOR_STEPS = int(os.getenv("ASM_MAX_STEPS", "12"))

# Per-tool subprocess timeout in seconds.
TOOL_TIMEOUT = int(os.getenv("ASM_TOOL_TIMEOUT", "120"))

# Embedding model for FAISS semantic memory. Falls back to a keyword store
# if sentence-transformers / faiss are unavailable.
EMBED_MODEL = os.getenv("ASM_EMBED_MODEL", "all-MiniLM-L6-v2")

# The valid worker names the supervisor is allowed to route to. Used as a
# whitelist so a hallucinated agent name can't crash the graph.
WORKERS = ["recon", "vision", "analysis", "report"]

# Fallback model when Gemini quota is exhausted (Groq llama3 is free + fast).
FALLBACK_MODEL = os.getenv("ASM_FALLBACK_MODEL", "groq:llama-3.3-70b-versatile")

# Retry decorator for Gemini rate-limit (429 / RESOURCE_EXHAUSTED) errors.
llm_retry = retry(
    retry=retry_if_exception(lambda e: "429" in str(e) or "RESOURCE_EXHAUSTED" in str(e)),
    wait=wait_exponential(multiplier=1, min=25, max=90),
    stop=stop_after_attempt(5),
    reraise=True,
)

def build_llm(model: str = LLM_MODEL, **kwargs):
    """Return primary LLM with Groq as automatic fallback on quota errors.

    Uses LangChain's with_fallbacks() so no probe calls are needed at startup.
    Falls back whenever the primary raises any exception (quota, 404, etc.).
    """
    primary = init_chat_model(model, **kwargs)
    fallback = init_chat_model(FALLBACK_MODEL, **kwargs)
    return primary.with_fallbacks([fallback])
