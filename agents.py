"""Worker agents and the vision node.

recon + analysis are real ReAct agents (langchain create_agent) that decide
for themselves which tools to call. vision is a direct multimodal call because
streaming an image through a tool loop is awkward and unreliable.
"""
from __future__ import annotations

import base64
import os
from typing import Callable

from langchain.agents import create_agent
from langchain_core.messages import HumanMessage
from langchain_google_genai import ChatGoogleGenerativeAI

import config
import tools

RECON_PROMPT = (
    "You are a reconnaissance specialist mapping an attack surface. "
    "Follow these steps in order:\n"
    "1. Enumerate subdomains for the target.\n"
    "2. Scan the most interesting hosts (api, admin, dev, staging, vpn, portal first) for open ports.\n"
    "3. Run audit_ssl_all on the root domain to check SSL certificates across ALL subdomains.\n"
    "Use the recall tool to avoid repeating work. Be concise. "
    "When you have a clear picture of the surface, summarise what you found."
)

ANALYSIS_PROMPT = (
    "You are a vulnerability assessment specialist. Using the recon data in "
    "memory (use the recall tool), run signature-based detection against the "
    "live hosts/URLs you know about. Detect and report only — never attempt "
    "exploitation. Summarise findings grouped by severity."
)


def _worker(model: str, prompt: str, tool_list: list[Callable]):
    return create_agent(model=model, tools=tool_list, system_prompt=prompt)


recon_agent = _worker(config.LLM_MODEL, RECON_PROMPT, tools.RECON_TOOLS)
analysis_agent = _worker(config.LLM_MODEL, ANALYSIS_PROMPT, tools.ANALYSIS_TOOLS)

# Fallback agents — built lazily: gemini-3.1-flash-lite first, then groq.
_recon_fb1: object = None
_recon_fb2: object = None
_analysis_fb1: object = None
_analysis_fb2: object = None


def _get_recon_fallback():
    global _recon_fb1, _recon_fb2
    if _recon_fb1 is None:
        _recon_fb1 = _worker(config.FALLBACK_MODEL_1, RECON_PROMPT, tools.RECON_TOOLS)
    if _recon_fb2 is None:
        _recon_fb2 = _worker(config.FALLBACK_MODEL, RECON_PROMPT, tools.RECON_TOOLS)
    return _recon_fb1, _recon_fb2


def _get_analysis_fallback():
    global _analysis_fb1, _analysis_fb2
    if _analysis_fb1 is None:
        _analysis_fb1 = _worker(config.FALLBACK_MODEL_1, ANALYSIS_PROMPT, tools.ANALYSIS_TOOLS)
    if _analysis_fb2 is None:
        _analysis_fb2 = _worker(config.FALLBACK_MODEL, ANALYSIS_PROMPT, tools.ANALYSIS_TOOLS)
    return _analysis_fb1, _analysis_fb2


def _is_quota_error(e: Exception) -> bool:
    s = str(e)
    return "429" in s or "RESOURCE_EXHAUSTED" in s or "quota" in s.lower() or "NOT_FOUND" in s


def _extract_text(content) -> str:
    """Pull plain text out of Gemini's content-block list or a raw string."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(
            block.get("text", "") for block in content
            if isinstance(block, dict) and block.get("type") == "text"
        ).strip()
    return str(content)


def _normalize_url(target: str) -> str:
    """Strip malformed protocol prefixes (e.g. 'chttps://') and return a valid URL."""
    import re
    # Replace any garbled prefix that ends in https:// or http://
    cleaned = re.sub(r'^.*?(https?://)', r'\1', target)
    if cleaned == target and not target.startswith("http"):
        cleaned = f"https://{target}"
    return cleaned


def _invoke_with_fallbacks(primary, fallbacks, msg):
    try:
        return config.llm_retry(primary.invoke)(msg)
    except Exception as e:
        if not _is_quota_error(e):
            raise
    for fb in fallbacks:
        try:
            return fb.invoke(msg)
        except Exception as e:
            if not _is_quota_error(e):
                raise
    raise RuntimeError("All models exhausted quota.")


def run_recon(target: str) -> str:
    msg = {"messages": [{"role": "user", "content": f"Map the attack surface of {target}."}]}
    res = _invoke_with_fallbacks(recon_agent, list(_get_recon_fallback()), msg)
    return _extract_text(res["messages"][-1].content)


def run_analysis(target: str) -> str:
    msg = {"messages": [{"role": "user", "content": f"Assess the hosts discovered for {target}."}]}
    res = _invoke_with_fallbacks(analysis_agent, list(_get_analysis_fallback()), msg)
    return _extract_text(res["messages"][-1].content)


def run_vision(target: str, screenshot_dir: str) -> str:
    """Capture a screenshot of the target and analyse it with a vision model."""
    url = _normalize_url(target)
    os.makedirs(screenshot_dir, exist_ok=True)
    path = os.path.join(screenshot_dir, "target.png")
    saved = tools.capture_screenshot(url, path)

    if not saved:
        return "Screenshot unavailable; skipping visual analysis."

    with open(saved, "rb") as fh:
        b64 = base64.standard_b64encode(fh.read()).decode()

    # Vision must stay on Gemini — Groq/llama does not support image inputs.
    # Try primary then one Gemini fallback; if both fail, degrade gracefully.
    prompt = (
        "You are analysing a screenshot of a web target during an authorised "
        "attack-surface assessment. Identify anything security-relevant a "
        "text-only scanner would miss: login portals, admin panels, exposed "
        "dashboards, default/setup pages, WAF or block pages, technology "
        "fingerprints visible in the UI. Be specific and concise."
    )
    msg = HumanMessage(content=[
        {"type": "text", "text": prompt},
        {"type": "image_url", "image_url": f"data:image/png;base64,{b64}"},
    ])

    gemini_models = [config.VISION_MODEL, config.FALLBACK_MODEL_1.replace("google_genai:", "")]
    text = None
    for model_name in gemini_models:
        try:
            llm = ChatGoogleGenerativeAI(model=model_name, max_output_tokens=1024)
            findings = config.llm_retry(llm.invoke)([msg]).content
            text = _extract_text(findings)
            break
        except Exception:
            continue

    if not text:
        text = "Visual analysis unavailable (vision quota exhausted or screenshot capture failed)."

    tools._mem().set_fact("vision_findings", text)
    tools._mem().set_fact("screenshot_path", saved)
    tools._mem().add_note(f"Visual analysis of {url}: {text[:400]}")
    return text
