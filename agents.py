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


def _is_real_screenshot(path: str) -> bool:
    """Placeholder PIL images are ~15 KB; real browser captures are much larger."""
    try:
        return os.path.getsize(path) > 50_000
    except Exception:
        return False


def _fetch_page_context(url: str) -> str:
    """Fetch live HTTP response and extract security-relevant page context."""
    import urllib.request, re
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as r:
            resp_headers = dict(r.headers)
            html = r.read(80_000).decode("utf-8", errors="ignore")
    except Exception as e:
        return f"Could not fetch {url}: {e}"

    sec = {k: v for k, v in resp_headers.items() if any(
        s in k.lower() for s in ["content-security", "x-frame", "strict-transport",
                                  "x-content-type", "referrer-policy",
                                  "set-cookie", "server", "x-powered-by"])}
    missing = [h for h in ["Content-Security-Policy", "X-Frame-Options",
                            "Strict-Transport-Security", "X-Content-Type-Options"]
               if not any(h.lower() in k.lower() for k in sec)]

    title  = (re.findall(r"<title[^>]*>(.*?)</title>", html, re.I | re.S) or [""])[0].strip()
    forms  = re.findall(r"<form[^>]*>", html, re.I)
    inputs = list(set(re.findall(r'<input[^>]+type=["\']?(\w+)', html, re.I)))
    scripts = re.findall(r'src=["\']([^"\']+\.js[^"\']*)', html, re.I)[:8]
    admin_paths = list(set(h for h in re.findall(r'href=["\']([^"\']+)', html, re.I)
                       if any(k in h.lower() for k in ["/admin", "/login", "/dashboard",
                                                        "/wp-", "/phpmyadmin", "/panel"])))[:8]
    return (
        f"URL: {url}\n"
        f"Page title: {title}\n"
        f"Forms: {len(forms)}, input types: {', '.join(inputs) or 'none'}\n"
        f"Sensitive paths linked: {', '.join(admin_paths) or 'none'}\n"
        f"JS libraries: {', '.join(scripts) or 'none'}\n"
        f"Security headers present: {list(sec.keys()) or 'none'}\n"
        f"Missing security headers: {missing}\n"
        f"Server: {resp_headers.get('Server') or resp_headers.get('server') or 'not disclosed'}\n"
        f"X-Powered-By: {resp_headers.get('X-Powered-By') or resp_headers.get('x-powered-by') or 'not disclosed'}\n"
        f"Cookies: {resp_headers.get('Set-Cookie') or resp_headers.get('set-cookie') or 'none'}"
    )


def run_vision(target: str, screenshot_dir: str) -> str:
    """Capture screenshot or fetch live HTML; analyse for security issues."""
    url = _normalize_url(target)
    os.makedirs(screenshot_dir, exist_ok=True)
    path = os.path.join(screenshot_dir, "target.png")
    saved = tools.capture_screenshot(url, path)

    gemini_models = [config.VISION_MODEL,
                     config.FALLBACK_MODEL_1.replace("google_genai:", "")]

    # --- Try real screenshot first (Playwright worked and produced a real image) ---
    if saved and _is_real_screenshot(saved):
        with open(saved, "rb") as fh:
            b64 = base64.standard_b64encode(fh.read()).decode()
        img_msg = HumanMessage(content=[
            {"type": "text", "text": (
                "Analyse this screenshot from an authorised attack-surface assessment. "
                "Identify: login portals, admin panels, dashboards, WAF/block pages, "
                "technology fingerprints, exposed version numbers. Be specific and concise."
            )},
            {"type": "image_url", "image_url": f"data:image/png;base64,{b64}"},
        ])
        for model_name in gemini_models:
            try:
                llm = ChatGoogleGenerativeAI(model=model_name, max_output_tokens=1024)
                text = _extract_text(config.llm_retry(llm.invoke)([img_msg]).content)
                if text:
                    tools._mem().set_fact("vision_findings", text)
                    tools._mem().set_fact("screenshot_path", saved)
                    tools._mem().add_note(f"Screenshot analysis of {url}: {text[:400]}")
                    return text
            except Exception:
                continue

    # --- Fallback: analyse real live HTTP response (works on any server) ---
    page_context = _fetch_page_context(url)
    html_prompt = (
        "You are performing a web security assessment. Based on the live HTTP "
        "response data below, identify security issues: missing headers, sensitive "
        "paths, technology disclosure, insecure cookies, login surfaces. "
        "Be specific and concise.\n\n" + page_context
    )
    from langchain.chat_models import init_chat_model
    for model_id in [f"google_genai:{m}" for m in gemini_models] + [config.FALLBACK_MODEL]:
        try:
            llm = init_chat_model(model_id)
            text = _extract_text(config.llm_retry(llm.invoke)(
                [HumanMessage(content=html_prompt)]).content)
            if text:
                tools._mem().set_fact("vision_findings", text)
                tools._mem().add_note(f"Page analysis of {url}: {text[:400]}")
                return text
        except Exception:
            continue

    return "Visual analysis unavailable."
