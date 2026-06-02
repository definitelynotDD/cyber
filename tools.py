"""Security tool wrappers exposed to the agents as LangChain tools.

Each tool either shells out to the real binary or, in SIMULATION_MODE, returns
realistic synthetic data so the pipeline runs without anything installed.
Tools write structured results into the active MemoryStore as a side effect
and return a short text summary for the agent's reasoning loop.

Scope note: these run reconnaissance and *detection* only (enumerate,
fingerprint, match known-CVE signatures, screenshot). Nothing here attempts
exploitation.
"""
from __future__ import annotations

import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
from typing import Optional

from langchain_core.tools import tool

import config
from memory import MemoryStore

# The orchestrator sets this before invoking each worker agent.
_ACTIVE_MEMORY: Optional[MemoryStore] = None


def set_active_memory(mem: MemoryStore) -> None:
    global _ACTIVE_MEMORY
    _ACTIVE_MEMORY = mem


def _mem() -> MemoryStore:
    if _ACTIVE_MEMORY is None:
        raise RuntimeError("No active MemoryStore set for tools.")
    return _ACTIVE_MEMORY


def _have(binary: str) -> bool:
    return shutil.which(binary) is not None


def _run(cmd: list[str]) -> str:
    try:
        out = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=config.TOOL_TIMEOUT,
            check=False,
        )
        return out.stdout or out.stderr
    except subprocess.TimeoutExpired:
        return f"[timeout after {config.TOOL_TIMEOUT}s]"
    except Exception as e:  # pragma: no cover
        return f"[error: {e}]"


def _seed(target: str) -> random.Random:
    """Deterministic synthetic data per target so demos are reproducible."""
    h = int(hashlib.sha256(target.encode()).hexdigest(), 16)
    return random.Random(h)


# --- recon -----------------------------------------------------------------
@tool(parse_docstring=True)
def enumerate_subdomains(domain: str) -> str:
    """Enumerate subdomains for a domain using passive sources (subfinder).

    Args:
        domain: The root domain to enumerate, e.g. "example.com".

    Returns:
        A summary of discovered subdomains.
    """
    if config.SIMULATION_MODE or not _have("subfinder"):
        rng = _seed(domain)
        prefixes = ["www", "api", "dev", "staging", "admin", "mail", "vpn",
                    "portal", "test", "cdn", "git", "internal"]
        rng.shuffle(prefixes)
        subs = [f"{p}.{domain}" for p in prefixes[: rng.randint(4, 8)]]
    else:
        raw = _run(["subfinder", "-silent", "-d", domain])
        subs = [s.strip() for s in raw.splitlines() if s.strip()]

    _mem().set_fact("subdomains", subs)
    for s in subs:
        _mem().add_note(f"Subdomain {s} resolves for {domain}.")
    return f"Found {len(subs)} subdomains: {', '.join(subs[:10])}"


@tool(parse_docstring=True)
def scan_ports(host: str) -> str:
    """Scan a host for open TCP ports and service banners (nmap).

    Args:
        host: Hostname or subdomain to scan, e.g. "api.example.com".

    Returns:
        A summary of open ports and detected services.
    """
    if config.SIMULATION_MODE or not _have("nmap"):
        rng = _seed(host)
        catalog = {22: "ssh OpenSSH 8.9", 80: "http nginx 1.24",
                   443: "https nginx 1.24", 8080: "http-proxy",
                   3306: "mysql 8.0", 6379: "redis", 21: "ftp vsftpd"}
        chosen = rng.sample(list(catalog), rng.randint(2, 4))
        ports = {p: catalog[p] for p in sorted(chosen)}
    else:
        raw = _run(["nmap", "-sV", "-T4", "--open", "-oG", "-", host])
        ports = {}
        for line in raw.splitlines():
            if "Ports:" in line:
                for chunk in line.split("Ports:")[1].split(","):
                    parts = chunk.strip().split("/")
                    if len(parts) >= 5 and parts[1] == "open":
                        ports[int(parts[0])] = parts[4] or parts[2]

    store = _mem().get_fact("open_ports", {})
    store[host] = ports
    _mem().set_fact("open_ports", store)
    for p, svc in ports.items():
        _mem().add_note(f"{host} has port {p} open running {svc}.")
    return f"{host}: open ports " + ", ".join(f"{p} ({s})" for p, s in ports.items())


# --- detection -------------------------------------------------------------
@tool(parse_docstring=True)
def detect_known_issues(url: str) -> str:
    """Run signature-based detection of known issues against a URL (nuclei).

    This matches published vulnerability/misconfiguration *signatures*; it does
    not exploit anything.

    Args:
        url: Full URL to scan, e.g. "https://example.com".

    Returns:
        A summary of detection findings with severities.
    """
    if config.SIMULATION_MODE or not _have("nuclei"):
        rng = _seed(url)
        catalog = [
            ("info", "Missing security headers (X-Frame-Options, CSP)"),
            ("low", "Server version disclosed in response header"),
            ("medium", "Directory listing enabled on /assets/"),
            ("medium", "Cookie set without Secure/HttpOnly flags"),
            ("low", "TLS 1.0/1.1 still supported"),
            ("info", "robots.txt exposes /admin/ path"),
        ]
        n = rng.randint(2, 4)
        findings = [{"severity": s, "name": d} for s, d in rng.sample(catalog, n)]
    else:
        raw = _run(["nuclei", "-silent", "-jsonl", "-u", url])
        findings = []
        for line in raw.splitlines():
            try:
                j = json.loads(line)
                findings.append({
                    "severity": j.get("info", {}).get("severity", "unknown"),
                    "name": j.get("info", {}).get("name", j.get("template-id", "?")),
                })
            except json.JSONDecodeError:
                continue

    existing = _mem().get_fact("vulnerabilities", [])
    existing.extend(findings)
    _mem().set_fact("vulnerabilities", existing)
    for f in findings:
        _mem().add_note(f"[{f['severity']}] {f['name']} at {url}")
    return f"{len(findings)} findings: " + "; ".join(
        f"{f['severity']}: {f['name']}" for f in findings)


@tool(parse_docstring=True)
def recall(query: str) -> str:
    """Query the agent's semantic memory of everything gathered so far.

    Use this instead of re-running a scan when you need prior recon data.

    Args:
        query: Natural-language question, e.g. "which hosts run mysql".

    Returns:
        The most relevant stored observations.
    """
    notes = _mem().query_notes(query, k=5)
    if not notes:
        return "No relevant memory yet."
    return "\n".join(f"- {n}" for n in notes)


# --- screenshot (used by the vision node, not the ReAct loop) --------------
def capture_screenshot(url: str, out_path: str) -> Optional[str]:
    """Capture a headless screenshot with Playwright. Returns path or None.

    In SIMULATION_MODE (or if Playwright isn't installed) renders a simple
    placeholder PNG so the vision step still has something to analyse.
    """
    # Run Playwright in a subprocess to avoid asyncio event-loop conflicts
    # with Streamlit's own loop. Errors are printed so they surface in the terminal.
    import subprocess, sys
    _here   = os.path.dirname(os.path.abspath(__file__))
    _helper = os.path.join(_here, "_capture.py")
    _abs_out = os.path.abspath(out_path)
    try:
        result = subprocess.run(
            [sys.executable, _helper, url, _abs_out],
            timeout=90, capture_output=True, text=True,
            cwd=_here,
        )
        if result.returncode == 0 and os.path.exists(_abs_out):
            return _abs_out
        if result.stderr:
            print(f"[screenshot] Playwright error: {result.stderr[-600:]}", flush=True)
    except Exception as exc:
        print(f"[screenshot] subprocess failed: {exc}", flush=True)

    # placeholder image so the pipeline never hard-fails
    try:
        from PIL import Image, ImageDraw  # type: ignore

        img = Image.new("RGB", (1280, 800), (245, 246, 248))
        d = ImageDraw.Draw(img)
        d.rectangle([0, 0, 1280, 64], fill=(33, 41, 54))
        d.text((24, 24), f"[simulated screenshot] {url}", fill=(255, 255, 255))
        d.rectangle([480, 320, 800, 520], outline=(120, 130, 150), width=2)
        d.text((520, 340), "Login", fill=(60, 70, 90))
        img.save(out_path)
        return out_path
    except Exception:
        return None


RECON_TOOLS = [enumerate_subdomains, scan_ports, recall]
ANALYSIS_TOOLS = [detect_known_issues, recall]
