"""Findings report generation.

Produces a risk-rated markdown report from the MemoryStore — the kind of
deliverable a real attack-surface assessment ends with.
"""
from __future__ import annotations

import datetime
import os

from memory import MemoryStore

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3,
                  "info": 4, "unknown": 5}
REPORT_PATH = "runs/report.md"

# Recommended fixes keyed on substrings that appear in finding names.
_FIXES: list[tuple[str, str]] = [
    ("x-frame-options",      "Add `X-Frame-Options: SAMEORIGIN` to all HTTP responses."),
    ("csp",                  "Deploy a Content-Security-Policy header; start with `default-src 'self'`."),
    ("security header",      "Enable security headers (X-Frame-Options, CSP, HSTS, X-Content-Type-Options) via server/CDN config."),
    ("hsts",                 "Enforce HTTPS with `Strict-Transport-Security: max-age=31536000; includeSubDomains`."),
    ("x-content-type",       "Set `X-Content-Type-Options: nosniff` to prevent MIME sniffing."),
    ("clickjack",            "Set `X-Frame-Options: DENY` or use a CSP `frame-ancestors 'none'` directive."),
    ("directory listing",    "Disable directory listing in the web server config (e.g. `Options -Indexes` in Apache)."),
    ("exposed git",          "Block public access to `/.git/` via server config or move the repo outside the web root."),
    ("exposed env",          "Remove `.env` from the web root; add it to `.gitignore` and rotate any leaked secrets."),
    ("open redirect",        "Validate and whitelist redirect destinations; never reflect raw user-supplied URLs."),
    ("sql injection",        "Use parameterised queries / prepared statements; never interpolate user input into SQL."),
    ("xss",                  "Encode all user-supplied output; implement a strict CSP; use framework auto-escaping."),
    ("default credential",   "Change default credentials immediately; enforce a strong password policy and MFA."),
    ("ssh",                  "Restrict SSH to key-based auth; disable password login; firewall port 22 to known IPs."),
    ("admin panel",          "Move admin interfaces behind VPN or IP allowlist; enable MFA for all admin accounts."),
    ("cors",                 "Scope `Access-Control-Allow-Origin` to trusted origins only; never use `*` for credentialed requests."),
    ("tls",                  "Upgrade to TLS 1.2+; disable SSLv3/TLS 1.0/1.1; use strong cipher suites."),
    ("outdated",             "Patch or upgrade the component to a supported version; subscribe to vendor security advisories."),
    ("information disclosure","Remove server/version banners from HTTP headers and error pages."),
    ("cookie",               "Set the `Secure` and `HttpOnly` flags on all session/auth cookies; also add `SameSite=Strict`."),
    ("server version",       "Remove server version banners: set `server_tokens off` (nginx) or `ServerTokens Prod` (Apache)."),
    ("robots.txt",           "Remove sensitive paths from `robots.txt`; security-by-obscurity isn't protection, but don't advertise `/admin/`."),
]

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🔵",
    "info":     "⚪",
}


def _fix_for(name: str) -> str:
    nl = name.lower()
    for keyword, fix in _FIXES:
        if keyword in nl:
            return fix
    return "Review manually and apply the principle of least privilege / defence in depth."


def generate(mem: MemoryStore, out_path: str = REPORT_PATH) -> str:
    facts = mem.all_facts()
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

    subs   = facts.get("subdomains", [])
    ports  = facts.get("open_ports", {})
    vulns  = facts.get("vulnerabilities", [])
    vision = facts.get("vision_findings", "")
    ssl    = facts.get("ssl_certificate", {})
    ssl_all = facts.get("ssl_all", {})

    sorted_vulns = sorted(vulns, key=lambda x: SEVERITY_ORDER.get(
        x.get("severity", "unknown"), 9))

    counts: dict[str, int] = {}
    for v in vulns:
        sev = v.get("severity", "unknown")
        counts[sev] = counts.get(sev, 0) + 1

    lines: list[str] = []
    lines.append(f"# Attack Surface Assessment — {mem.target}")
    lines.append("")
    lines.append(f"*Generated {now}. Detection and reconnaissance only — no "
                 "exploitation was performed. Run only against assets you own "
                 "or are explicitly authorised to test.*")
    lines.append("")

    # --- Summary ---
    lines.append("## Summary")
    lines.append("")
    lines.append(f"| Metric | Value |")
    lines.append(f"| --- | --- |")
    lines.append(f"| Subdomains discovered | **{len(subs)}** |")
    lines.append(f"| Hosts scanned | **{len(ports)}** |")
    lines.append(f"| Total findings | **{len(vulns)}** |")
    for sev in ["critical", "high", "medium", "low", "info"]:
        if sev in counts:
            lines.append(f"| {SEVERITY_EMOJI.get(sev, '')} {sev.capitalize()} | {counts[sev]} |")
    lines.append("")

    # --- Subdomains ---
    if subs:
        lines.append("## Subdomains")
        lines.append("")
        for s in subs:
            lines.append(f"- `{s}`")
        lines.append("")

    # --- Ports ---
    if ports:
        lines.append("## Open Ports & Services")
        lines.append("")
        lines.append("| Host | Port | Service |")
        lines.append("| --- | --- | --- |")
        for host, hostports in ports.items():
            for p, svc in hostports.items():
                lines.append(f"| `{host}` | {p} | {svc} |")
        lines.append("")

    # --- SSL Certificates (all subdomains) ---
    if ssl_all:
        lines.append("## SSL Certificates")
        lines.append("")
        lines.append("| Host | Status | Issuer |")
        lines.append("| --- | --- | --- |")
        for host, info in ssl_all.items():
            lines.append(f"| `{host}` | {info.get('status', '?')} | {info.get('issuer', '?')} |")
        lines.append("")
    elif ssl:
        days = ssl.get("days_left", 9999)
        status = (
            "🔴 EXPIRED" if days < 0
            else "🟡 Expiring soon" if days <= 30
            else "🟢 Valid"
        )
        lines.append("## SSL Certificate")
        lines.append("")
        lines.append(f"| Field | Value |")
        lines.append(f"| --- | --- |")
        lines.append(f"| Status | {status} ({days} days remaining) |")
        lines.append(f"| Issuer | {ssl.get('issuer', 'unknown')} |")
        lines.append(f"| Expiry | {ssl.get('expiry', 'unknown')} |")
        lines.append(f"| Self-signed | {'⚠ Yes' if ssl.get('self_signed') else 'No'} |")
        lines.append("")

    # --- Visual Analysis ---
    if vision:
        lines.append("## Visual Analysis")
        lines.append("")
        lines.append(vision)
        lines.append("")

    # --- Findings with fixes (deduplicated, grouped by severity+name) ---
    if sorted_vulns:
        lines.append("## Findings & Recommended Fixes")
        lines.append("")
        lines.append("> Findings are sorted by severity. Each entry includes a "
                     "concise remediation step.")
        lines.append("")

        # Deduplicate: group by (severity, name), collect affected hosts.
        seen: dict[tuple, list[str]] = {}
        for v in sorted_vulns:
            key = (v.get("severity", "unknown"), v.get("name", "Unnamed finding"))
            host = v.get("url") or v.get("host") or ""
            seen.setdefault(key, [])
            if host and host not in seen[key]:
                seen[key].append(host)

        for (sev, name), hosts in sorted(seen.items(),
                                         key=lambda x: SEVERITY_ORDER.get(x[0][0], 9)):
            emoji = SEVERITY_EMOJI.get(sev, "")
            fix   = _fix_for(name)
            lines.append(f"### {emoji} [{sev.upper()}] {name}")
            lines.append("")
            if hosts:
                lines.append(f"**Affected hosts:** {', '.join(f'`{h}`' for h in hosts)}")
                lines.append("")
            lines.append(f"**Fix:** {fix}")
            lines.append("")

    md = "\n".join(lines)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(md)
    mem.set_fact("report_markdown", md)
    return md
