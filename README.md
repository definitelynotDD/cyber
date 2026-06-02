# 🛰️ Autonomous Attack Surface Mapper

A multi-agent system that maps a target's external attack surface and produces
a risk-rated findings report. A **supervisor** agent (LangGraph) coordinates
three specialists:

| Agent | Job | Tools |
| --- | --- | --- |
| 🔎 Recon | subdomain enumeration + port scanning | `subfinder`, `nmap` |
| 👁️ Vision | screenshots the target and analyses the UI for login portals, admin panels, WAF/block pages, exposed dashboards | Playwright + a multimodal LLM |
| 🧪 Analysis | signature-based detection of known issues | `nuclei` |

Recon data is stored in **agent memory** — structured facts in a plain store,
unstructured observations in a **FAISS** vector index — so agents recall prior
findings instead of re-scanning.

> **Scope:** this tool performs reconnaissance and *detection* only. It does
> not attempt exploitation. The UI requires you to confirm authorisation, and
> `runs/report.md` is the deliverable. Run it only against assets you own or
> are explicitly authorised to test — unauthorised active scanning is illegal
> in most jurisdictions.

## Quick start (zero dependencies beyond pip)

```bash
pip install -r requirements.txt
export GEMINI_API_KEY=...                # for the agents + vision model
streamlit run app.py
```

It launches in **simulation mode** by default: recon tools return realistic
synthetic data, so the full multi-agent pipeline runs and demos without
`nmap` / `subfinder` / `nuclei` installed. Toggle simulation off in the
sidebar to use the real binaries.

## Live mode

Install the external tools (not pip packages) and Playwright's browser:

```bash
playwright install chromium
# install subfinder, nmap, nuclei via your package manager / their releases
```

Then untoggle "Simulation mode" in the sidebar.

## Architecture

```
                ┌─────────────┐
   target ─────▶│ Supervisor  │◀───────────┐  (circuit breaker + whitelist)
                └──────┬──────┘            │
          ┌───────────┼───────────┐        │
          ▼           ▼           ▼        │
       Recon       Vision      Analysis    │
          └───────────┴───────────┴────────┘
                       │
                       ▼
                 Memory (facts + FAISS)
                       │
                       ▼
                   Report (.md)
```

The supervisor is LLM-driven but every routing decision is validated against a
whitelist and bounded by a step counter (`ASM_MAX_STEPS`) so the graph can
never loop forever.

## Configuration (env vars)

| Var | Default | Meaning |
| --- | --- | --- |
| `ASM_SIMULATION` | `true` | synthetic data vs. real tools |
| `ASM_LLM_MODEL` | `google_genai:gemini-2.5-flash` | agent + supervisor model |
| `ASM_VISION_MODEL` | `gemini-2.5-flash` | multimodal model for screenshots |
| `ASM_MAX_STEPS` | `12` | supervisor circuit breaker |
| `ASM_TOOL_TIMEOUT` | `120` | per-tool timeout (s) |

## Files

- `app.py` — Streamlit dashboard with live agent-log streaming
- `orchestrator.py` — LangGraph supervisor + state graph
- `agents.py` — recon/analysis ReAct workers + vision node
- `tools.py` — tool wrappers (real + simulated) and screenshot capture
- `memory.py` — FAISS semantic store + structured fact store
- `report.py` — markdown report generation
- `config.py` — settings
