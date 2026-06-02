# CLAUDE.md — Autonomous Attack Surface Mapper

Context for continuing this project in Claude Code. Read this first.

## What this is

A multi-agent system that maps a target's external attack surface and produces
a risk-rated findings report. A LangGraph **supervisor** coordinates three
specialist agents: **recon** (subdomains + ports), **vision** (screenshot + UI
analysis), and **analysis** (signature-based detection). Recon data is stored
in **agent memory** (FAISS for semantic notes, a plain dict for structured
facts) so agents recall instead of re-scanning. The UI is Streamlit with live
agent-log streaming.

## Scope — keep this invariant

This tool does **reconnaissance and detection only**. It must not perform or
gain the ability to perform exploitation. Concretely, when extending it:
- Do not add modules that launch exploits/payloads or weaponise findings.
- Keep the authorisation-confirmation gate in the UI (`app.py`).
- Keep `SIMULATION_MODE` as the safe default.
- The deliverable is a findings/assessment report, like a real pentest write-up.

This is intentional and is what makes it demo-safe and credible. Don't "helpfully"
remove these.

## Architecture

```
target ─▶ supervisor (LLM choice + whitelist + circuit breaker)
            ├─▶ recon    (subfinder, nmap)        ─┐
            ├─▶ vision   (Playwright + Gemini)     ├─▶ memory (facts + FAISS)
            ├─▶ analysis (nuclei)                 ─┘        │
            └─▶ report ──────────────────────────────────▶ runs/report.md
```

## File map

| File | Responsibility |
| --- | --- |
| `app.py` | Streamlit dashboard, auth gate, live log streaming, report display |
| `orchestrator.py` | LangGraph `StateGraph`, supervisor node, routing, `run_scan()` generator |
| `agents.py` | recon/analysis ReAct workers (`create_agent`) + `run_vision()` |
| `tools.py` | `@tool` wrappers (real + simulated), `capture_screenshot()`, active-memory hookup |
| `memory.py` | `MemoryStore`: dict facts + FAISS semantic notes (keyword fallback) |
| `report.py` | markdown report generation |
| `config.py` | env-driven settings |

## Key decisions

- **LLM:** Gemini 2.5 Flash via `langchain-google-genai` (`google_genai:gemini-2.5-flash`).
  Key from `GEMINI_API_KEY` env var — never hardcode it.
- **Supervisor** is hand-rolled on `StateGraph` (not `langgraph-supervisor`) so the
  circuit breaker (`MAX_SUPERVISOR_STEPS`) and whitelist routing are explicit.
- **Memory split:** structured facts → dict (exact lookups like open ports);
  unstructured observations → FAISS (semantic recall). Don't put structured
  facts in FAISS.
- **Vision** is a direct multimodal call, not a ReAct loop (images through tool
  results are unreliable). Gemini wants `image_url` data-URI format.
- **Active memory** is a module-level singleton in `tools.py` set per run — fine
  for single-user Streamlit, NOT thread-safe (don't run concurrent scans).

## Current state

- All modules compile. Verified at syntax/import level only — not yet run
  end-to-end (needs `GEMINI_API_KEY` and, for live mode, the binaries).
- Expect first-run tuning. Most likely spots: ReAct tool-calling reliability on
  Gemini (tighten tool docstrings in `tools.py` if a tool is skipped), and the
  Gemini image block format in `agents.py`.

## Run

```bash
pip install -r requirements.txt
export GEMINI_API_KEY=...
streamlit run app.py          # launches in simulation mode by default
```

Live mode (sidebar toggle): also `playwright install chromium` and install
`subfinder`, `nmap`, `nuclei`.

## Suggested next steps

1. Eval harness scoring supervisor routing accuracy (good thing to demo).
2. End-to-end run + fix first-run issues.
3. Real embeddings-backed memory demo (confirm FAISS path, not keyword fallback).
4. Dashboard polish.
