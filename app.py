"""Streamlit dashboard for the Autonomous Attack Surface Mapper.

Run with:  streamlit run app.py
"""
import os
import subprocess
import sys

# Always ensure Playwright's Chromium binary is present.
# `playwright install` is a fast no-op if the binary already exists,
# so running it unconditionally is safe and fixes Streamlit Cloud cold starts.
subprocess.run(
    [sys.executable, "-m", "playwright", "install", "chromium"],
    check=False, capture_output=True,
)

import streamlit as st

import config
import orchestrator

st.set_page_config(page_title="Attack Surface Mapper", page_icon="🛰️",
                   layout="wide")

AGENT_ICONS = {"supervisor": "🧭", "recon": "🔎", "vision": "👁️",
               "analysis": "🧪", "report": "📄"}

st.title("🛰️ Autonomous Attack Surface Mapper")
st.caption("A supervisor coordinates recon, vision, and detection agents to "
           "map and report on a target's attack surface. Reconnaissance and "
           "detection only — no exploitation.")

with st.sidebar:
    st.header("Configuration")
    sim = st.toggle("Simulation mode", value=config.SIMULATION_MODE,
                    help="Generate realistic synthetic recon data without "
                         "needing nmap/subfinder/nuclei installed.")
    os.environ["ASM_SIMULATION"] = "true" if sim else "false"
    config.SIMULATION_MODE = sim
    st.write(f"**Model:** `{config.LLM_MODEL}`")
    if not sim:
        st.warning("Live mode shells out to real tools and touches the target. "
                   "Only proceed against assets you are authorised to test.")

target = st.text_input("Target domain or URL", placeholder="example.com")

authorized = st.checkbox(
    "I confirm I own this target or have explicit written authorisation to "
    "test it.")

run = st.button("Run assessment", type="primary",
                disabled=not (target and authorized))

if run:
    log_box = st.container()
    rendered = {}
    memory = None

    with st.status("Agents working…", expanded=True) as status:
        for update in orchestrator.run_scan(target.strip()):
            if "__memory__" in update:
                memory = update["__memory__"]
                continue
            # update is {node_name: state_delta}
            for node, delta in update.items():
                for entry in delta.get("logs", []):
                    icon = AGENT_ICONS.get(entry["agent"], "•")
                    with log_box:
                        st.markdown(f"{icon} **{entry['agent']}** — "
                                    f"{entry['message']}")
        status.update(label="Assessment complete", state="complete")

    if memory is not None:
        facts = memory.all_facts()
        st.divider()
        col1, col2 = st.columns([2, 1])
        with col1:
            st.subheader("Findings report")
            st.markdown(facts.get("report_markdown", "_No report produced._"))
            st.download_button("Download report (.md)",
                               facts.get("report_markdown", ""),
                               file_name=f"{target.strip()}_report.md")
        with col2:
            shot = facts.get("screenshot_path")
            if shot and os.path.exists(shot):
                st.subheader("Captured screenshot")
                st.image(shot, use_container_width=True)
