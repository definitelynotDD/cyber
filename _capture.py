"""Standalone Playwright screenshot helper — called as a subprocess by tools.py."""
import sys

url, out_path = sys.argv[1], sys.argv[2]

from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page(viewport={"width": 1280, "height": 800})
    page.goto(url, timeout=30000, wait_until="domcontentloaded")
    page.wait_for_timeout(1000)
    page.screenshot(path=out_path, full_page=False)
    browser.close()
