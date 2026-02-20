import streamlit as st
import asyncio
import os
import subprocess
import base64
import requests
from playwright.async_api import async_playwright

# --- FORCED INSTALLATION (The Fix) ---
# This runs once when the app starts up on the server
def ensure_playwright_installed():
    try:
        # Check if chromium exists
        import playwright
        browser_path = os.path.expanduser("~/.cache/ms-playwright")
        if not os.path.exists(browser_path):
            subprocess.run(["python", "-m", "playwright", "install", "chromium"])
            subprocess.run(["python", "-m", "playwright", "install-deps"])
    except Exception as e:
        st.error(f"Setup Error: {e}")

ensure_playwright_installed()

# --- SECURITY CHECKS ---
def get_vt_report(url):
    try:
        if "VT_API_KEY" not in st.secrets: return None
        api_key = st.secrets["VT_API_KEY"]
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        response = requests.get(vt_url, headers={"x-apikey": api_key})
        if response.status_code == 200:
            return response.json()['data']['attributes']['last_analysis_stats'].get('malicious', 0)
        return 0
    except: return 0

# --- SANDBOX ENGINE ---
async def analyze_link(url):
    results = {"score": 100, "flags": [], "title": "Unknown", "final_url": url}
    
    # Simple Logic
    if any(word in url.lower() for word in ['login', 'bank', 'verify', 'secure']):
        results["score"] -= 20
        results["flags"].append("⚠️ **Suspicious Name:** Potential phishing keywords detected.")
    if not url.startswith("https://"):
        results["score"] -= 30
        results["flags"].append("🔒 **No Security:** Site is not encrypted.")

    vt_threats = get_vt_report(url)
    if vt_threats and vt_threats > 0:
        results["score"] -= (vt_threats * 10)
        results["flags"].append(f"🚨 **Known Danger:** {vt_threats} systems marked this as MALICIOUS.")

    async with async_playwright() as p:
        try:
            # We add a specific argument to handle the Streamlit environment
            browser = await p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-setuid-sandbox"])
            page = await browser.new_page()
            await page.goto(url, timeout=30000)
            results["title"] = await page.title()
            results["final_url"] = page.url
            await page.screenshot(path="evidence.png")
            await browser.close()
            return True, results
        except Exception as e:
            return False, f"Browser Error: {str(e)}"

# --- UI ---
st.set_page_config(page_title="SafeLink Scanner", page_icon="🛡️")
st.title("🛡️ Is This Link Safe?")

target = st.text_input("Paste link here:", "https://")

if st.button("Start Analysis"):
    with st.spinner("Opening sandbox (this may take 1 minute on first run)..."):
        success, report = asyncio.run(analyze_link(target))
        if success:
            score = max(0, report["score"])
            if score >= 80: st.success(f"### Score: {score}% — Likely Safe ✅")
            elif score >= 50: st.warning(f"### Score: {score}% — Caution ⚠️")
            else: st.error(f"### Score: {score}% — DANGER 🛑")
            for f in report["flags"]: st.info(f)
            st.image("evidence.png", caption="Sandbox Snapshot")
        else:
            st.error(report)
