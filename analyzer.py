import streamlit as st
import asyncio
import os
import subprocess
import base64
import requests
from playwright.async_api import async_playwright

# --- 1. BOOTSTRAP: THIS FIXES THE "EXECUTABLE DOESN'T EXIST" ERROR ---
def setup_playwright():
    # This command downloads the missing Chromium binary to the correct folder
    if not os.path.exists("/home/appuser/.cache/ms-playwright"):
        try:
            subprocess.run(["playwright", "install", "chromium"], check=True)
            subprocess.run(["playwright", "install-deps"], check=True)
        except Exception as e:
            st.error(f"Setup Error: {e}")

setup_playwright()

# --- 2. VIRUSTOTAL CHECK ---
def get_vt_report(url):
    try:
        if "VT_API_KEY" not in st.secrets:
            return None
        api_key = st.secrets["VT_API_KEY"]
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": api_key}
        response = requests.get(vt_url, headers=headers)
        if response.status_code == 200:
            return response.json()['data']['attributes']['last_analysis_stats'].get('malicious', 0)
        return 0
    except:
        return 0

# --- 3. ANALYSIS ENGINE ---
async def analyze_link(url):
    results = {"score": 100, "flags": [], "title": "Unknown", "final_url": url}
    
    # Simple Logic
    if any(word in url.lower() for word in ['login', 'bank', 'verify', 'secure']):
        results["score"] -= 20
        results["flags"].append("⚠️ **Suspicious Name:** Uses keywords commonly found in phishing links.")

    if not url.startswith("https://"):
        results["score"] -= 30
        results["flags"].append("🔒 **No Security:** This site is not encrypted. It is risky to enter any data.")

    vt_threats = get_vt_report(url)
    if vt_threats and vt_threats > 0:
        results["score"] -= (vt_threats * 10)
        results["flags"].append(f"🚨 **Known Danger:** {vt_threats} security systems have flagged this site as malicious.")

    async with async_playwright() as p:
        try:
            # Added --no-sandbox to work better in Streamlit's Linux environment
            browser = await p.chromium.launch(headless=True, args=["--no-sandbox"])
            context = await browser.new_context()
            page = await context.new_page()
            await page.goto(url, timeout=30000)
            results["title"] = await page.title()
            results["final_url"] = page.url
            await page.screenshot(path="evidence.png")
            await browser.close()
            return True, results
        except Exception as e:
            return False, str(e)

# --- 4. INTERFACE ---
st.set_page_config(page_title="SafeLink Scanner", page_icon="🛡️")
st.title("🛡️ Is This Link Safe?")

target_url = st.text_input("Paste the link you want to check:", "https://")

if st.button("Run Security Scan"):
    with st.spinner("Opening secure sandbox... (The first scan may take a minute)"):
        success, data = asyncio.run(analyze_link(target_url))
        if success:
            score = max(0, data["score"])
            if score >= 80: st.success(f"### Score: {score}% — Likely Safe ✅")
            elif score >= 50: st.warning(f"### Score: {score}% — Caution ⚠️")
            else: st.error(f"### Score: {score}% — DANGER 🛑")
            
            for flag in data["flags"]: st.info(flag)
            st.image("evidence.png", caption="Live Sandbox View")
        else:
            st.error(f"Sandbox Error: {data}")
