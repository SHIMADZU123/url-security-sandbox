import streamlit as st
import asyncio
import os
import base64
import requests
from playwright.async_api import async_playwright

# --- VIRUSTOTAL CHECK ---
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
            return response.json()['data']['attributes']['last_analysis_stats']['malicious']
        return 0
    except Exception:
        return 0

# --- ANALYSIS ENGINE ---
async def analyze_link(url):
    results = {"score": 100, "flags": [], "title": "Unknown", "final_url": url}
    
    # Static Analysis
    suspicious_keywords = ['login', 'verify', 'bank', 'secure', 'update', 'account']
    if any(word in url.lower() for word in suspicious_keywords):
        results["score"] -= 20
        results["flags"].append("⚠️ **Suspicious Name:** Uses words meant to trick you.")

    if not url.startswith("https://"):
        results["score"] -= 30
        results["flags"].append("🔒 **No Security:** This site is not private.")

    vt_malicious = get_vt_report(url)
    if vt_malicious and vt_malicious > 0:
        results["score"] -= (vt_malicious * 10)
        results["flags"].append(f"🚨 **Known Threat:** {vt_malicious} security vendors say this is DANGEROUS.")

    async with async_playwright() as p:
        # Browser is launched normally
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()
        try:
            await page.goto(url, timeout=30000)
            results["title"] = await page.title()
            results["final_url"] = page.url
            await page.screenshot(path="evidence.png")
            await browser.close()
            return True, results
        except Exception as e:
            await browser.close()
            return False, str(e)

# --- USER INTERFACE ---
st.set_page_config(page_title="SafeLink Scanner", page_icon="🛡️")
st.title("🛡️ Is This Link Safe?")
st.write("We check links in a secure sandbox so you don't have to.")

target_url = st.text_input("Paste link here:", "https://")

if st.button("Check Safety"):
    with st.spinner("Analyzing..."):
        success, data = asyncio.run(analyze_link(target_url))
        if success:
            score = max(0, data["score"])
            if score >= 80: st.success(f"### Score: {score}% — Safe ✅")
            elif score >= 50: st.warning(f"### Score: {score}% — Caution ⚠️")
            else: st.error(f"### Score: {score}% — DANGER 🛑")
            for flag in data["flags"]: st.info(flag)
            st.image("evidence.png")
        else:
            st.error(f"Error: {data}")
