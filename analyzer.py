import streamlit as st
import asyncio
import os
import base64
import requests
from playwright.async_api import async_playwright

# 1. BROWSER SETUP
if not os.path.exists("/home/appuser/.cache/ms-playwright"):
    os.system("playwright install chromium")

# 2. VIRUSTOTAL CHECK
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

# 3. CORE ANALYSIS
async def analyze_link(url):
    results = {"score": 100, "flags": [], "title": "Unknown", "final_url": url}
    
    # Simple Logic for Humans
    suspicious_keywords = ['login', 'verify', 'bank', 'secure', 'update', 'account', 'signin', 'wp-admin']
    if any(word in url.lower() for word in suspicious_keywords):
        results["score"] -= 20
        results["flags"].append("⚠️ **Suspicious Name:** The web address uses words that hackers often use to trick you.")

    if not url.startswith("https://"):
        results["score"] -= 30
        results["flags"].append("🔒 **No Padlock:** This site is not encrypted. Any info you type can be stolen.")

    vt_malicious = get_vt_report(url)
    if vt_malicious and vt_malicious > 0:
        results["score"] -= (vt_malicious * 10)
        results["flags"].append(f"🚨 **Known Threat:** {vt_malicious} security systems have officially marked this site as DANGEROUS.")

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()
        try:
            await page.goto(url, timeout=30000)
            results["title"] = await page.title()
            results["final_url"] = page.url
            
            if results["final_url"].rstrip('/') != url.rstrip('/'):
                results["score"] -= 15
                results["flags"].append("🔀 **Hidden Redirect:** The link secretly sent you to a different website.")

            await page.screenshot(path="evidence.png")
            await browser.close()
            return True, results
        except Exception as e:
            await browser.close()
            return False, "This website refused to load, which is common for 'broken' or fake links."

# 4. SIMPLE STREAMLIT UI
st.set_page_config(page_title="EasySafe Scanner", page_icon="🛡️")
