import streamlit as st
import asyncio
import os
import base64
import requests
from playwright.async_api import async_playwright

# 1. VIRUSTOTAL CHECK: Queries global threat databases
def get_vt_report(url):
    try:
        # Pull key from Streamlit "Secrets" settings
        if "VT_API_KEY" not in st.secrets:
            return None
        
        api_key = st.secrets["VT_API_KEY"]
        # VirusTotal requires the URL to be base64 encoded
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        
        headers = {"x-apikey": api_key}
        response = requests.get(vt_url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            return data['data']['attributes']['last_analysis_stats']['malicious']
        return 0
    except Exception:
        return 0

# 2. CORE ANALYSIS ENGINE (The Sandbox)
async def analyze_link(url):
    results = {"score": 100, "flags": [], "title": "Unknown", "final_url": url}
    
    # --- Simple Warnings for Everyone ---
    suspicious_keywords = ['login', 'verify', 'bank', 'secure', 'update', 'account', 'signin', 'wp-admin']
    if any(word in url.lower() for word in suspicious_keywords):
        results["score"] -= 20
        results["flags"].append("⚠️ **Suspicious Name:** This link uses words like 'login' or 'bank' to try and trick you.")

    if not url.startswith("https://"):
        results["score"] -= 30
        results["flags"].append("🔒 **No Security Lock:** This site is not private. Anything you type can be seen by hackers.")

    # --- VirusTotal Check ---
    vt_malicious = get_vt_report(url)
    if vt_malicious and vt_malicious > 0:
        results["score"] -= (vt_malicious * 10)
        results["flags"].append(f"🚨 **Known Danger:** {vt_malicious} security companies have already reported this as a bad link.")

    # --- Hidden Sandbox Browser ---
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()
        
        try:
            await page.goto(url, timeout=300
