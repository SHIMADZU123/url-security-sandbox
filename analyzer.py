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
            await page.goto(url, timeout=30000)
            results["title"] = await page.title()
            results["final_url"] = page.url
            
            # Check for hidden redirects
            if results["final_url"].rstrip('/') != url.rstrip('/'):
                results["score"] -= 15
                results["flags"].append("🔀 **Secret Redirection:** This link tried to secretly take you to a different website.")

            await page.screenshot(path="evidence.png")
            await browser.close()
            return True, results
        except Exception as e:
            await browser.close()
            return False, "This website failed to open. Fake links often break or disappear quickly."

# 3. USER INTERFACE (UI)
st.set_page_config(page_title="SafeLink Scanner", page_icon="🛡️")

st.title("🛡️ Is This Link Safe?")
st.write("Paste a link below to see if it's a trick. We will open it safely for you.")

target_url = st.text_input("Paste the link here:", "https://")

if st.button("Check Safety Now"):
    if not target_url.startswith("http"):
        st.error("Please enter a full link (it must start with http:// or https://)")
    else:
        with st.spinner("Analyzing... Checking databases and opening the site safely..."):
            success, data = asyncio.run(analyze_link(target_url))
            
            if success:
                score = max(0, data["score"])
                
                # Big Safety Result
                if score >= 80:
                    st.success(f"### Safety Score: {score}% — Looks Safe ✅")
                elif score >= 50:
                    st.warning(f"### Safety Score: {score}% — Be Careful! ⚠️")
                else:
                    st.error(f"### Safety Score: {score}% — DANGER! 🛑")
                
                # Understandable Findings
                st.subheader("What we found:")
                if data["flags"]:
                    for
