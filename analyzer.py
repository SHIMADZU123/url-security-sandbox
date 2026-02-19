import streamlit as st
import requests

def check_virustotal(url):
    # This pulls the key directly from the Secrets you just saved!
    api_key = st.secrets["VT_API_KEY"]
    
    vt_url = f"https://www.virustotal.com/api/v3/urls"
    # ... code to send the URL to VirusTotal ...
import streamlit as st
import asyncio
import os
import re
from playwright.async_api import async_playwright

# Install Chromium in the cloud environment
if not os.path.exists("/home/appuser/.cache/ms-playwright"):
    os.system("playwright install chromium")

async def analyze_url(url):
    results = {"score": 100, "flags": [], "title": "Unknown", "final_url": url}
    
    # --- STATIC ANALYSIS: The URL itself ---
    # 1. Phishing Keywords
    bad_words = ['login', 'verify', 'bank', 'secure', 'update', 'account', 'signin']
    if any(word in url.lower() for word in bad_words):
        results["score"] -= 25
        results["flags"].append("Contains suspicious keywords (Phishing risk)")

    # 2. Encryption check
    if not url.startswith("https://"):
        results["score"] -= 30
        results["flags"].append("No HTTPS encryption (Data is unsafe)")

    # 3. URL length
    if len(url) > 80:
        results["score"] -= 15
        results["flags"].append("Unusually long URL (Often used to hide bad links)")

    # --- DYNAMIC ANALYSIS: The Behavior ---
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        try:
            response = await page.goto(url, timeout=30000)
            results["title"] = await page.title()
            results["final_url"] = page.url
            
            # Check for silent redirects
            if results["final_url"].rstrip('/') != url.rstrip('/'):
                results["score"] -= 20
                results["flags"].append(f"Silent Redirect detected to: {results['final_url']}")

            await page.screenshot(path="evidence.png")
            await browser.close()
            return True, results
        except Exception as e:
            await browser.close()
            return False, f"Could not load site: {str(e)}"

# --- STREAMLIT UI ---
st.set_page_config(page_title="SafeLink AI Scanner", page_icon="🛡️")
st.title("🛡️ URL Phishing & Sandbox Analyzer")
st.markdown("This tool opens links in a **hidden isolated box** to protect you.")

target = st.text_input("Paste the link you want to check:", "https://")

if st.button("Start Security Analysis"):
    with st.spinner("Analyzing threat levels..."):
        success, report = asyncio.run(analyze_url(target))
        
        if success:
            score = report["score"]
            # Visual Score Gauge
            if score >= 80:
                st.success(f"Safety Score: {score}% - LIKELY SAFE")
            elif score >= 50:
                st.warning(f"Safety Score: {score}% - USE CAUTION")
            else:
                st.error(f"Safety Score: {score}% - HIGH RISK DETECTED")

            # Findings
            col1, col2 = st.columns(2)
            with col1:
                st.subheader("Analysis Findings")
                for flag in report["flags"]:
                    st.write(f"🚩 {flag}")
                if not report["flags"]:
                    st.write("✅ No obvious red flags found.")
            
            with col2:
                st.subheader("Site Identity")
                st.write(f"**Page Title:** {report['title']}")
                st.write(f"**Final Destination:** `{report['final_url']}`")

            st.divider()
            st.subheader("Visual Evidence (Sandbox Screenshot)")
            st.image("evidence.png", caption="What the site looks like behind the scenes")
        else:
            st.error(report)
