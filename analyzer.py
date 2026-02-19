import streamlit as st
import asyncio
import os
import base64
import requests
from playwright.async_api import async_playwright

# 1. BROWSER SETUP: Install Chromium for the Cloud environment
if not os.path.exists("/home/appuser/.cache/ms-playwright"):
    os.system("playwright install chromium")

# 2. VIRUSTOTAL CHECK: Queries the global threat database
def get_vt_report(url):
    try:
        if "VT_API_KEY" not in st.secrets:
            return None # Skip if key isn't set yet
        
        api_key = st.secrets["VT_API_KEY"]
        # VT requires URLs to be base64 encoded
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

# 3. CORE ANALYSIS: The Sandbox Engine
async def analyze_link(url):
    results = {"score": 100, "flags": [], "title": "Unknown", "final_url": url}
    
    # Static Analysis
    suspicious_keywords = ['login', 'verify', 'bank', 'secure', 'update', 'account', 'signin', 'wp-admin']
    if any(word in url.lower() for word in suspicious_keywords):
        results["score"] -= 20
        results["flags"].append("Found suspicious keywords in URL (Phishing Risk)")

    if not url.startswith("https://"):
        results["score"] -= 30
        results["flags"].append("No HTTPS encryption detected")

    # VirusTotal Integration
    vt_malicious = get_vt_report(url)
    if vt_malicious and vt_malicious > 0:
        results["score"] -= (vt_malicious * 10)
        results["flags"].append(f"Flagged as malicious by {vt_malicious} security vendors on VirusTotal")

    # Dynamic Analysis (The Sandbox)
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()
        
        try:
            await page.goto(url, timeout=30000)
            results["title"] = await page.title()
            results["final_url"] = page.url
            
            # Check for silent redirects
            if results["final_url"].rstrip('/') != url.rstrip('/'):
                results["score"] -= 15
                results["flags"].append(f"Redirected to a different page: {results['final_url']}")

            await page.screenshot(path="evidence.png")
            await browser.close()
            return True, results
        except Exception as e:
            await browser.close()
            return False, str(e)

# 4. STREAMLIT INTERFACE
st.set_page_config(page_title="SafeScan Sandbox", page_icon="🛡️")
st.title("🛡️ URL Sandbox & Phishing Analyzer")
st.write("Enter a link to analyze it safely in a remote, isolated browser.")

target_url = st.text_input("URL to scan:", "https://")

if st.button("Run Security Scan"):
    if not target_url.startswith("http"):
        st.error("Please enter a valid URL starting with http:// or https://")
    else:
        with st.spinner("Analyzing... (Opening sandbox, checking databases, taking screenshot)"):
            success, data = asyncio.run(analyze_link(target_url))
            
            if success:
                # Score Logic
                score = max(0, data["score"]) # Don't go below 0
                
                if score >= 80:
                    st.success(f"Safety Score: {score}% - Likely Safe")
                elif score >= 50:
                    st.warning(f"Safety Score: {score}% - Caution Advised")
                else:
                    st.error(f"Safety Score: {score}% - HIGH RISK")
                
                st.metric("Risk Level", f"{score}%")

                col1, col2 = st.columns(2)
                with col1:
                    st.subheader("Red Flags")
                    if data["flags"]:
                        for flag in data["flags"]:
                            st.write(f"🚩 {flag}")
                    else:
                        st.write("✅ No immediate red flags found.")
                
                with col2:
                    st.subheader("Site Info")
                    st.write(f"**Title:** {data['title']}")
                    st.write(f"**Final URL:** {data['final_url']}")

                st.divider()
                st.subheader("Visual Screenshot (Sandbox)")
                st.image("evidence.png", caption="This is what our server saw so you don't have to.")
            else:
                st.error(f"Scan failed: {data}")

# Sidebar Info
st.sidebar.info("This app uses a headless browser to visit sites safely. Your computer is never at risk.")
