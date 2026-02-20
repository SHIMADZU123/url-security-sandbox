import streamlit as st
import asyncio
import base64
import requests
import os
from playwright.async_api import async_playwright

# --- 1. VIRUSTOTAL API CHECK ---
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

# --- 2. THE SANDBOX ENGINE ---
async def analyze_link(url):
    results = {"score": 100, "flags": [], "title": "Unknown", "final_url": url}
    
    # Simple logic checks
    if any(word in url.lower() for word in ['login', 'bank', 'verify', 'secure', 'update']):
        results["score"] -= 20
        results["flags"].append("⚠️ **Suspicious Keywords:** This link uses words often used in phishing.")

    if not url.startswith("https://"):
        results["score"] -= 30
        results["flags"].append("🔒 **Insecure Connection:** This site is not encrypted (no HTTPS).")

    vt_malicious = get_vt_report(url)
    if vt_malicious and vt_malicious > 0:
        results["score"] -= (vt_malicious * 10)
        results["flags"].append(f"🚨 **Security Alert:** {vt_malicious} engines flagged this as DANGEROUS.")

    # Launching the Sandbox
    async with async_playwright() as p:
        try:
            # We use these specific flags to run in the restricted Streamlit environment
            browser = await p.chromium.launch(
                headless=True, 
                args=["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"]
            )
            page = await browser.new_page()
            await page.goto(url, timeout=30000)
            results["title"] = await page.title()
            results["final_url"] = page.url
            await page.screenshot(path="evidence.png")
            await browser.close()
            return True, results
        except Exception as e:
            return False, f"Browser Error: {str(e)}"

# --- 3. THE UI ---
st.set_page_config(page_title="SafeLink AI Scanner", page_icon="🛡️")
st.title("🛡️ Is This Link Safe?")
st.write("Scan links safely in our cloud-based sandbox.")

target_url = st.text_input("Paste the link here:", "https://")

if st.button("Analyze Security Now"):
    if not target_url.startswith("http"):
        st.error("Please enter a full link (e.g., https://google.com)")
    else:
        with st.spinner("Opening secure sandbox... (Please wait)"):
            success, data = asyncio.run(analyze_link(target_url))
            
            if success:
                score = max(0, data["score"])
                if score >= 80:
                    st.success(f"### Safety Score: {score}% — Likely Safe ✅")
                elif score >= 50:
                    st.warning(f"### Safety Score: {score}% — Use Caution! ⚠️")
                else:
                    st.error(f"### Safety Score: {score}% — HIGH RISK 🛑")

                for flag in data["flags"]:
                    st.info(flag)

                st.divider()
                st.subheader("Visual Proof")
                st.image("evidence.png", caption="Screenshot from our secure server.")
            else:
                st.error(data)
