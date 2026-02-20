import streamlit as st
import asyncio
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
            return response.json()['data']['attributes']['last_analysis_stats'].get('malicious', 0)
        return 0
    except:
        return 0

# --- THE SANDBOX ENGINE ---
async def analyze_link(url):
    results = {"score": 100, "flags": [], "title": "Unknown", "final_url": url}
    
    # Simple logic check
    suspicious_words = ['login', 'bank', 'verify', 'secure', 'update']
    if any(word in url.lower() for word in suspicious_words):
        results["score"] -= 20
        results["flags"].append("⚠️ **Suspicious Name:** Uses words meant to trick you.")

    if not url.startswith("https://"):
        results["score"] -= 30
        results["flags"].append("🔒 **Insecure:** No encryption found on this link.")

    vt_threats = get_vt_report(url)
    if vt_threats and vt_threats > 0:
        results["score"] -= (vt_threats * 10)
        results["flags"].append(f"🚨 **Threat Alert:** {vt_threats} security engines flagged this site.")

    # Launching the Sandbox
    async with async_playwright() as p:
        try:
            # Added flags to bypass Streamlit's environment restrictions
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

# --- INTERFACE ---
st.set_page_config(page_title="SafeLink Scanner", page_icon="🛡️")
st.title("🛡️ Is This Link Safe?")
st.write("Enter a link to test it safely in our isolated cloud sandbox.")

target_url = st.text_input("Paste link here:", "https://")

if st.button("Analyze Link"):
    with st.spinner("Opening secure sandbox..."):
        success, data = asyncio.run(analyze_link(target_url))
        if success:
            score = max(0, data["score"])
            if score >= 80: st.success(f"### Score: {score}% — Safe ✅")
            elif score >= 50: st.warning(f"### Score: {score}% — Caution ⚠️")
            else: st.error(f"### Score: {score}% — DANGER 🛑")
            
            for flag in data["flags"]: st.info(flag)
            st.image("evidence.png", caption="Live Sandbox View")
        else:
            st.error(data)
