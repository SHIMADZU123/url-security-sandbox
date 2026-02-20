import streamlit as st
import asyncio
import base64
import requests
from playwright.async_api import async_playwright

# --- 1. VIRUSTOTAL SECURITY CHECK ---
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
            stats = response.json()['data']['attributes']['last_analysis_stats']
            return stats.get('malicious', 0)
        return 0
    except:
        return 0

# --- 2. THE SANDBOX ENGINE ---
async def analyze_link(url):
    results = {"score": 100, "flags": [], "title": "Unknown", "final_url": url}
    
    # Simple Logic for Humans
    suspicious_words = ['login', 'bank', 'verify', 'secure', 'update', 'account']
    if any(word in url.lower() for word in suspicious_words):
        results["score"] -= 20
        results["flags"].append("⚠️ **Suspicious Name:** The link uses words meant to trick you into giving away info.")

    if not url.startswith("https://"):
        results["score"] -= 30
        results["flags"].append("🔒 **No Privacy:** This site does not have a security padlock. Your data is not safe.")

    vt_threats = get_vt_report(url)
    if vt_threats and vt_threats > 0:
        results["score"] -= (vt_threats * 10)
        results["flags"].append(f"🚨 **Known Danger:** {vt_threats} security systems have officially marked this link as DANGEROUS.")

    # Launching the Browser
    async with async_playwright() as p:
        try:
            # We assume Chromium is pre-installed via packages.txt
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            await page.goto(url, timeout=30000)
            results["title"] = await page.title()
            results["final_url"] = page.url
            await page.screenshot(path="evidence.png")
            await browser.close()
            return True, results
        except Exception as e:
            return False, f"Browser Error: {str(e)}. (Ensure packages.txt is correct)"

# --- 3. THE USER INTERFACE ---
st.set_page_config(page_title="SafeLink AI Scanner", page_icon="🛡️")
st.title("🛡️ Is This Link Safe?")
st.write("Enter any link to test it safely in our isolated sandbox.")

target = st.text_input("Paste link here:", "https://")

if st.button("Start Security Analysis"):
    if not target.startswith("http"):
        st.error("Please enter a full link starting with http:// or https://")
    else:
        with st.spinner("Opening secure sandbox..."):
            success, report = asyncio.run(analyze_link(target))
            
            if success:
                score = max(0, report["score"])
                if score >= 80:
                    st.success(f"### Safety Score: {score}% — Likely Safe ✅")
                elif score >= 50:
                    st.warning(f"### Safety Score: {score}% — Be Careful! ⚠️")
                else:
                    st.error(f"### Safety Score: {score}% — HIGH RISK 🛑")

                st.subheader("What we found:")
                if report["flags"]:
                    for flag in report["flags"]:
                        st.info(flag)
                else:
                    st.write("✅ No obvious tricks found.")

                st.divider()
                st.subheader("Visual Proof (Screenshot)")
                st.image("evidence.png", caption="What the site looks like inside the sandbox.")
            else:
                st.error(report)
