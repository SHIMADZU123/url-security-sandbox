import streamlit as st
import asyncio
import requests
import whois
import plotly.graph_objects as go
from datetime import datetime
import os

# Install browser binaries if missing
if not os.path.exists("/home/appuser/.cache/ms-playwright"):
    os.system("playwright install chromium")

from playwright.async_api import async_playwright

# Intelligence: Resolve hidden links
def unshorten_url(url):
    try:
        response = requests.head(url, allow_redirects=True, timeout=5)
        return response.url
    except:
        return url

# Intelligence: Check how old the domain is
def get_domain_age(url):
    try:
        domain_info = whois.whois(url)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        days_old = (datetime.now() - creation_date).days
        return days_old
    except:
        return None

# Analysis: Safe inspection (No direct rendering)
async def analyze_link(url):
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        try:
            res = await page.goto(url, timeout=20000)
            title = await page.title()
            status = res.status
            await browser.close()
            return True, status, title
        except Exception as e:
            await browser.close()
            return False, str(e), ""

# --- DASHBOARD UI ---
st.set_page_config(page_title="Pro URL Sandbox", layout="wide")
st.title("🛡️ Cyber-Sentinel URL Intelligence")

user_input = st.text_input("Paste Link to Inspect:", "https://")

if st.button("Analyze Link Now"):
    with st.spinner("Running Multi-Layer Intelligence Check..."):
        final_url = unshorten_url(user_input)
        age = get_domain_age(final_url)
        success, status, title = asyncio.run(analyze_link(final_url))
        
        # Scoring Logic
        score = 100
        flags = []
        if age and age < 60:
            score -= 40
            flags.append(f"Domain is very new ({age} days old).")
        if not final_url.startswith("https"):
            score -= 30
            flags.append("Insecure connection (No HTTPS).")
        
        # UI: Safety Gauge
        fig = go.Figure(go.Indicator(
            mode = "gauge+number",
            value = score,
            gauge = {'axis': {'range': [0, 100]},
                     'bar': {'color': "black"},
                     'steps': [
                         {'range': [0, 50], 'color': "red"},
                         {'range': [50, 80], 'color': "yellow"},
                         {'range': [80, 100], 'color': "green"}]}
        ))
        st.plotly_chart(fig)

        # UI: Metrics and Expanders
        st.subheader("Intelligence Report")
        with st.expander("Show Technical Details"):
            st.write(f"**Final Destination:** {final_url}")
            st.write(f"**Page Title:** {title}")
            st.metric("HTTP Status", status)
            for flag in flags:
                st.error(f"🚩 {flag}")
