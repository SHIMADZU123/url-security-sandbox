import streamlit as st
import asyncio
import requests
import whois
import plotly.graph_objects as go
from datetime import datetime
from playwright.async_api import async_playwright

# 1. URL Unshortener Logic
def unshorten_url(url):
    try:
        response = requests.head(url, allow_redirects=True, timeout=5)
        return response.url
    except:
        return url

# 2. Domain Age Check (WHOIS)
def get_domain_age(url):
    try:
        domain = whois.whois(url)
        creation_date = domain.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        days_old = (datetime.now() - creation_date).days
        return days_old
    except:
        return None

# 3. Sandbox Analysis (No Rendering)
async def analyze_link(url):
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        try:
            res = await page.goto(url, timeout=20000)
            status = res.status
            title = await page.title()
            await browser.close()
            return True, status, title
        except Exception as e:
            await browser.close()
            return False, str(e), ""

# --- STREAMLIT UI ---
st.set_page_config(page_title="Pro Security Sandbox", layout="wide")
st.title("🛡️ Cyber-Sentinel URL Analyzer")

input_url = st.text_input("Enter URL to Scan:", "https://")

if st.button("Start Deep Scan"):
    with st.spinner("Performing intelligence checks..."):
        # Step 1: Unshorten
        final_url = unshorten_url(input_url)
        
        # Step 2: WHOIS
        age = get_domain_age(final_url)
        
        # Step 3: Sandbox
        success, status, title = asyncio.run(analyze_link(final_url))
        
        # CALCULATE SCORE
        score = 100
        alerts = []
        
        if age and age < 30:
            score -= 40
            alerts.append(f"Domain is brand new ({age} days old)!")
        if not final_url.startswith("https"):
            score -= 30
            alerts.append("Insecure Connection (No HTTPS)")
        if input_url != final_url:
            alerts.append(f"Redirected from shortened link to: {final_url}")

        # --- GAUGE CHART ---
        fig = go.Figure(go.Indicator(
            mode = "gauge+number",
            value = score,
            title = {'text': "Safety Score"},
            gauge = {
                'axis': {'range': [0, 100]},
                'bar': {'color': "black"},
                'steps': [
                    {'range': [0, 50], 'color': "red"},
                    {'range': [50, 80], 'color': "yellow"},
                    {'range': [80, 100], 'color': "green"}]
            }
        ))
        st.plotly_chart(fig)

        # FINAL VERDICT
        if score >= 80: st.success("VERDICT: LIKELY SAFE")
        elif score >= 50: st.warning("VERDICT: SUSPICIOUS")
        else: st.error("VERDICT: DANGEROUS")

        # COLLAPSIBLE DETAILS
        with st.expander("See Technical Intelligence Data"):
            col1, col2 = st.columns(2)
            col1.metric("HTTP Status", status)
            col1.metric("Domain Age (Days)", age if age else "Unknown")
            col2.write(f"**Final URL:** {final_url}")
            col2.write(f"**Page Title:** {title}")
            for a in alerts:
                st.write(f"🚩 {a}")
