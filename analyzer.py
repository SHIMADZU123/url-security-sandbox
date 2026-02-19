import os
import streamlit as st
import asyncio

# This command installs the browser into the Streamlit server
if not os.path.exists("/home/appuser/.cache/ms-playwright"):
    os.system("playwright install chromium")

from playwright.async_api import async_playwright
# ... the rest of your code ...
import os
os.system("playwright install chromium")
import streamlit as st
import asyncio
from playwright.async_api import async_playwright

async def scan_url(url):
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        score = 100
        warnings = []
        
        try:
            # Check 1: No HTTPS (Big Risk)
            if not url.startswith("https://"):
                score -= 40
                warnings.append("No encryption (HTTP detected).")

            response = await page.goto(url, timeout=30000)
            
            # Check 2: Suspicious Redirects
            if page.url != url:
                score -= 20
                warnings.append(f"Redirected to: {page.url}")

            # Check 3: Unusual URL Length (Common in Phishing)
            if len(url) > 100:
                score -= 15
                warnings.append("URL is unusually long.")

            await page.screenshot(path="evidence.png")
            title = await page.title()
            await browser.close()
            return True, score, warnings, title
        except Exception as e:
            await browser.close()
            return False, 0, [str(e)], "Error"

# STREAMLIT UI
st.set_page_config(page_title="Security Scanner", page_icon="🛡️")
st.title("🛡️ Link Safety Inspector")

user_url = st.text_input("Enter link to test:", "https://")

if st.button("Calculate Safety Score"):
    with st.spinner("Analyzing..."):
        success, final_score, issues, title = asyncio.run(scan_url(user_url))
        
        if success:
            # Color-coded result
            if final_score >= 80:
                st.balloons()
                st.success(f"Safety Score: {final_score}% - Likely Safe")
            elif final_score >= 50:
                st.warning(f"Safety Score: {final_score}% - Use Caution")
            else:
                st.error(f"Safety Score: {final_score}% - HIGH RISK")
            
            st.metric("Final Verdict", f"{final_score}%")
            
            if issues:
                st.subheader("Red Flags Found:")
                for issue in issues:
                    st.write(f"🚩 {issue}")
            
            st.image("evidence.png", caption=f"Screenshot of {title}")
        else:
            st.error(f"Could not scan: {issues[0]}")
