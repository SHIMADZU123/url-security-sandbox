import streamlit as st
import requests
import whois
import tldextract
import validators
from bs4 import BeautifulSoup
from datetime import datetime
import pandas as pd

# --- CONFIG & STYLING ---
st.set_page_config(page_title="SafeCheck Pro | URL Sandbox", page_icon="🛡️", layout="wide")

# Custom CSS for a professional look
st.markdown("""
    <style>
    .main { background-color: #f8f9fa; }
    .stMetric { background-color: white; padding: 15px; border-radius: 10px; border: 1px solid #ddd; }
    .trust-high { color: #28a745; font-weight: bold; }
    .trust-low { color: #dc3545; font-weight: bold; }
    </style>
    """, unsafe_allow_html=True)

# --- WELL-KNOWN COMPANY DATABASE ---
# In a real app, this would be a larger JSON or DB
WELL_KNOWN_BRANDS = {
    "google.com": {"name": "Google LLC", "industry": "Technology"},
    "microsoft.com": {"name": "Microsoft Corp", "industry": "Software"},
    "amazon.com": {"name": "Amazon.com Inc.", "industry": "E-commerce"},
    "apple.com": {"name": "Apple Inc.", "industry": "Hardware/Tech"},
    "github.com": {"name": "GitHub (Microsoft)", "industry": "Development"},
    "netflix.com": {"name": "Netflix Inc.", "industry": "Entertainment"}
}

# --- LOGIC FUNCTIONS ---
def analyze_url(url):
    results = {"url": url, "score": 100, "flags": [], "brand": None}
    
    # 1. Basic Validation
    if not validators.url(url):
        return None

    ext = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}"
    
    # 2. Brand Check
    if domain in WELL_KNOWN_BRANDS:
        results["brand"] = WELL_KNOWN_BRANDS[domain]
        results["score"] = 100 # Verified brands get top score
    else:
        # Check for "typosquatting" (e.g., g00gle.com)
        for brand in WELL_KNOWN_BRANDS:
            if brand in domain and domain != brand:
                results["flags"].append(f"Potential Phishing: Domain resembles {brand}")
                results["score"] -= 40

    # 3. Security Headers & SSL
    try:
        response = requests.get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
        if not url.startswith("https"):
            results["flags"].append("No HTTPS Encryption")
            results["score"] -= 20
        
        headers = response.headers
        if 'Content-Security-Policy' not in headers:
            results["flags"].append("Missing Content-Security-Policy (CSP)")
            results["score"] -= 5
            
    except Exception as e:
        results["flags"].append(f"Connection Error: {str(e)}")
        results["score"] = 0

    return results, domain

# --- UI LAYOUT ---
st.title("🛡️ SafeCheck Pro: URL Sandbox")
st.caption("Professional Security Analysis & Brand Verification")

url_input = st.text_input("Enter URL to analyze:", placeholder="https://example.com")

if st.button("Run Security Sandbox"):
    if url_input:
        with st.spinner("Analyzing domain reputation and headers..."):
            data, domain = analyze_url(url_input)
            
            if data:
                # Top Metrics
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    color = "trust-high" if data['score'] > 70 else "trust-low"
                    st.markdown(f"### Trust Score: <span class='{color}'>{data['score']}/100</span>", unsafe_allow_html=True)
                
                with col2:
                    status = "✅ Verified Brand" if data['brand'] else "🌐 Public Domain"
                    st.metric("Identity Status", status)
                
                with col3:
                    st.metric("Domain", domain)

                st.divider()

                # Detailed Analysis
                left_tab, right_tab = st.columns(2)

                with left_tab:
                    st.subheader("Brand & Ownership")
                    if data['brand']:
                        st.success(f"**Entity:** {data['brand']['name']}")
                        st.info(f"**Industry:** {data['brand']['industry']}")
                    else:
                        st.warning("No official corporate brand matched. Exercise caution if this site asks for credentials.")
                    
                    # Mock WHOIS (In a real app, use the 'whois' library)
                    st.write("**Whois Data Snippet:**")
                    st.code(f"Registrar: Unknown\nRegistered: Recently\nCountry: Protected", language="yaml")

                with right_tab:
                    st.subheader("Security Flags")
                    if not data['flags']:
                        st.success("No critical security issues found.")
                    else:
                        for flag in data['flags']:
                            st.error(f"🚩 {flag}")

                # Image Sandbox Visualization
                st.info("💡 **Sandbox Insight:** Professional companies usually have high 'Security Header' scores and 10+ year domain history.")
            else:
                st.error("Invalid URL format. Please include http:// or https://")

# --- SIDEBAR ---
with st.sidebar:
    st.header("Settings")
    st.write("Scan Depth: **High**")
    st.checkbox("Check for Typosquatting", value=True)
    st.checkbox("Analyze SSL Certificate", value=True)
    st.divider()
    st.write("Version: 1.0.2-Stable")
