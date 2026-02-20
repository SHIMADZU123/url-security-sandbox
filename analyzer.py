import streamlit as st
import requests
import whois
import ssl
import socket
import urllib.parse
from datetime import datetime
import re
import plotly.graph_objects as go

# --- PAGE CONFIG ---
st.set_page_config(page_title="AI Threat Intelligence", page_icon="🛡️", layout="wide")

# --- ADVANCED CUSTOM STYLING ---
st.markdown("""
    <style>
    .stApp {
        background: linear-gradient(135deg, #050b18 0%, #0c152a 100%);
        color: #e0e0e0;
    }
    .header-container {
        background: rgba(255, 255, 255, 0.05);
        backdrop-filter: blur(10px);
        padding: 1.5rem;
        border-radius: 20px;
        border: 1px solid rgba(255, 255, 255, 0.1);
        margin-bottom: 2rem;
    }
    .footer {
        position: fixed; left: 0; bottom: 0; width: 100%;
        background-color: rgba(10, 20, 40, 0.95); color: #8892b0;
        text-align: center; padding: 12px; font-size: 13px;
        border-top: 1px solid #1a2a4a; z-index: 100;
    }
    .stTextInput>div>div>input {
        background-color: #0d1930 !important;
        color: #00d4ff !important;
        border: 1px solid #1a2a4a !important;
        border-radius: 10px !important;
    }
    </style>
    """, unsafe_allow_html=True)

# --- HEADER WITH LOGOS ---
with st.container():
    st.markdown('<div class="header-container">', unsafe_allow_html=True)
    col1, col2, col3 = st.columns([1, 3, 1])
    
    with col1:
        try:
            st.image("NTU logo.jpg", width=120)
        except:
            st.markdown("🏛️ **NTU**")
            
    with col2:
        st.markdown("<h1 style='text-align: center; color: #ffffff; margin-bottom: 5px;'>Welcome to the AI Threat Intelligence</h1>", unsafe_allow_html=True)
        st.markdown("<h4 style='text-align: center; color: #00d4ff; margin-top: 0;'>Northern Technical University</h4>", unsafe_allow_html=True)
        st.markdown("<p style='text-align: center; color: #8892b0;'>AI & Computer Engineering College | Advanced Phishing Detection System</p>", unsafe_allow_html=True)
        
    with col3:
        try:
            st.image("collegue logo.jpg", width=120)
        except:
            st.markdown("<div style='text-align: right;'>💻 **AI & CE**</div>", unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)

# --- LOGIC ENGINE ---
def analyze_url_deep(url):
    score = 100
    details = []
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc
    
    # Check A: IP Address Usage
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
        score -= 45
        details.append(("Critical", "Direct IP Usage", "URL uses raw IP instead of a registered domain name."))
    
    # Check B: Phishing Symbols
    if "@" in url:
        score -= 35
        details.append(("High", "Credential Spoofing", "Symbol '@' detected, used to mislead browsers."))
        
    # Check C: Subdomain Depth
    if domain.count('.') > 3:
        score -= 20
        details.append(("Medium", "Excessive Subdomains", "Unusually deep subdomains are typical in phishing URLs."))

    # Check D: SSL Protocol
    if not url.startswith("https"):
        score -= 30
        details.append(("High", "Insecure Connection", "Site uses HTTP. Data is not encrypted."))

    return max(0, score), details

# --- MAIN DASHBOARD ---
st.markdown("### 🔍 Security Analysis Console")
target_url = st.text_input("ENTER URL FOR INVESTIGATION:", placeholder="https://example-secure-site.com")

if st.button("🚀 RUN SYSTEM SCAN"):
    if target_url:
        with st.spinner("Neural networks analyzing threat vectors..."):
            score, findings = analyze_url_deep(target_url)
            
            st.divider()
            left_col, right_col = st.columns([1, 1.5])
            
            with left_col:
                # PRO DYNAMIC GAUGE
                color = "#00ff9d" if score > 75 else "#ffcc00" if score > 45 else "#ff4b4b"
                fig = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=score,
                    number={'suffix': "%", 'font': {'color': color, 'size': 55}},
                    gauge={
                        'axis': {'range': [0, 100], 'tickcolor': "#8892b0"},
                        'bar': {'color': color},
                        'bgcolor': "#101d33",
                        'steps': [
                            {'range': [0, 45], 'color': "rgba(255, 75, 75, 0.15)"},
                            {'range': [45, 75], 'color': "rgba(255, 204, 0, 0.15)"},
                            {'range': [75, 100], 'color': "rgba(0, 255, 157, 0.15)"}
                        ],
                        'threshold': {'line': {'color': "white", 'width': 4}, 'value': score}
                    }
                ))
                fig.update_layout(height=350, paper_bgcolor='rgba(0,0,0,0)', font={'color': "white"})
                st.plotly_chart(fig, use_container_width=True)

            with right_col:
                st.markdown("### 📊 Forensic Intelligence Report")
                if score > 75:
                    st.success(f"**TRUST LEVEL: HIGH ({score}%)** - Link appears legitimate.")
                elif score > 45:
                    st.warning(f"**TRUST LEVEL: MODERATE ({score}%)** - Caution: Structural anomalies detected.")
                else:
                    st.error(f"**TRUST LEVEL: CRITICAL ({score}%)** - HIGH RISK OF PHISHING DETECTED.")

                for severity, title, desc in findings:
                    with st.expander(f"📌 {severity}: {title}"):
                        st.write(desc)
    else:
        st.error("Please provide a URL to analyze.")

# --- FOOTER ---
st.markdown(f"""
    <div class="footer">
        <b>TECHNICAL SUPPORT:</b> Northern Technical University | <b>Telegram: @shim_azu64</b> | v3.0-Stable
    </div>
    """, unsafe_allow_html=True)
