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

# --- ADVANCED CUSTOM STYLING (The "Pro" Look) ---
st.markdown("""
    <style>
    /* Main background */
    .stApp {
        background: linear-gradient(135deg, #050b18 0%, #0c152a 100%);
        color: #e0e0e0;
    }
    /* Top Header Bar */
    .header-bar {
        background: rgba(255, 255, 255, 0.05);
        backdrop-filter: blur(10px);
        padding: 2rem;
        border-radius: 15px;
        border: 1px solid rgba(255, 255, 255, 0.1);
        text-align: center;
        margin-bottom: 2rem;
    }
    /* Metric Cards */
    .metric-card {
        background: rgba(13, 25, 48, 0.6);
        padding: 20px;
        border-radius: 12px;
        border-left: 5px solid #00d4ff;
        margin-bottom: 10px;
    }
    /* Footer */
    .footer {
        position: fixed; left: 0; bottom: 0; width: 100%;
        background-color: rgba(10, 20, 40, 0.9); color: #8892b0;
        text-align: center; padding: 10px; font-size: 13px;
        border-top: 1px solid #1a2a4a; z-index: 100;
    }
    /* Input Box */
    .stTextInput>div>div>input {
        background-color: #0d1930 !important;
        color: #00d4ff !important;
        border: 1px solid #1a2a4a !important;
    }
    </style>
    """, unsafe_allow_html=True)

# --- PROFESSIONAL HEADER SECTION ---
st.markdown("""
    <div class="header-bar">
        <h1 style='color: #ffffff; margin-bottom: 5px; font-family: "Segoe UI", sans-serif;'>Welcome to the AI Threat Intelligence</h1>
        <h3 style='color: #00d4ff; font-weight: 400; margin-top: 0;'>Powered by Northern Technical University</h3>
        <p style='color: #8892b0;'>AI & Computer Engineering College | Advanced Security Framework v2.1</p>
    </div>
    """, unsafe_allow_html=True)

# --- ANALYSIS ENGINE ---
def analyze_url_deep(url):
    score = 100
    details = []
    
    # 1. Parsing & Normalization
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc
    
    # Check A: Known Phishing Patterns (Heuristics)
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
        score -= 45
        details.append(("Critical", "Direct IP Usage", "The URL uses a raw IP address, bypassing DNS reputation checks."))
    
    if "@" in url:
        score -= 35
        details.append(("High", "Credential Obfuscation", "Presence of '@' symbol indicates a high risk of user-redirection trickery."))
        
    if domain.count('.') > 3:
        score -= 20
        details.append(("Medium", "Excessive Subdomains", "Unusual subdomain depth is common in generated phishing links."))

    # Check B: Security Protocol (SSL)
    if not url.startswith("https"):
        score -= 30
        details.append(("High", "Missing Encryption", "Site uses HTTP. Data entered is visible to attackers (Cleartext)."))
    
    # Check C: Brand Mimicry & Urgency
    danger_keywords = ['login', 'verify', 'update', 'secure', 'bank', 'account', 'signin', 'support']
    if any(k in url.lower() for k in danger_keywords):
        score -= 10
        details.append(("Low", "Semantic Urgency", "URL contains keywords commonly used in social engineering."))

    return max(0, score), details

# --- MAIN DASHBOARD LAYOUT ---
col_input, col_empty = st.columns([2, 1])
with col_input:
    target_url = st.text_input("🛡️ ENTER SECURITY TARGET (URL):", placeholder="e.g., https://secure-login-ntu.com")

if st.button("🚀 EXECUTE THREAT ANALYSIS"):
    if target_url:
        with st.spinner("Initializing neural scan..."):
            score, findings = analyze_url_deep(target_url)
            
            # --- RESULTS GRID ---
            st.write("---")
            left_col, right_col = st.columns([1.2, 2])
            
            with left_col:
                # DYNAMIC PRO GAUGE
                color = "#00ff9d" if score > 75 else "#ffcc00" if score > 45 else "#ff4b4b"
                fig = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=score,
                    number={'suffix': "%", 'font': {'color': color, 'size': 60}},
                    gauge={
                        'axis': {'range': [0, 100], 'tickcolor': "#8892b0"},
                        'bar': {'color': color},
                        'bgcolor': "#101d33",
                        'borderwidth': 2,
                        'bordercolor': "#1a2a4a",
                        'steps': [
                            {'range': [0, 45], 'color': "rgba(255, 75, 75, 0.1)"},
                            {'range': [45, 75], 'color': "rgba(255, 204, 0, 0.1)"},
                            {'range': [75, 100], 'color': "rgba(0, 255, 157, 0.1)"}
                        ]
                    }
                ))
                fig.update_layout(height=350, paper_bgcolor='rgba(0,0,0,0)', font={'color': "white"})
                st.plotly_chart(fig, use_container_width=True)

            with right_col:
                st.markdown("### 📊 Security Intelligence Report")
                
                if score > 75:
                    st.success("✅ **TRUST LEVEL: HIGH** - No critical vulnerabilities found in structural analysis.")
                elif score > 45:
                    st.warning("⚠️ **TRUST LEVEL: MODERATE** - Suspicious patterns detected. Caution advised.")
                else:
                    st.error("🛑 **TRUST LEVEL: CRITICAL** - High probability of malicious intent.")

                # Detail rows
                for severity, title, desc in findings:
                    with st.expander(f"{severity}: {title}"):
                        st.write(desc)
                        
                if not findings:
                    st.write("Link structure meets global security standards.")

    else:
        st.error("Input required to begin scan.")

# --- FOOTER ---
st.markdown("""
    <div class="footer">
        <b>TECHNICAL SUPPORT:</b> Northern Technical University | <b>Telegram: @shim_azu64</b> | v2.1-Live
    </div>
    """, unsafe_allow_html=True)
