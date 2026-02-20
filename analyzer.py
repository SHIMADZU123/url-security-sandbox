import streamlit as st
import requests
import whois
import ssl
import socket
import urllib.parse
from datetime import datetime
import re
import plotly.graph_objects as go

# --- PAGE CONFIGURATION ---
st.set_page_config(page_title="NTU AI Threat Intel", page_icon="🛡️", layout="wide")

# --- CYBERSECURITY UI CSS ---
st.markdown("""
    <style>
    .stApp { background: #0b0f19; color: #ffffff; }
    .report-box {
        background: rgba(255, 255, 255, 0.03);
        border-radius: 15px;
        padding: 20px;
        border: 1px solid #1f2937;
    }
    .red-flag { color: #ff4b4b; font-weight: bold; }
    .footer {
        position: fixed; bottom: 0; left: 0; width: 100%;
        background: #0b0f19; text-align: center; padding: 10px;
        font-size: 12px; color: #4b5563; border-top: 1px solid #1f2937;
    }
    </style>
    """, unsafe_allow_html=True)

# --- HEADER ---
col1, col2, col3 = st.columns([1, 4, 1])
with col1:
    try: st.image("NTU logo.jpg", width=100)
    except: st.write("🏛️")
with col2:
    st.markdown("<h1 style='text-align: center; color: #58a6ff;'>Advanced Threat Detection System</h1>", unsafe_allow_html=True)
    st.markdown("<p style='text-align: center; color: #8b949e;'>Northern Technical University | AI & Computer Engineering College</p>", unsafe_allow_html=True)
with col3:
    try: st.image("collegue logo.jpg", width=100)
    except: st.write("💻")

# --- POWERFUL SCANNING ENGINE ---
def deep_analyze(url):
    score = 100
    red_flags = []
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()

    # FLAG 1: Homograph/Punnycode Attack (Visual deception)
    if domain.startswith("xn--"):
        score -= 50
        red_flags.append("🚨 **HOMOGRAPH ATTACK:** This URL uses international characters to mimic a real brand.")

    # FLAG 2: Suspicious TLD (Top Level Domain)
    malicious_tlds = ['.zip', '.mov', '.top', '.gq', '.tk', '.xyz', '.cf', '.ga']
    if any(domain.endswith(tld) for tld in malicious_tlds):
        score -= 25
        red_flags.append(f"⚠️ **UNTRUSTED TLD:** The '{domain.split('.')[-1]}' extension is statistically linked to malware.")

    # FLAG 3: Obfuscation (IP/Symbols)
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
        score -= 40
        red_flags.append("🚨 **IP-BASED HOSTING:** Legitimate companies use DNS names, not raw IP addresses.")

    # FLAG 4: Credential Harvesting Keywords
    harvest_patterns = ['login', 'verify', 'update-account', 'secure-signin', 'webmail', 'banking']
    if any(p in path or p in domain for p in harvest_patterns):
        score -= 20
        red_flags.append("🎣 **PHISHING KEYWORD:** The URL contains high-urgency keywords used to steal credentials.")

    # FLAG 5: Subdomain Obfuscation
    if domain.count('.') > 3:
        score -= 15
        red_flags.append("⚠️ **SUBDOMAIN PADDING:** Excessive dots are used to hide the real domain on mobile devices.")

    # FLAG 6: Missing Security Layer
    if not url.startswith("https"):
        score -= 30
        red_flags.append("🔓 **NO ENCRYPTION:** Site uses HTTP. Any data entered is visible to hackers.")

    return max(0, score), red_flags

# --- USER INTERFACE ---
st.write("---")
input_url = st.text_input("Enter URL for Deep Inspection:", placeholder="https://")

if st.button("RUN DEEP ANALYSIS"):
    if input_url:
        score, flags = deep_analyze(input_url)
        
        c1, c2 = st.columns([1, 1.5])
        with c1:
            # Dynamic Gauge
            color = "#00ff9d" if score > 80 else "#ffcc00" if score > 40 else "#ff4b4b"
            fig = go.Figure(go.Indicator(
                mode="gauge+number", value=score,
                gauge={'bar': {'color': color}, 'bgcolor': "#1a1f2e", 'axis': {'range': [0, 100]}}
            ))
            fig.update_layout(height=300, paper_bgcolor='rgba(0,0,0,0)', font={'color': "white"})
            st.plotly_chart(fig, use_container_width=True)
            
        with c2:
            st.markdown("### 🔍 Threat Intelligence Log")
            if not flags:
                st.success("Clean: No common red flags detected in URL structure.")
            else:
                for f in flags:
                    st.markdown(f)
                    
            if score < 40:
                st.error("SYSTEM RECOMMENDATION: BLOCK CONNECTION")
            elif score < 80:
                st.warning("SYSTEM RECOMMENDATION: PROCEED WITH CAUTION")
            else:
                st.success("SYSTEM RECOMMENDATION: SAFE")

# --- FOOTER ---
st.markdown(f'<div class="footer">NTU SUPPORT: @shim_azu64 | Forensic Engine V4.0</div>', unsafe_allow_html=True)
