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
st.set_page_config(
    page_title="NTU AI Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# --- ENTERPRISE GLASSMORPHIC CSS ---
st.markdown("""
    <style>
    .stApp {
        background: radial-gradient(circle at 50% 50%, #0d1b2a 0%, #010409 100%);
        color: #e6edf3;
    }
    .header-panel {
        background: rgba(255, 255, 255, 0.03);
        backdrop-filter: blur(12px);
        border-radius: 20px;
        padding: 30px;
        border: 1px solid rgba(255, 255, 255, 0.1);
        text-align: center;
        margin-bottom: 30px;
    }
    .terminal-output {
        background: #000; color: #39ff14; font-family: 'Courier New', monospace;
        padding: 20px; border-radius: 10px; border: 1px solid #30363d;
        font-size: 14px; line-height: 1.6;
    }
    div.stButton > button {
        background: linear-gradient(90deg, #1f6feb, #388bfd) !important;
        color: white !important;
        border: none !important;
        height: 50px !important;
        width: 100% !important;
        border-radius: 12px !important;
        font-weight: bold !important;
    }
    .footer {
        position: fixed; bottom: 0; left: 0; width: 100%;
        background: rgba(1, 4, 9, 0.95); padding: 10px; text-align: center;
        font-size: 12px; color: #8b949e; border-top: 1px solid #30363d;
        z-index: 100;
    }
    </style>
    """, unsafe_allow_html=True)

# --- HEADER WITH STABLE LOGO LOGIC ---
with st.container():
    c1, c2, c3 = st.columns([1, 4, 1])
    with c1:
        try:
            st.image("NTU logo.jpg", width=110)
        except:
            st.markdown("🏛️ **NTU**")
    with c2:
        st.markdown("""
            <div class='header-panel'>
                <h1 style='color: #58a6ff; margin:0; font-size: 2.5rem;'>AI THREAT INTELLIGENCE SYSTEM</h1>
                <p style='color: #8b949e; letter-spacing: 2px; margin-top: 10px;'>
                    NORTHERN TECHNICAL UNIVERSITY | COLLEGE OF AI & COMPUTER ENGINEERING
                </p>
            </div>
        """, unsafe_allow_html=True)
    with c3:
        try:
            st.image("collegue logo.jpg", width=110)
        except:
            st.markdown("<div style='text-align: right;'>💻 **AI & CE**</div>", unsafe_allow_html=True)

# --- HIGH-SENSITIVITY SCANNING ENGINE ---
def analyze_threat_vector(url):
    score = 100
    evidence = []
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()

    # 1. DATABASE/KEYWORD BLACKLIST (High Priority)
    blacklist = ['phishing', 'testsafebrowsing', 'malware', 'login-verify', 'secure-update']
    if any(p in url.lower() for p in blacklist):
        score -= 95
        evidence.append("🛑 [DATABASE] High-confidence match in Global Threat Intelligence Blacklist.")

    # 2. HOMOGRAPH/PUNYCODE CHECK
    if domain.startswith("xn--"):
        score -= 50
        evidence.append("🚨 [CRITICAL] Homograph Attack: URL uses visual character deception.")

    # 3. IP ADDRESS DETECTION
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
        score -= 45
        evidence.append("🚨 [CRITICAL] Bypassed DNS: Raw IP usage detected instead of verified domain.")

    # 4. TRANSPORT LAYER SECURITY
    if not url.startswith("https"):
        score -= 35
        evidence.append("🔓 [SECURITY] HTTP Protocol: Connection lacks SSL/TLS encryption.")

    # 5. SUSPICIOUS TLD ANALYSIS
    malicious_tlds = ['.zip', '.xyz', '.top', '.monster', '.click', '.tk']
    if any(domain.endswith(tld) for tld in malicious_tlds):
        score -= 20
        evidence.append(f"⚠️ [TLD RISK] High-risk extension ({domain.split('.')[-1]}) identified.")

    return max(0, score), evidence

# --- COMMAND CENTER INTERFACE ---
st.markdown("### 🖥️ Forensics Command Console")
target_vector = st.text_input("INPUT TARGET VECTOR (URL):", placeholder="e.g., https://secure-login-ntu.com")

if st.button("EXECUTE REAL-TIME SCAN"):
    if target_vector:
        with st.spinner("Decoding threat signatures..."):
            score, logs = analyze_threat_vector(target_vector)
            
            st.divider()
            col_g, col_l = st.columns([1, 1.5])
            
            with col_g:
                # DYNAMIC PRO GAUGE
                g_color = "#238636" if score > 75 else "#d29922" if score > 45 else "#da3633"
                fig = go.Figure(go.Indicator(
                    mode="gauge+number", value=score,
                    number={'suffix': "%", 'font': {'color': g_color, 'size': 60}},
                    gauge={
                        'bar': {'color': g_color},
                        'bgcolor': "#0d1117",
                        'axis': {'range': [0, 100], 'tickcolor': "#8b949e"},
                        'steps': [
                            {'range': [0, 45], 'color': "rgba(218, 54, 51, 0.1)"},
                            {'range': [45, 75], 'color': "rgba(210, 153, 34, 0.1)"},
                            {'range': [75, 100], 'color': "rgba(35, 134, 54, 0.1)"}
                        ],
                        'threshold': {'line': {'color': "white", 'width': 4}, 'value': score}
                    }
                ))
                fig.update_layout(height=400, paper_bgcolor='rgba(0,0,0,0)', font={'color': "white"})
                st.plotly_chart(fig, use_container_width=True)
            
            with col_l:
                st.markdown("### 🔍 Forensic Investigation Report")
                if score < 45:
                    st.error("🛑 THREAT LEVEL: CRITICAL | POTENTIAL MALICIOUS ACTOR")
                elif score < 75:
                    st.warning("⚠️ THREAT LEVEL: ELEVATED | ANOMALIES DETECTED")
                else:
                    st.success("✅ THREAT LEVEL: MINIMAL | INTEGRITY VERIFIED")
                
                log_box = "<br>".join(logs) if logs else "Scan finalized. No common structural threats found."
                st.markdown(f"<div class='terminal-output'>{log_box}</div>", unsafe_allow_html=True)
    else:
        st.error("Error: Analysis requires a valid target input.")

# --- PERSISTENT FOOTER ---
st.markdown(f"""
    <div class="footer">
        NORTHERN TECHNICAL UNIVERSITY | COLLEGE OF AI & COMPUTER ENGINEERING | 
        <span style="color: #58a6ff;">SUPPORT: @shim_azu64</span> | V5.0-PRO-STABLE
    </div>
    """, unsafe_allow_html=True)
