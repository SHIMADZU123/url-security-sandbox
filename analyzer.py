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
    page_title="Forensic AI | Northern Technical University",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# --- MODERN ENTERPRISE UI (CSS) ---
st.markdown("""
    <style>
    /* Main Background with Cyber-Grid effect */
    .stApp {
        background-color: #05070a;
        background-image: 
            radial-gradient(at 0% 0%, rgba(31, 111, 235, 0.1) 0, transparent 50%), 
            radial-gradient(at 50% 0%, rgba(188, 140, 255, 0.05) 0, transparent 50%);
        color: #e6edf3;
    }

    /* Professional Glassmorphic Header */
    .header-card {
        background: rgba(13, 17, 23, 0.7);
        backdrop-filter: blur(10px);
        padding: 40px;
        border-radius: 24px;
        border: 1px solid rgba(48, 54, 61, 0.8);
        text-align: center;
        margin-bottom: 40px;
        box-shadow: 0 20px 40px rgba(0,0,0,0.4);
    }

    /* Subtitle Styling */
    .university-text {
        color: #8b949e;
        font-weight: 500;
        letter-spacing: 3px;
        text-transform: uppercase;
        font-size: 0.85rem;
        margin-bottom: 8px;
    }

    /* High-End Input Box */
    .stTextInput>div>div>input {
        background-color: #0d1117 !important;
        color: #58a6ff !important;
        border: 1px solid #30363d !important;
        border-radius: 12px !important;
        padding: 12px 20px !important;
        font-family: 'Inter', sans-serif;
    }

    /* Action Button - Neon Blue */
    div.stButton > button {
        background: linear-gradient(90deg, #1f6feb 0%, #388bfd 100%) !important;
        color: white !important;
        border: none !important;
        padding: 14px 28px !important;
        font-weight: 700 !important;
        border-radius: 12px !important;
        width: 100% !important;
        box-shadow: 0 4px 14px 0 rgba(31, 111, 235, 0.39) !important;
        transition: 0.3s ease;
    }
    
    div.stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 20px rgba(31, 111, 235, 0.6) !important;
    }

    /* Terminal/Log Output */
    .terminal-output {
        background: #010409;
        border: 1px solid #30363d;
        color: #7ee787;
        font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
        padding: 24px;
        border-radius: 16px;
        font-size: 0.95rem;
        line-height: 1.6;
    }

    /* Dynamic Footer */
    .footer {
        position: fixed; bottom: 0; left: 0; width: 100%;
        background: rgba(1, 4, 9, 0.9);
        backdrop-filter: blur(5px);
        padding: 12px;
        text-align: center;
        font-size: 11px;
        color: #484f58;
        border-top: 1px solid #30363d;
        z-index: 100;
    }
    </style>
    """, unsafe_allow_html=True)

# --- HEADER WITH STABLE LOGO HANDLING ---
with st.container():
    c1, c2, c3 = st.columns([1, 4, 1])
    with c1:
        try:
            st.image("NTU logo.jpg", width=120)
        except:
            st.markdown("🏛️ **NTU**")
            
    with c2:
        st.markdown("""
            <div class='header-card'>
                <div class='university-text'>Northern Technical University</div>
                <h1 style='color: #ffffff; margin:0; font-size: 2.8rem; font-weight: 800;'>AI THREAT INTELLIGENCE</h1>
                <p style='color: #58a6ff; font-weight: 400; font-size: 1.1rem; margin-top: 10px;'>
                    Advanced Phishing Detection & Network Forensics
                </p>
            </div>
        """, unsafe_allow_html=True)
        
    with c3:
        try:
            st.image("collegue logo.jpg", width=120)
        except:
            st.markdown("<div style='text-align: right;'>💻 **AI&CE**</div>", unsafe_allow_html=True)

# --- ELITE FORENSIC ENGINE ---
def run_forensic_scan(url):
    score = 100
    evidence = []
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    domain = urllib.parse.urlparse(url).netloc.lower()
    
    # Check 1: Database Intelligence
    blacklist = ['phishing', 'testsafebrowsing', 'malware', 'login-verify', 'secure-update', 'appspot.com']
    if any(p in url.lower() for p in blacklist):
        score -= 95
        evidence.append("🛑 [INTEL] Destination matches known malicious signature database.")

    # Check 2: Punycode/Homograph Analysis
    if domain.startswith("xn--"):
        score -= 55
        evidence.append("🚨 [CRITICAL] Homograph Attack: Visual spoofing of character encoding detected.")

    # Check 3: Raw IP Routing
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
        score -= 45
        evidence.append("🚨 [CRITICAL] Suspicious Routing: URL uses raw IP address instead of verified DNS.")

    # Check 4: SSL Integrity
    if not url.startswith("https"):
        score -= 35
        evidence.append("🔓 [SECURITY] HTTP Protocol: Connection lacks encryption. Data vulnerable to interception.")

    return max(0, score), evidence

# --- MAIN DASHBOARD INTERFACE ---
st.markdown("### 🔍 Forensic Command Center")
target_url = st.text_input("INPUT TARGET VECTOR (URL):", placeholder="e.g., https://internal-security-scan.net")

if st.button("EXECUTE LIVE FORENSIC SCAN"):
    if target_url:
        with st.spinner("Decoding threat signatures..."):
            score, logs = run_forensic_scan(target_url)
            
            st.write("---")
            col_chart, col_report = st.columns([1.2, 2])
            
            with col_chart:
                # CUSTOM GAUGUE WITH ENTERPRISE COLORS
                g_color = "#238636" if score > 75 else "#d29922" if score > 45 else "#da3633"
                fig = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=score,
                    number={'suffix': "%", 'font': {'color': g_color, 'size': 60}},
                    gauge={
                        'axis': {'range': [0, 100], 'tickcolor': "#484f58"},
                        'bar': {'color': g_color},
                        'bgcolor': "#0d1117",
                        'borderwidth': 2,
                        'bordercolor': "#30363d",
                        'steps': [
                            {'range': [0, 45], 'color': "rgba(218, 54, 51, 0.1)"},
                            {'range': [45, 75], 'color': "rgba(210, 153, 34, 0.1)"},
                            {'range': [75, 100], 'color': "rgba(35, 134, 54, 0.1)"}
                        ],
                    }
                ))
                fig.update_layout(height=400, paper_bgcolor='rgba(0,0,0,0)', font={'color': "white"})
                st.plotly_chart(fig, use_container_width=True)

            with col_report:
                st.markdown("### 📊 Investigation Summary")
                if score < 45:
                    st.error("🛑 THREAT LEVEL: CRITICAL | POTENTIAL MALICIOUS ACTOR")
                elif score < 75:
                    st.warning("⚠️ THREAT LEVEL: ELEVATED | ANOMALIES DETECTED")
                else:
                    st.success("✅ THREAT LEVEL: MINIMAL | INTEGRITY VERIFIED")
                
                log_content = "<br>".join(logs) if logs else "No structural threat vectors identified in real-time analysis."
                st.markdown(f"<div class='terminal-output'>{log_content}</div>", unsafe_allow_html=True)
    else:
        st.error("Target required for execution.")

# --- PERSISTENT FOOTER ---
st.markdown(f"""
    <div class="footer">
        NORTHERN TECHNICAL UNIVERSITY | AI & COMPUTER ENGINEERING COLLEGE | 
        <span style="color: #58a6ff;">SUPPORT ID: @shim_azu64</span> | FORENSIC NODE: ACTIVE
    </div>
    """, unsafe_allow_html=True)
