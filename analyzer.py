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
    page_title="NTU | AI Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# --- ADVANCED CSS FOR HIGH-END "ENTERPRISE" VIBE ---
st.markdown("""
    <style>
    /* Dark Cyber Theme Background */
    .stApp {
        background: radial-gradient(circle at 50% 50%, #0d1b2a 0%, #010409 100%);
        color: #e6edf3;
    }
    
    /* Modern Glassmorphic Header */
    .main-header {
        background: rgba(255, 255, 255, 0.03);
        backdrop-filter: blur(12px);
        border-radius: 24px;
        padding: 40px;
        border: 1px solid rgba(255, 255, 255, 0.1);
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.8);
        text-align: center;
        margin-bottom: 40px;
    }

    /* Gradient Text for Headlines */
    .gradient-text {
        background: linear-gradient(90deg, #58a6ff, #bc8cff);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-weight: 800;
        letter-spacing: -1px;
    }

    /* Cyber Button Styling */
    div.stButton > button {
        background: linear-gradient(90deg, #1f6feb, #388bfd) !important;
        color: white !important;
        border: none !important;
        padding: 15px 30px !important;
        font-weight: bold !important;
        border-radius: 12px !important;
        box-shadow: 0 0 15px rgba(31, 111, 235, 0.4) !important;
        transition: 0.3s all ease !important;
    }
    
    div.stButton > button:hover {
        box-shadow: 0 0 25px rgba(31, 111, 235, 0.8) !important;
        transform: translateY(-2px);
    }

    /* Fixed Contact Footer */
    .pro-footer {
        position: fixed;
        bottom: 0;
        left: 0;
        width: 100%;
        background: rgba(1, 4, 9, 0.9);
        border-top: 1px solid #30363d;
        padding: 15px;
        text-align: center;
        font-family: 'Courier New', Courier, monospace;
        font-size: 12px;
        color: #8b949e;
        z-index: 999;
    }
    </style>
    """, unsafe_allow_html=True)

# --- PROFESSIONAL HEADER LAYOUT ---
with st.container():
    col1, col2, col3 = st.columns([1, 4, 1])
    
    with col1:
        try:
            st.image("NTU logo.jpg", width=120)
        except:
            st.markdown("🏛️ **NTU**")
            
    with col2:
        st.markdown("""
            <div class="main-header">
                <h1 class="gradient-text" style='font-size: 3rem; margin-bottom: 0;'>Welcome to the AI Threat Intelligence</h1>
                <h3 style='color: #8b949e; font-weight: 400; margin-top: 10px;'>Northern Technical University</h3>
                <p style='color: #58a6ff; font-size: 1rem; letter-spacing: 2px;'>AI & COMPUTER ENGINEERING COLLEGE | CYBER-THREAT V3.0 STABLE</p>
            </div>
            """, unsafe_allow_html=True)
        
    with col3:
        try:
            st.image("collegue logo.jpg", width=120)
        except:
            st.markdown("<div style='text-align: right;'>💻 **AI&CE**</div>", unsafe_allow_html=True)

# --- CORE ANALYSIS ENGINE ---
def deep_scan_engine(url):
    score = 100
    risk_factors = []
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    domain = urllib.parse.urlparse(url).netloc
    
    # 1. Structural Checks
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
        score -= 45
        risk_factors.append(("CRITICAL", "IP Domain masking detected. Standard DNS bypassed."))
    
    if "@" in url:
        score -= 30
        risk_factors.append(("HIGH", "User credential redirection injection detected."))
        
    if domain.count('.') > 3:
        score -= 20
        risk_factors.append(("MEDIUM", "Excessive subdomain layering typical of phishing architecture."))

    if not url.startswith("https"):
        score -= 35
        risk_factors.append(("HIGH", "Unencrypted protocol (HTTP). Potential MITM vulnerability."))

    return max(0, score), risk_factors

# --- MAIN INTERFACE ---
st.markdown("### 🖥️ Security Command Center")
target_url = st.text_input("INPUT TARGET URL FOR REAL-TIME FORENSICS:", placeholder="https://external-threat-target.net")

if st.button("EXECUTE DEEP SYSTEM SCAN"):
    if target_url:
        with st.spinner("📡 Interrogating global threat databases..."):
            score, factors = deep_scan_engine(target_url)
            
            st.divider()
            l_col, r_col = st.columns([1.5, 2])
            
            with l_col:
                # PREMIUM PLOTLY GAUGE
                gauge_color = "#238636" if score > 75 else "#d29922" if score > 45 else "#da3633"
                fig = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=score,
                    number={'suffix': "%", 'font': {'size': 80, 'color': gauge_color}},
                    gauge={
                        'axis': {'range': [0, 100], 'tickcolor': "#8b949e"},
                        'bar': {'color': gauge_color},
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

            with r_col:
                st.markdown("### 🔍 Threat Intelligence Report")
                if score > 75:
                    st.success(f"🛡️ **THREAT LEVEL: LOW** | Confidence: 94%")
                elif score > 45:
                    st.warning(f"⚠️ **THREAT LEVEL: ELEVATED** | Potential Phishing Vectors Detected")
                else:
                    st.error(f"🛑 **THREAT LEVEL: CRITICAL** | Malicious Signature Identified")

                for level, msg in factors:
                    st.markdown(f"**[{level}]** {msg}")
                
                if not factors:
                    st.info("No immediate heuristic anomalies detected in URL structure.")
    else:
        st.error("SYSTEM ERROR: No target provided for scan.")

# --- PROFESSIONAL FOOTER ---
st.markdown(f"""
    <div class="pro-footer">
        NORTHERN TECHNICAL UNIVERSITY | AI & COMPUTER ENGINEERING | 
        <span style="color: #58a6ff;">SUPPORT: @shim_azu64</span> | 
        SECURE NODE: {socket.gethostname().upper()}
    </div>
    """, unsafe_allow_html=True)
