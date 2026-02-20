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

# --- ADVANCED ENTERPRISE CSS ---
st.markdown("""
    <style>
    .stApp {
        background-color: #05070a;
        background-image: 
            radial-gradient(at 0% 0%, rgba(31, 111, 235, 0.1) 0, transparent 50%), 
            radial-gradient(at 100% 0%, rgba(188, 140, 255, 0.05) 0, transparent 50%);
        color: #e6edf3;
    }
    .header-card {
        background: rgba(13, 17, 23, 0.8);
        backdrop-filter: blur(12px);
        padding: 35px;
        border-radius: 20px;
        border: 1px solid rgba(48, 54, 61, 1);
        text-align: center;
        box-shadow: 0 15px 35px rgba(0,0,0,0.5);
    }
    .forensic-log {
        background: #010409;
        border-left: 4px solid #f85149;
        color: #e6edf3;
        font-family: 'SFMono-Regular', Consolas, monospace;
        padding: 15px;
        margin-bottom: 10px;
        border-radius: 4px;
        font-size: 0.9rem;
    }
    .flag-critical { border-left-color: #f85149; }
    .flag-high { border-left-color: #f78166; }
    div.stButton > button {
        background: linear-gradient(180deg, #1f6feb 0%, #0969da 100%) !important;
        color: white !important;
        border-radius: 8px !important;
        width: 100% !important;
    }
    </style>
    """, unsafe_allow_html=True)

# --- HEADER SECTION ---
with st.container():
    c1, c2, c3 = st.columns([1, 4, 1])
    with c1:
        try: st.image("NTU logo.jpg", use_container_width=True)
        except: st.markdown("🏛️ **NTU**")
            
    with c2:
        st.markdown("""
            <div class='header-card'>
                <div style='color: #8b949e; letter-spacing: 2px; font-size: 0.8rem; margin-bottom: 5px;'>NORTHERN TECHNICAL UNIVERSITY</div>
                <h1 style='color: #ffffff; margin:0; font-size: 2.5rem; font-weight: 800;'>AI THREAT INTELLIGENCE</h1>
                <p style='color: #58a6ff; font-size: 1rem;'>College of AI & Computer Engineering | Forensic Analysis Unit</p>
            </div>
        """, unsafe_allow_html=True)
        
    with c3:
        # Proper Right-Alignment for College Logo
        _, c3_right = st.columns([1, 10]) 
        with c3_right:
            try: st.image("collegue logo.jpg", use_container_width=True)
            except: st.markdown("<div style='text-align: right;'>💻 **AI&CE**</div>", unsafe_allow_html=True)

# --- POWERFUL FORENSIC ENGINE ---
def deep_forensic_analysis(url):
    score = 100
    red_flags = []
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    domain = urllib.parse.urlparse(url).netloc.lower()
    path = urllib.parse.urlparse(url).path.lower()

    # --- 1. MALWARE SIGNATURE LAYER (Catching EICAR/Executables) ---
    malware_patterns = ['eicar', '.exe', '.com', '.scr', '.bin', '.dll', '.zip']
    if any(p in url.lower() for p in malware_patterns):
        score -= 90
        red_flags.append(("CRITICAL", "Malware Signature Detected: URL contains references to known antivirus test files or suspicious executable extensions (.com/.exe)."))

    # --- 2. PHISHING DATABASE LAYER ---
    blacklist = ['phishing', 'testsafebrowsing', 'verify', 'secure-update', 'signin-check']
    if any(p in url.lower() for p in blacklist):
        score -= 85
        red_flags.append(("CRITICAL", "Heuristic Phishing Match: URL architecture matches known social engineering deployment patterns."))

    # --- 3. DOMAIN SECURITY ---
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
        score -= 50
        red_flags.append(("CRITICAL", "IP-Based Routing: Bypass of DNS identified. Legitimate services do not host sensitive content on raw IP addresses."))

    if domain.startswith("xn--"):
        score -= 60
        red_flags.append(("CRITICAL", "Homograph Deception: Use of Punycode detected. This mimics legitimate brands using international characters."))

    return max(0, score), red_flags

# --- DASHBOARD ---
st.write("---")
st.markdown("### 🖥️ Forensic Command Console")
target_vector = st.text_input("INPUT ANALYSIS TARGET (URL):", placeholder="Paste URL here...")

if st.button("EXECUTE LIVE THREAT SCAN"):
    if target_vector:
        with st.spinner("Decoding threat vectors..."):
            score, flags = deep_forensic_analysis(target_vector)
            
            st.write("---")
            col_res1, col_res2 = st.columns([1, 1.5])
            
            with col_res1:
                g_color = "#238636" if score > 75 else "#d29922" if score > 45 else "#da3633"
                fig = go.Figure(go.Indicator(
                    mode="gauge+number", value=score,
                    number={'suffix': "%", 'font': {'color': g_color, 'size': 65}},
                    gauge={
                        'bar': {'color': g_color},
                        'bgcolor': "#0d1117",
                        'axis': {'range': [0, 100], 'tickcolor': "#484f58"},
                        'steps': [
                            {'range': [0, 45], 'color': "rgba(218, 54, 51, 0.1)"},
                            {'range': [45, 75], 'color': "rgba(210, 153, 34, 0.1)"},
                            {'range': [75, 100], 'color': "rgba(35, 134, 54, 0.1)"}
                        ],
                    }
                ))
                fig.update_layout(height=400, paper_bgcolor='rgba(0,0,0,0)', font={'color': "white"})
                st.plotly_chart(fig, use_container_width=True)

            with col_res2:
                st.markdown("### 📊 Forensic Intelligence Report")
                if score < 45: st.error("🛑 SECURITY STATUS: CRITICAL THREAT IDENTIFIED")
                elif score < 75: st.warning("⚠️ SECURITY STATUS: ELEVATED RISK ANOMALIES")
                else: st.success("✅ SECURITY STATUS: INTEGRITY VERIFIED")

                for severity, description in flags:
                    st.markdown(f"""<div class='forensic-log flag-{severity.lower()}'>
                        <strong>[{severity}]</strong> {description}</div>""", unsafe_allow_html=True)
                
                if not flags:
                    st.info("No immediate malicious signatures identified.")
    else:
        st.error("Please provide a target URL.")

st.markdown(f"""<div style="position: fixed; bottom: 0; left: 0; width: 100%; background: rgba(1, 4, 9, 0.95); padding: 12px; text-align: center; border-top: 1px solid #30363d; font-size: 11px; color: #484f58;">
    NTU | COLLEGE OF AI & COMPUTER ENGINEERING | <b>FORENSIC SUPPORT: @shim_azu64</b> | v5.2-ELITE</div>""", unsafe_allow_html=True)
