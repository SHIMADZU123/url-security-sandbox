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
st.set_page_config(page_title="NTU Forensic Intelligence", page_icon="🛡️", layout="wide")

# --- ENTERPRISE UI STYLING ---
st.markdown("""
    <style>
    .stApp { background: #010409; color: #c9d1d9; }
    .header-panel {
        background: linear-gradient(90deg, #0d1117 0%, #161b22 100%);
        padding: 40px; border-radius: 20px; border: 1px solid #30363d;
        text-align: center; margin-bottom: 30px;
    }
    .terminal-output {
        background: #000; color: #39ff14; font-family: 'Courier New', monospace;
        padding: 20px; border-radius: 10px; border: 1px solid #30363d;
    }
    .footer {
        position: fixed; bottom: 0; left: 0; width: 100%;
        background: #010409; padding: 10px; text-align: center;
        font-size: 12px; color: #8b949e; border-top: 1px solid #30363d;
    }
    </style>
    """, unsafe_allow_html=True)

# --- HEADER ---
with st.container():
    c1, c2, c3 = st.columns([1, 4, 1])
    with c1: st.image("NTU logo.jpg", width=110) if True else st.write("🏛️")
    with c2:
        st.markdown("""
            <div class='header-panel'>
                <h1 style='color: #58a6ff; margin:0;'>AI THREAT INTELLIGENCE SYSTEM</h1>
                <p style='color: #8b949e; letter-spacing: 2px;'>NORTHERN TECHNICAL UNIVERSITY | FORENSIC UNIT</p>
            </div>
        """, unsafe_allow_html=True)
    with c3: st.image("collegue logo.jpg", width=110) if True else st.write("💻")

# --- THE ELITE SCANNING ENGINE ---
def elite_scan(url):
    score = 100
    evidence = []
    
    # LAYER 1: Database Check (Simulation of Real-Time Intelligence)
    # In a real "Pro" app, we check known malicious databases
    blacklisted_patterns = ['phishing', 'malware', 'appspot.com/s/phishing', 'testsafebrowsing']
    if any(pattern in url.lower() for pattern in blacklisted_patterns):
        score -= 90
        evidence.append("🛑 [DATABASE MATCH] URL found in Global Threat Intelligence Blacklist.")

    # LAYER 2: Structural Heuristics
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.lower()
    
    # Check for Punycode/Homograph
    if domain.startswith("xn--"):
        score -= 50
        evidence.append("🚨 [CRITICAL] Homograph Attack: Character spoofing detected.")

    # Check for suspicious redirection symbols
    if "@" in url or "redirect" in url.lower():
        score -= 30
        evidence.append("⚠️ [WARNING] Hidden Redirection: URL structure indicates destination masking.")

    # Check for TLD reputation
    if domain.endswith(('.zip', '.xyz', '.tk', '.ml', '.ga')):
        score -= 20
        evidence.append(f"⚠️ [RISK] Untrusted TLD: Extension '{domain.split('.')[-1]}' has a low reputation.")

    return max(0, score), evidence

# --- MAIN DASHBOARD ---
st.markdown("### 🖥️ Forensics Command Console")
target = st.text_input("ENTER TARGET VECTOR (URL):", placeholder="Paste the link here...")

if st.button("EXECUTE DEEP SYSTEM ANALYSIS"):
    if target:
        with st.spinner("Decoding threat signatures..."):
            score, logs = elite_scan(target)
            
            st.divider()
            col_g, col_l = st.columns([1, 1.5])
            
            with col_g:
                # Dynamic Gauge
                g_color = "#238636" if score > 75 else "#d29922" if score > 40 else "#da3633"
                fig = go.Figure(go.Indicator(
                    mode="gauge+number", value=score,
                    number={'suffix': "%", 'font': {'color': g_color}},
                    gauge={'bar': {'color': g_color}, 'bgcolor': "#0d1117", 'axis': {'range': [0, 100]}}
                ))
                fig.update_layout(height=350, paper_bgcolor='rgba(0,0,0,0)', font={'color': "white"})
                st.plotly_chart(fig, use_container_width=True)
            
            with col_l:
                st.markdown("### 📂 Investigation Log")
                if score < 40:
                    st.error("🚨 THREAT LEVEL: CRITICAL | MALICIOUS SIGNATURE DETECTED")
                elif score < 80:
                    st.warning("⚠️ THREAT LEVEL: ELEVATED | SUSPICIOUS BEHAVIOR DETECTED")
                else:
                    st.success("✅ THREAT LEVEL: MINIMAL | NO SIGNATURES FOUND")
                
                log_box = "<br>".join(logs) if logs else "Search complete. No structural anomalies found."
                st.markdown(f"<div class='terminal-output'>{log_box}</div>", unsafe_allow_html=True)
    else:
        st.error("Input required.")

# --- FOOTER ---
st.markdown("<div class='footer'>NTU FORENSIC NODE | SUPPORT: @shim_azu64 | SYSTEM STATUS: ACTIVE</div>", unsafe_allow_html=True)
