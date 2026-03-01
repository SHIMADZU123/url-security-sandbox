import streamlit as st
import requests
import base64
import whois
import socket
import time
import Levenshtein
from fpdf import FPDF
from datetime import datetime
from tldextract import extract

# --- [1. ULTIMATE SHINOBI DESIGN SYSTEM] ---
st.set_page_config(page_title="VORTEX // SHINOBI.OS", layout="wide", page_icon="🍥")

st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Permanent+Marker&family=Orbitron:wght@400;700&display=swap');
    
    /* Global Styles */
    .stApp { background: #050505; color: #f2a30b; }
    
    /* Typography */
    h1 { font-family: 'Permanent Marker', cursive; color: #ff4500; font-size: 4em !important; text-shadow: 3px 3px 0px #331100; text-align: center; }
    h3 { font-family: 'Orbitron', sans-serif; letter-spacing: 2px; color: #00d4ff; }
    
    /* Shinobi Card Design */
    .jutsu-card {
        background: rgba(20, 20, 20, 0.8);
        border: 2px solid #ff4500;
        border-radius: 15px;
        padding: 25px;
        box-shadow: 0 0 20px rgba(255, 69, 0, 0.3);
        margin-bottom: 20px;
        backdrop-filter: blur(10px);
    }
    
    /* Chakra Bar (Progress Bar) */
    .stProgress > div > div > div > div { background-image: linear-gradient(to right, #ff4500 , #f2a30b); }
    
    /* The "Seal" Button */
    .stButton>button {
        background: #ff4500;
        color: white; border: none; font-family: 'Orbitron', sans-serif;
        padding: 15px 30px; font-weight: bold; width: 100%;
        border-radius: 0px 20px 0px 20px;
        box-shadow: 5px 5px 0px #802200;
        transition: all 0.2s ease;
    }
    .stButton>button:hover { background: #ff6600; transform: translate(-2px, -2px); box-shadow: 7px 7px 0px #802200; }
    
    /* Sharingan Alert Pulse */
    .sharingan-alert {
        border: 2px solid #ff0000;
        background: rgba(255, 0, 0, 0.1);
        padding: 15px;
        animation: pulse 1.5s infinite;
        text-align: center; font-family: 'Permanent Marker';
    }
    @keyframes pulse { 0% { opacity: 0.6; } 50% { opacity: 1; } 100% { opacity: 0.6; } }
    </style>
    """, unsafe_allow_html=True)

# --- [2. FORBIDDEN JUTSU KERNEL] ---

def get_ip_history(url):
    """Nine-Tails Mode: Trace the spirit of the domain back to its IP."""
    try:
        domain = extract(url).registered_domain
        ip_addr = socket.gethostbyname(domain)
        return ip_addr
    except:
        return "IP_TRACE_FAILED"

def byakugan_vision(url):
    """Detects Genjutsu (Phishing) on high-authority cloud nodes."""
    test_nodes = ["testsafebrowsing.appspot.com", "eicar.org"]
    danger_words = ["phishing", "login", "verify", "secure", "signin"]
    threats = []
    
    if any(node in url for node in test_nodes):
        threats.append("🚨 TEST_NODE_DETECTION: Known Malicious Simulation Node Found.")
    
    for word in danger_words:
        if word in url.lower():
            threats.append(f"👁️ SHARINGAN: Suspicious Path Segment '{word.upper()}' detected.")
            
    return threats

# --- [3. UI LAYOUT: THE SCROLL OF SEALING] ---

st.markdown("<h1>🌀 VORTEX // SHINOBI.OS</h1>", unsafe_allow_html=True)
st.markdown("<p style='text-align:center; color:#555;'>PROXIED VIA ANBU INTELLIGENCE NETWORK // VER 9.4</p>", unsafe_allow_html=True)

API_KEY = st.secrets.get("VT_API_KEY")

# Input Section with "Scroll" styling
with st.container():
    st.markdown("### 📜 ENTER TARGET SCROLL (URL)")
    target_url = st.text_input("", placeholder="https://hidden-threat-coordinate.ninja")

if st.button("EXE: SUMMON ANALYTICAL JUTSU") and target_url:
    # --- PHASE 1: CHAKRA LOADING ---
    progress = st.progress(0)
    for i in range(100):
        time.sleep(0.01)
        progress.progress(i + 1)
    
    # --- PHASE 2: JUTSU EXECUTION ---
    threat_list = byakugan_vision(target_url)
    ip_trace = get_ip_history(target_url)
    
    # VirusTotal Integration
    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
    vt_res = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers={"x-apikey": API_KEY})
    
    # Domain Age
    try:
        w = whois.whois(extract(target_url).registered_domain)
        creation = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        age = (datetime.now() - creation).days
    except: age = "UNKNOWN"

    # --- PHASE 3: THE TACTICAL HUD ---
    if vt_res.status_code == 200:
        stats = vt_res.json()['data']['attributes']['last_analysis_stats']
        risk_base = (stats['malicious'] / sum(stats.values())) * 100 if sum(stats.values()) > 0 else 0
        
        # Override Logic
        final_risk = 100 if threat_list else risk_base

        if final_risk > 20:
            st.markdown(f"<div class='sharingan-alert'>FORBIDDEN JUTSU DETECTED! RISK: {final_risk:.1f}%</div>", unsafe_allow_html=True)
        else:
            st.success("🍃 WILL OF FIRE: Site appears clear of corruption.")

        st.divider()

        # Columns for Shinobi Metrics
        c1, c2, c3 = st.columns(3)
        with c1:
            st.markdown("<div class='jutsu-card'><h3>⚡ RISK</h3>" + f"<h2>{final_risk:.1f}%</h2></div>", unsafe_allow_html=True)
        with c2:
            st.markdown("<div class='jutsu-card'><h3>🕰️ AGE</h3>" + f"<h2>{age}d</h2></div>", unsafe_allow_html=True)
        with c3:
            st.markdown("<div class='jutsu-card'><h3>🌐 IP_TRACE</h3>" + f"<h2>{ip_trace}</h2></div>", unsafe_allow_html=True)

        # Visual Recon
        st.markdown("### 👁️ VISUAL RECONNAISSANCE")
        st.image(f"https://s0.wp.com/mshots/v1/{target_url}?w=800", use_container_width=True)
        
        # Threat List Breakdown
        if threat_list:
            with st.expander("VIEW SHADOW CLONE DATA (Technical Details)"):
                for t in threat_list:
                    st.write(f"- {t}")
