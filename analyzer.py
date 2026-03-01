import streamlit as st
import requests
import base64
import whois
import time
import Levenshtein
import plotly.graph_objects as go
from fpdf import FPDF
from datetime import datetime
from tldextract import extract
from bs4 import BeautifulSoup

# --- [1. DESIGN: THE GHOST ARCHITECTURE] ---
st.set_page_config(page_title="VORTEX // GHOST-OS", layout="wide", page_icon="💀")

st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@100;400&display=swap');
    * { font-family: 'JetBrains Mono', monospace; }
    .stApp { background: #000000; color: #00ff41; } /* Matrix Green on Black */
    .stMetric { border-left: 3px solid #00ff41; background: rgba(0,255,65,0.05); padding: 10px; }
    .terminal-card { border: 1px solid #333; padding: 20px; border-radius: 0px; background: #050505; }
    .scan-line { width: 100%; height: 2px; background: #00ff41; position: absolute; opacity: 0.3; animation: scan 3s infinite; }
    @keyframes scan { 0% { top: 0; } 100% { top: 100%; } }
    </style>
    """, unsafe_allow_html=True)

# --- [2. UNIQUE LOGIC: STRUCTURAL DNA] ---
def analyze_structural_dna(url):
    try:
        res = requests.get(url, timeout=5)
        soup = BeautifulSoup(res.text, 'html.parser')
        links = soup.find_all('a', href=True)
        total_links = len(links)
        if total_links == 0: return 0
        
        # Calculate how many links point AWAY from the domain
        # High external link ratio = likely a hasty clone
        ext_links = [l['href'] for l in links if "http" in l['href'] and extract(url).domain not in l['href']]
        return (len(ext_links) / total_links) * 100
    except: return 0

# --- [3. UNIQUE LOGIC: HEURISTIC AI SCORE] ---
def calculate_phantom_score(risk, age, dna):
    score = 0
    if risk > 10: score += 40
    if isinstance(age, int) and age < 60: score += 30
    if dna > 50: score += 30  # High external link ratio
    return min(score, 100)

# --- [4. CORE SYSTEM] ---
st.markdown("<h1 style='letter-spacing: -2px;'>VORTEX // <span style='color:white;'>GHOST.OS</span></h1>", unsafe_allow_html=True)
st.caption("TACTICAL URL DECONSTRUCTION // KERNEL VER: 9.2.0-STABLE")

API_KEY = st.secrets.get("VT_API_KEY")

target = st.text_input(">> [ENTER_TARGET_STRING]:", placeholder="TERMINAL_CMD://INPUT_URL")

if st.button("EXECUTE_DECONSTRUCTION") and target:
    with st.empty():
        for percent in range(0, 101, 10):
            st.write(f"📂 ACCESSING_MEMORY_BLOCK_{percent}%...")
            time.sleep(0.1)
    
    # Data Gathering
    url_id = base64.urlsafe_b64encode(target.encode()).decode().strip("=")
    vt_res = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers={"x-apikey": API_KEY})
    
    dna_risk = analyze_structural_dna(target)
    
    try:
        w = whois.whois(extract(target).registered_domain)
        creation = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        age = (datetime.now() - creation).days
    except: age = "UNKNOWN"

    # Phantom Analysis
    if vt_res.status_code == 200:
        vt_stats = vt_res.json()['data']['attributes']['last_analysis_stats']
        base_risk = (vt_stats['malicious'] / sum(vt_stats.values())) * 100
        phantom_score = calculate_phantom_score(base_risk, age, dna_risk)

        # --- UNIQUE UI: THE PHANTOM HUD ---
        col_hud, col_recon = st.columns([2, 1])
        
        with col_hud:
            st.markdown("<div class='terminal-card'>", unsafe_allow_html=True)
            st.write(f"### [ SYSTEM_VERDICT: {'CRITICAL' if phantom_score > 50 else 'STABLE'} ]")
            
            # Custom Gauge
            fig = go.Figure(go.Pie(labels=['RISK', 'SAFE'], values=[phantom_score, 100-phantom_score], hole=.8, marker_colors=['#ff0000', '#111']))
            fig.update_layout(showlegend=False, height=200, margin=dict(t=0,b=0), paper_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig, use_container_width=True)
            
            st.write(f"**DOMAIN_AGE:** {age} DAYS")
            st.write(f"**STRUCTURAL_DNA_RISK:** {dna_risk:.1f}%")
            st.markdown("</div>", unsafe_allow_html=True)

        with col_recon:
            st.markdown("### [ VISUAL_RECON ]")
            st.image(f"https://s0.wp.com/mshots/v1/{target}?w=400", use_container_width=True)
            
        st.divider()
        st.write("### [ RAW_TELEMETRY_STREAM ]")
        st.json(vt_stats)
