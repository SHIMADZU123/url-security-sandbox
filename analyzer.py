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

# --- [1. GHOST-OS DESIGN SYSTEM] ---
st.set_page_config(page_title="VORTEX // GHOST-OS", layout="wide", page_icon="💀")

st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@100;400&display=swap');
    * { font-family: 'JetBrains Mono', monospace; }
    .stApp { background: #050505; color: #00ff41; } 
    .stMetric { border: 1px solid #333; background: #0a0a0a; padding: 15px; border-radius: 0px; }
    .critical-glow { border: 1px solid #ff0000; box-shadow: 0 0 20px rgba(255, 0, 0, 0.4); padding: 20px; color: #ff0000; }
    .terminal-header { color: #555; font-size: 0.8em; margin-bottom: 20px; }
    </style>
    """, unsafe_allow_html=True)

# --- [2. ADVANCED HEURISTIC KERNEL] ---

def deep_path_inspection(url):
    """Detects 'Infrastructure Abuse' - Phishing hosted on safe platforms."""
    danger_keywords = ["phishing", "login", "verify", "secure", "account", "signin", "banking"]
    platform_domains = ["appspot.com", "github.io", "firebaseapp.com", "vercel.app", "pages.dev", "s3.amazonaws.com"]
    
    ext = extract(url)
    root = f"{ext.domain}.{ext.suffix}"
    warnings = []
    
    # Check for keywords in the path
    for word in danger_keywords:
        if word in url.lower():
            warnings.append(f"DETECTED: Path-based keyword '{word.upper()}'")
            
    # Platform Abuse Check: If a "Safe" domain is used to host "Danger" words
    if root in platform_domains and any(w in url.lower() for w in danger_keywords):
        warnings.append(f"CRITICAL: Infrastructure Abuse on {root.upper()}")
        
    return warnings

def generate_pdf(url, risk, stats, age):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Courier", 'B', 16)
    pdf.cell(0, 10, "VORTEX GHOST-OS: INTEL REPORT", ln=True, align='C')
    pdf.set_font("Courier", size=12)
    pdf.ln(10)
    pdf.cell(0, 10, f"Target: {url}", ln=True)
    pdf.cell(0, 10, f"Final Risk Score: {risk:.1f}%", ln=True)
    pdf.cell(0, 10, f"Domain Age: {age} Days", ln=True)
    return pdf.output()

# --- [3. MAIN OPERATING SYSTEM] ---
st.markdown("<div class='terminal-header'>SECURE_TERMINAL // BOOT_SEQUENCE_COMPLETE</div>", unsafe_allow_html=True)
st.markdown("<h1 style='letter-spacing: -2px;'>VORTEX // <span style='color:white;'>GHOST.OS</span></h1>", unsafe_allow_html=True)

# Secure API Key
API_KEY = st.secrets.get("VT_API_KEY")

# Input - We define 'target' here first!
target = st.text_input(">> [ENTER_TARGET_STRING]:", placeholder="https://example.com")

if st.button("EXECUTE_DECONSTRUCTION") and target:
    with st.status("Initializing Neural Bypass...", expanded=True) as status:
        # 1. Path & Subdomain Inspection (THE FIX FOR THE 'STABLE' ERROR)
        path_threats = deep_path_inspection(target)
        
        # 2. VirusTotal Intelligence
        url_id = base64.urlsafe_b64encode(target.encode()).decode().strip("=")
        vt_res = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers={"x-apikey": API_KEY})
        
        # 3. Domain Chronology
        try:
            domain_info = whois.whois(extract(target).registered_domain)
            creation = domain_info.creation_date[0] if isinstance(domain_info.creation_date, list) else domain_info.creation_date
            age_days = (datetime.now() - creation).days
        except: age_days = "UNKNOWN"
        
        status.update(label="DECONSTRUCTION_COMPLETE", state="complete")

    # --- [4. THE PHANTOM HUD] ---
    if vt_res.status_code == 200:
        stats = vt_res.json()['data']['attributes']['last_analysis_stats']
        base_risk = (stats['malicious'] / sum(stats.values())) * 100 if sum(stats.values()) > 0 else 0
        
        # THE OVERRIDE: If path_threats exist, the score is 100 regardless of the domain
        final_score = 100 if path_threats else base_risk

        if final_score > 50:
            st.markdown(f"""
            <div class='critical-glow'>
                <h3>🚨 SYSTEM_VERDICT: MALICIOUS</h3>
                <p>Threat detected in URL architecture or global databases.</p>
                <ul>{"".join(f"<li>{t}</li>" for t in path_threats)}</ul>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.success("🟢 SYSTEM_VERDICT: STABLE")

        st.divider()
        
        col1, col2, col3 = st.columns(3)
        col1.metric("THREAT_INDEX", f"{final_score:.1f}%", delta="HIGH_RISK" if final_score > 0 else None, delta_color="inverse")
        col2.metric("DOMAIN_AGE", f"{age_days} DAYS")
        
        # PDF Fix included
        pdf_out = generate_pdf(target, final_score, stats, age_days)
        col3.download_button("📥 DOWNLOAD_INTEL", data=bytes(pdf_out), file_name="phantom_intel.pdf")

        # Visual Recon
        st.markdown("### [ VISUAL_RECON ]")
        st.image(f"https://s0.wp.com/mshots/v1/{target}?w=800", caption="Remote Sandbox View")
    else:
        st.error("API_FAILURE: Check your VirusTotal key or connection.")
