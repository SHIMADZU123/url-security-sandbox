import streamlit as st
import requests
import base64
import whois
import time
import plotly.graph_objects as go
from fpdf import FPDF
from datetime import datetime
from tldextract import extract

# --- [GOD-MODE DESIGN] ---
st.set_page_config(page_title="VORTEX SENTINEL | NEXUS-7", layout="wide")

st.markdown("""
    <style>
    .stApp { background: #05070a; color: #e0e0e0; }
    .stMetric { background: #0d1117; border: 1px solid #1f6feb; border-radius: 10px; }
    .report-card { background: rgba(13, 17, 23, 0.8); padding: 25px; border-radius: 15px; border: 1px solid #30363d; }
    .glow-text { color: #58a6ff; text-shadow: 0 0 10px rgba(88, 166, 255, 0.5); }
    </style>
    """, unsafe_allow_html=True)

# --- [PDF ENGINE] ---
class ThreatReport(FPDF):
    def header(self):
        self.set_font("helvetica", "B", 20)
        self.set_text_color(31, 111, 235)
        self.cell(0, 10, "VORTEX SENTINEL: INTELLIGENCE REPORT", ln=True, align="C")
        self.ln(10)

def generate_pdf(url, risk, stats, age, creation):
    pdf = ThreatReport()
    pdf.add_page()
    pdf.set_font("helvetica", size=12)
    
    # Report Meta
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 10, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
    pdf.ln(5)
    
    # Executive Summary
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("helvetica", "B", 16)
    pdf.cell(0, 10, f"Target: {url}", ln=True)
    pdf.set_font("helvetica", size=12)
    pdf.cell(0, 10, f"Risk Score: {risk:.2f}%", ln=True)
    pdf.cell(0, 10, f"Domain Age: {age} days (Registered: {creation})", ln=True)
    pdf.ln(10)
    
    # Engine Details
    pdf.set_font("helvetica", "B", 14)
    pdf.cell(0, 10, "Engine Detection Breakdown:", ln=True)
    pdf.set_font("helvetica", size=12)
    for key, val in stats.items():
        pdf.cell(0, 10, f"- {key.capitalize()}: {val}", ln=True)
    
    return pdf.output()

# --- [SCAN LOGIC] ---
def fetch_vt(url, key):
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    res = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers={"x-apikey": key})
    return res.json() if res.status_code == 200 else None

# --- [MAIN INTERFACE] ---
st.title("⚡ VORTEX SENTINEL")
st.markdown("<h3 class='glow-text'>NEXUS-7 Command Interface</h3>", unsafe_allow_html=True)

try:
    API_KEY = st.secrets["VT_API_KEY"]
except:
    st.error("🔑 SECURITY BREACH: VT_API_KEY missing in Secrets.")
    st.stop()

target_url = st.text_input("📡 INSERT TARGET OSCILLATION (URL):")

if st.button("EXECUTE NEURAL BYPASS SCAN") and target_url:
    # 1. THE NEURAL ANIMATION
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    stages = [
        "Infiltrating Domain Layer...", 
        "Bypassing SSL Handshake...", 
        "Decrypting Threat Vectors...", 
        "Finalizing Intelligence Synthesis..."
    ]
    
    for i, stage in enumerate(stages):
        status_text.text(f"SYSTEM: {stage}")
        progress_bar.progress((i + 1) * 25)
        time.sleep(0.6)
    
    # 2. DATA ACQUISITION
    vt_data = fetch_vt(target_url, API_KEY)
    ext = extract(target_url)
    try:
        w = whois.whois(f"{ext.domain}.{ext.suffix}")
        creation = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        age = (datetime.now() - creation).days
        create_str = creation.strftime('%Y-%m-%d')
    except:
        age, create_str = "Unknown", "Unknown"

    if vt_data:
        stats = vt_data['data']['attributes']['last_analysis_stats']
        risk = (stats['malicious'] / sum(stats.values())) * 100 if sum(stats.values()) > 0 else 0
        
        # --- DASHBOARD ---
        st.divider()
        col1, col2 = st.columns([1, 1])
        
        with col1:
            st.markdown("### 📊 RISK METRIC")
            fig = go.Figure(go.Indicator(
                mode="gauge+number", value=risk,
                gauge={'axis': {'range': [0, 100]}, 'bar': {'color': "#1f6feb"}}
            ))
            fig.update_layout(height=250, paper_bgcolor="rgba(0,0,0,0)", font={'color':"white"})
            st.plotly_chart(fig, use_container_width=True)

        with col2:
            st.markdown("### 🧬 DOMAIN BIOMETRICS")
            st.metric("CHRONOLOGY", f"{age} Days", delta="New Domain" if str(age).isdigit() and int(age) < 365 else None)
            st.metric("MALICIOUS HITS", f"{stats['malicious']} Engines")
            
            # --- THE GOD-MODE REPORT BUTTON ---
            pdf_bytes = generate_pdf(target_url, risk, stats, age, create_str)
            st.download_button(
                label="📥 DOWNLOAD INTEL REPORT (PDF)",
                data=pdf_bytes,
                file_name=f"VORTEX_REPORT_{int(time.time())}.pdf",
                mime="application/pdf"
            )

        # 3. VISUAL RECON
        st.markdown("### 🖼️ SECURE VISUAL PREVIEW")
        st.image(f"https://s0.wp.com/mshots/v1/{target_url}?w=800", use_container_width=True)
