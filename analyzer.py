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
    .report-card { background: rgba(13, 17, 23, 0.9); padding: 20px; border-radius: 12px; border: 1px solid #1f6feb; margin-bottom: 20px; }
    .glow-text { color: #58a6ff; text-shadow: 0 0 12px rgba(88, 166, 255, 0.6); font-family: 'Courier New', monospace; }
    </style>
    """, unsafe_allow_html=True)

# --- [RESILIENT PDF ENGINE] ---
class ThreatReport(FPDF):
    def header(self):
        self.set_font("helvetica", "B", 18)
        self.set_text_color(31, 111, 235)
        self.cell(0, 10, "VORTEX SENTINEL: INTEL REPORT", ln=True, align="C")
        self.ln(10)

def generate_pdf(url, risk, stats, age, creation):
    pdf = ThreatReport()
    pdf.add_page()
    pdf.set_font("helvetica", size=12)
    pdf.cell(0, 10, f"Target URL: {url}", ln=True)
    pdf.cell(0, 10, f"Risk Probability: {risk:.1f}%", ln=True)
    pdf.cell(0, 10, f"Domain Chronology: {age} Days (Registered: {creation})", ln=True)
    pdf.ln(10)
    pdf.set_font("helvetica", "B", 14)
    pdf.cell(0, 10, "Engine Analysis Data:", ln=True)
    pdf.set_font("helvetica", size=11)
    for key, val in stats.items():
        pdf.cell(0, 8, f"> {key.capitalize()}: {val}", ln=True)
    return pdf.output() # Outputting as bytes/bytearray

# --- [MAIN APP LOGIC] ---
st.title("⚡ VORTEX SENTINEL")
st.markdown("<h3 class='glow-text'>NEXUS-7 Command Terminal</h3>", unsafe_allow_html=True)

# Get API Key Safely
API_KEY = st.secrets.get("VT_API_KEY")
if not API_KEY:
    st.error("🔑 ERROR: VT_API_KEY not found in Streamlit Secrets.")
    st.stop()

target_url = st.text_input("📡 INPUT TARGET FREQUENCY (URL):", placeholder="https://")

if st.button("RUN NEURAL BYPASS SCAN") and target_url:
    # --- PHASE 1: NEURAL ANIMATION ---
    progress = st.progress(0)
    status_label = st.empty()
    stages = ["Infiltrating Domain...", "Bypassing Handshakes...", "Harvesting Intel..."]
    
    for i, s in enumerate(stages):
        status_label.text(f"CORE: {s}")
        progress.progress((i + 1) * 33)
        time.sleep(0.5)

    # --- PHASE 2: INTEL HARVEST (WITH ERROR BYPASS) ---
    vt_data, age, create_str = None, "REDACTED", "REDACTED"
    
    # VirusTotal API Check
    try:
        url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
        res = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers={"x-apikey": API_KEY})
        if res.status_code == 200: vt_data = res.json()
    except Exception as e:
        st.sidebar.error(f"API Error: {e}")

    # WHOIS Domain Age Check (Heavily protected against timeouts)
    try:
        ext = extract(target_url)
        w = whois.whois(f"{ext.domain}.{ext.suffix}")
        creation = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        age = (datetime.now() - creation).days
        create_str = creation.strftime('%Y-%m-%d')
    except:
        pass # Silently bypass WHOIS failures to keep app alive

    # --- PHASE 3: THE GOD-DASHBOARD ---
    if vt_data:
        stats = vt_data['data']['attributes']['last_analysis_stats']
        risk = (stats['malicious'] / sum(stats.values())) * 100 if sum(stats.values()) > 0 else 0
        
        col_metrics, col_gauge = st.columns([1, 1])
        with col_metrics:
            st.metric("THREAT VECTOR", f"{stats['malicious']} Engines", delta="CRITICAL" if stats['malicious'] > 0 else "CLEAN", delta_color="inverse")
            st.metric("CHRONOLOGY", f"{age} Days", help="Younger domains (<30 days) are high-risk.")
            
            # --- THE FIXED DOWNLOAD BUTTON ---
            pdf_raw = generate_pdf(target_url, risk, stats, age, create_str)
            st.download_button(
                label="📥 DOWNLOAD INTEL REPORT",
                data=bytes(pdf_raw),  # <--- CRITICAL FIX: CONVERT TO BYTES
                file_name=f"SENTINEL_REPORT_{int(time.time())}.pdf",
                mime="application/pdf"
            )

        with col_gauge:
            fig = go.Figure(go.Indicator(
                mode="gauge+number", value=risk,
                gauge={'axis': {'range': [0, 100]}, 'bar': {'color': "#1f6feb"},
                       'steps': [{'range': [0, 20], 'color': "green"}, {'range': [20, 50], 'color': "orange"}, {'range': [50, 100], 'color': "red"}]}
            ))
            fig.update_layout(height=250, paper_bgcolor="rgba(0,0,0,0)", font={'color': "white"})
            st.plotly_chart(fig, use_container_width=True)

        # Secure Visual Preview
        st.markdown("### 🖼️ VISUAL RECONNAISSANCE")
        try:
            st.image(f"https://s0.wp.com/mshots/v1/{target_url}?w=800", caption="Remote Sandbox View (Safe Render)")
        except:
            st.warning("Visual Reconnaissance offline for this node.")
