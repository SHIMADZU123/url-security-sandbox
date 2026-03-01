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

# --- [1. DESIGN SYSTEM] ---
st.set_page_config(page_title="VORTEX PHANTOM", layout="wide", page_icon="🛡️")

st.markdown("""
    <style>
    .stApp { background: #020408; color: #d0d7de; }
    .stMetric { background: #0d1117; border: 1px solid #238636; border-radius: 8px; padding: 10px; }
    .header-badge { background: #1f6feb; color: white; padding: 4px 12px; border-radius: 20px; font-size: 0.8em; }
    .glow-alert { border: 1px solid #f85149; box-shadow: 0 0 15px rgba(248, 81, 73, 0.3); padding: 15px; border-radius: 10px; }
    </style>
    """, unsafe_allow_html=True)

# --- [2. CORE INTELLIGENCE UNITS] ---

def get_security_headers(url):
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        checks = {
            "HSTS": "Strict-Transport-Security" in headers,
            "XSS Protection": "X-XSS-Protection" in headers,
            "Frame Protection": "X-Frame-Options" in headers
        }
        return checks
    except: return None

def check_spoofing(url):
    brands = ["microsoft", "google", "amazon", "apple", "facebook", "paypal", "netflix", "bankofamerica"]
    domain = extract(url).domain.lower()
    if domain in brands: return None
    for b in brands:
        if 1 <= Levenshtein.distance(domain, b) <= 2: return b
    return None

def fetch_vt(url, key):
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    res = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers={"x-apikey": key})
    return res.json() if res.status_code == 200 else None

# --- [3. PDF ENGINE (STABLE)] ---
class PhantomReport(FPDF):
    def header(self):
        self.set_font("helvetica", "B", 20); self.set_text_color(31, 111, 235)
        self.cell(0, 10, "PHANTOM INTEL REPORT", ln=True, align="C"); self.ln(10)

def generate_pdf(url, risk, stats, age):
    pdf = PhantomReport()
    pdf.add_page(); pdf.set_font("helvetica", size=12)
    pdf.cell(0, 10, f"Target: {url}", ln=True)
    pdf.cell(0, 10, f"Risk Score: {risk:.2f}%", ln=True)
    pdf.cell(0, 10, f"Domain Age: {age} Days", ln=True)
    pdf.ln(10); pdf.set_font("helvetica", "B", 14); pdf.cell(0, 10, "Detection Details:", ln=True)
    for k, v in stats.items(): pdf.cell(0, 8, f"- {k}: {v}", ln=True)
    return pdf.output()

# --- [4. MAIN INTERFACE] ---
st.markdown("<h1>🛡️ VORTEX <span style='color:#1f6feb'>PHANTOM</span></h1>", unsafe_allow_html=True)
st.markdown("<span class='header-badge'>VERSION 2026.4</span>", unsafe_allow_html=True)

API_KEY = st.secrets.get("VT_API_KEY")
if not API_KEY:
    st.error("🔑 API KEY MISSING: Add VT_API_KEY to Secrets.")
    st.stop()

target = st.text_input("📡 TARGET OSCILLATION (URL):", placeholder="https://")

if st.button("⚡ EXECUTE NEURAL BYPASS") and target:
    with st.status("Analyzing Site DNA...", expanded=True) as status:
        # Step 1: Brand Similarity
        spoof = check_spoofing(target)
        
        # Step 2: Security Headers
        headers = get_security_headers(target)
        
        # Step 3: Global Threat Intel
        vt_data = fetch_vt(target, API_KEY)
        
        # Step 4: Domain Age
        try:
            domain_info = whois.whois(extract(target).registered_domain)
            creation = domain_info.creation_date[0] if isinstance(domain_info.creation_date, list) else domain_info.creation_date
            age_days = (datetime.now() - creation).days
        except: age_days = "Unknown"
        
        status.update(label="ANALYSIS COMPLETE", state="complete")

    # --- RESULTS DISPLAY ---
    if vt_data:
        stats = vt_data['data']['attributes']['last_analysis_stats']
        risk = (stats['malicious'] / sum(stats.values())) * 100 if sum(stats.values()) > 0 else 0

        # Brand Alert
        if spoof:
            st.markdown(f"<div class='glow-alert'>🚨 <b>CRITICAL:</b> This URL is a lookalike of <b>{spoof.upper()}</b>!</div>", unsafe_allow_html=True)

        col1, col2, col3 = st.columns([1, 1, 1])
        with col1:
            st.metric("Risk Level", f"{risk:.1f}%")
            # PDF Report Fix
            pdf_bytes = generate_pdf(target, risk, stats, age_days)
            st.download_button("📥 DOWNLOAD INTEL", data=bytes(pdf_bytes), file_name="intel_report.pdf")
        
        with col2:
            st.metric("Domain Age", f"{age_days} Days")
            if str(age_days).isdigit() and int(age_days) < 90: st.warning("Extreme Risk: Domain is brand new.")

        with col3:
            st.markdown("<b>Security Headers:</b>", unsafe_allow_html=True)
            if headers:
                for h, active in headers.items():
                    st.write(f"{'✅' if active else '❌'} {h}")

        st.divider()
        
        # Favicon + Visual Preview
        c_icon, c_preview = st.columns([1, 4])
        with c_icon:
            st.markdown("### 🧬 Favicon")
            st.image(f"https://www.google.com/s2/favicons?domain={target}&sz=64")
        with c_preview:
            st.markdown("### 🖼️ Visual Recon")
            st.image(f"https://s0.wp.com/mshots/v1/{target}?w=800")
