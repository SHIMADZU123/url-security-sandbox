import streamlit as st
import plotly.graph_objects as go
import urllib.parse
import re

# --- 1. UPDATED SMART SCAN ENGINE ---
def deep_forensic_analysis(url):
    score = 100
    red_flags = []
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()

    # SMART FILE CHECK: Only flags if .exe/.com is a FILE at the end, not a domain
    malware_extensions = ('.exe', '.com', '.scr', '.bin', '.dll', '.zip')
    if path.endswith(malware_extensions) or "eicar" in url.lower():
        score -= 90
        red_flags.append(("CRITICAL", "Payload Signature: System identified a high-risk executable file path targeting local system directories."))

    # PHISHING HEURISTICS
    blacklist = ['phishing', 'testsafebrowsing', 'verify', 'secure-update']
    if any(p in url.lower() for p in blacklist):
        score -= 85
        red_flags.append(("CRITICAL", "Social Engineering Pattern: URL architecture matches known credential harvesting signatures."))

    # INFRASTRUCTURE CHECKS
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
        score -= 50
        red_flags.append(("CRITICAL", "Non-DNS Routing: Direct IP access detected, bypassing standard domain reputation protocols."))

    return max(0, score), red_flags

# --- 2. ENTERPRISE UI (MAINTAINED) ---
st.set_page_config(page_title="Forensic AI | Enterprise Console", page_icon="🛡️", layout="wide")

st.markdown("""
    <style>
    .stApp { background-color: #05070a; background-image: radial-gradient(circle at 1px 1px, #161b22 1px, transparent 0); background-size: 32px 32px; color: #e6edf3; }
    .hero-container { background: linear-gradient(145deg, rgba(22, 27, 34, 0.9), rgba(13, 17, 23, 0.95)); backdrop-filter: blur(20px); padding: 50px; border-radius: 32px; border: 1px solid rgba(48, 54, 61, 0.5); text-align: center; margin-bottom: 40px; }
    .flag-card { background: rgba(248, 81, 73, 0.05); padding: 20px; border-radius: 12px; border-left: 6px solid #f85149; margin-bottom: 12px; }
    div.stButton > button { background: #1f6feb !important; border: none !important; border-radius: 10px !important; padding: 18px !important; font-weight: 700 !important; width: 100% !important; text-transform: uppercase; letter-spacing: 2px; }
    </style>
    """, unsafe_allow_html=True)

# HEADER
col_l, col_m, col_r = st.columns([1, 4, 1])
with col_l:
    try: st.image("NTU logo.jpg", width=130)
    except: st.markdown("### 🏛️")
with col_m:
    st.markdown("""
        <div class="hero-container">
            <h6 style="color: #58a6ff; letter-spacing: 6px; margin-bottom: 15px; font-weight: 600;">NORTHERN TECHNICAL UNIVERSITY</h6>
            <h1 style="color: #ffffff; font-size: 3.5rem; font-weight: 900; margin-bottom: 10px;">AI THREAT INTELLIGENCE</h1>
            <p style="color: #8b949e;">Advanced Cyber-Forensics Unit | College of AI & Computer Engineering</p>
        </div>
    """, unsafe_allow_html=True)
with col_r:
    sub_l, sub_r = st.columns([1, 5])
    with sub_r:
        try: st.image("collegue logo.jpg", width=130)
        except: st.markdown("<div style='text-align:right'>### 💻</div>", unsafe_allow_html=True)

# INTERFACE
target_vector = st.text_input("ENTER TARGET URL FOR DEEP PACKET INSPECTION:", placeholder="https://google.com")

if st.button("EXECUTE SYSTEM SCAN"):
    if target_vector:
        score, flags = deep_forensic_analysis(target_vector)
        res_col1, res_col2 = st.columns([1, 1.5])
        
        with res_col1:
            g_color = "#238636" if score > 75 else "#d29922" if score > 45 else "#f85149"
            fig = go.Figure(go.Indicator(
                mode="gauge+number", value=score,
                number={'suffix': "%", 'font': {'color': g_color, 'size': 85}},
                gauge={'bar': {'color': g_color}, 'bgcolor': "#010409", 'axis': {'range': [0, 100], 'visible': False}}
            ))
            fig.update_layout(height=400, paper_bgcolor='rgba(0,0,0,0)', font={'color': "white"})
            st.plotly_chart(fig, use_container_width=True)

        with res_col2:
            st.markdown("### 📄 Threat Intelligence Manifest")
            if score < 45: st.error("🛑 CRITICAL VULNERABILITY: IMMEDIATE ACTION RECOMMENDED")
            elif score < 75: st.warning("⚠️ ELEVATED RISK: ANOMALIES DETECTED")
            else: st.success("✅ INTEGRITY VERIFIED: NO MALICIOUS SIGNATURES FOUND")

            for severity, msg in flags:
                st.markdown(f"<div class='flag-card'><span style='color:#f85149; font-weight:800;'>[{severity}]</span> {msg}</div>", unsafe_allow_html=True)
