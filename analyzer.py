import streamlit as st
import plotly.graph_objects as go
import urllib.parse
import re

# --- 1. CORE FORENSIC ENGINE (WITH SHORT LINK DETECTION) ---
def deep_forensic_analysis(url):
    score = 100
    red_flags = []
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()

    # 🚨 NEW: SHORTENED LINK DETECTION
    shortener_domains = [
        'bit.ly', 'tinyurl.com', 't.co', 'rb.gy', 'is.gd', 
        'buff.ly', 'goo.gl', 'ow.ly', 'rebrand.ly'
    ]
    if any(s in domain for s in shortener_domains):
        score -= 60
        red_flags.append(("HIGH RISK", "URL Masking Detected: This is a shortened link. The final destination is hidden, which is a common tactic for bypassing security filters."))

    # SMART FILE DETECTION
    payload_exts = ('.exe', '.com', '.scr', '.bin', '.dll', '.zip', '.msi')
    if path.endswith(payload_exts) or "eicar" in url.lower():
        score -= 90
        red_flags.append(("CRITICAL", "Malware Payload Signature: URL targets a suspicious executable binary or test signature."))

    # PHISHING HEURISTICS
    blacklist = ['phishing', 'testsafebrowsing', 'verify', 'secure-update', 'login-check']
    if any(p in url.lower() for p in blacklist):
        score -= 85
        red_flags.append(("CRITICAL", "Social Engineering Vector: High-confidence phishing keywords identified in path."))

    return max(0, score), red_flags

# --- 2. ELITE UI CONFIGURATION ---
st.set_page_config(page_title="Forensic AI | NTU", page_icon="🛡️", layout="wide")

st.markdown("""
    <style>
    .stApp { background-color: #05070a; color: #e6edf3; }
    .hero-card {
        background: linear-gradient(145deg, rgba(22, 27, 34, 0.9), rgba(13, 17, 23, 0.95));
        padding: 50px; border-radius: 35px; border: 1px solid rgba(48, 54, 61, 0.7);
        text-align: center; margin-bottom: 50px;
    }
    .threat-card {
        background: rgba(248, 81, 73, 0.08); padding: 22px;
        border-radius: 15px; border-left: 6px solid #f85149; margin-bottom: 15px;
    }
    div.stButton > button {
        background: linear-gradient(180deg, #1f6feb 0%, #0969da 100%) !important;
        border-radius: 12px !important; padding: 20px !important; color: white !important;
    }
    </style>
    """, unsafe_allow_html=True)

# --- HEADER LAYOUT ---
c1, c2, c3 = st.columns([1, 4, 1])
with c1:
    try: st.image("NTU logo.jpg", width=140)
    except: st.markdown("### 🏛️")

with c2:
    st.markdown("""
        <div class="hero-card">
            <p style="color: #58a6ff; font-weight: 700; letter-spacing: 1px; margin-bottom: 10px;">
                <span style="font-size: 1.3rem;">C</span>ybersecurity <span style="font-size: 1.3rem;">E</span>ngineering <span style="font-size: 1.3rem;">D</span>epartment <span style="font-size: 1.3rem;">S</span>tudents 
                <span style="color: #8b949e; margin-left: 15px; font-weight: 400;">| College of AI & Computer Engineering</span>
            </p>
            
            <h6 style="color: #8b949e; letter-spacing: 5px; font-weight: 700; margin-bottom: 5px;">NORTHERN TECHNICAL UNIVERSITY</h6>
            <h1 style="color: #ffffff; font-size: 3.5rem; font-weight: 900; margin: 0;">AI THREAT INTELLIGENCE</h1>
            <div style="height: 4px; background: #1f6feb; width: 80px; margin: 20px auto; border-radius: 10px;"></div>
        </div>
    """, unsafe_allow_html=True)

with c3:
    try: st.image("collegue logo.jpg", width=140)
    except: st.markdown("### 💻")

# --- INTERFACE ---
st.markdown("### 🔍 Forensic Command Console")
target_url = st.text_input("INPUT VECTOR (URL):", placeholder="Paste URL here (e.g., bit.ly link or direct domain)...")

if st.button("EXECUTE SYSTEM SCAN"):
    if target_url:
        score, flags = deep_forensic_analysis(target_url)
        st.divider()
        r1, r2 = st.columns([1, 1.5])
        
        with r1:
            color = "#238636" if score > 75 else "#d29922" if score > 45 else "#f85149"
            fig = go.Figure(go.Indicator(
                mode="gauge+number", value=score,
                number={'suffix': "%", 'font': {'color': color, 'size': 80}},
                gauge={'bar': {'color': color}, 'bgcolor': "#010409", 'axis': {'range': [0, 100], 'visible': False}}
            ))
            fig.update_layout(height=350, paper_bgcolor='rgba(0,0,0,0)', font={'color': "white"})
            st.plotly_chart(fig, use_container_width=True)

        with r2:
            st.markdown("### 📊 Forensic Investigation Report")
            if score < 45: st.error("🛑 STATUS: CRITICAL THREAT DETECTED")
            elif score < 75: st.warning("⚠️ STATUS: ELEVATED ANOMALIES")
            else: st.success("✅ STATUS: SYSTEM INTEGRITY VERIFIED")

            for sev, msg in flags:
                st.markdown(f"<div class='threat-card'><strong>[{sev}]</strong> {msg}</div>", unsafe_allow_html=True)
