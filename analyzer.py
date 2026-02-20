import streamlit as st
import plotly.graph_objects as go
import urllib.parse
import re

# --- 1. CORE FORENSIC ENGINE (WITH SHORT LINK & MALWARE DETECTION) ---
def deep_forensic_analysis(url):
    score = 100
    red_flags = []
    
    # Standardize URL
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()

    # 🚨 SHORTENED LINK DETECTION (Neutralizing the 100% bug)
    shortener_list = ['bit.ly', 'tinyurl.com', 't.co', 'rebrand.ly', 'is.gd', 'buff.ly', 'ow.ly']
    if any(s in domain for s in shortener_list):
        score -= 70
        red_flags.append(("HIGH RISK", "URL Masking Detected: Shortened links hide the final destination, a common tactic for phishing."))

    # MALWARE PAYLOAD DETECTION
    payload_exts = ('.exe', '.com', '.scr', '.bin', '.dll', '.zip', '.msi')
    if path.endswith(payload_exts) or "eicar" in url.lower():
        score -= 90
        red_flags.append(("CRITICAL", "Malware Payload: System identified suspicious executable binary extensions in the target path."))

    # PHISHING & SOCIAL ENGINEERING HEURISTICS
    phish_keywords = ['phishing', 'verify', 'login-check', 'secure-update', 'account-support']
    if any(p in url.lower() for p in phish_keywords):
        score -= 80
        red_flags.append(("CRITICAL", "Social Engineering: High-confidence phishing keywords detected in URL structure."))

    return max(0, score), red_flags

# --- 2. ELITE UI CONFIGURATION ---
st.set_page_config(page_title="Forensic AI | NTU", page_icon="🛡️", layout="wide")

# Load Bootstrap Icons for professional "SOC" vibe
st.markdown('<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css">', unsafe_allow_html=True)

st.markdown("""
    <style>
    .stApp { background-color: #05070a; color: #e6edf3; }
    
    /* Hero Card Styling */
    .hero-card {
        background: linear-gradient(145deg, rgba(22, 27, 34, 0.9), rgba(13, 17, 23, 0.95));
        padding: 40px; border-radius: 35px; border: 1px solid rgba(48, 54, 61, 0.7);
        text-align: center; margin-bottom: 40px;
    }
    
    /* Neural Terminal Styling */
    .terminal-header {
        display: flex; align-items: center; gap: 12px;
        background: rgba(31, 111, 235, 0.1);
        padding: 15px 25px; border-radius: 15px 15px 0 0;
        border: 1px solid rgba(31, 111, 235, 0.3); border-bottom: none;
    }
    .terminal-title {
        font-family: 'Courier New', monospace; font-weight: 800;
        letter-spacing: 2px; color: #58a6ff; text-transform: uppercase;
    }
    .stTextInput input {
        background-color: #0d1117 !important; border: 1px solid #30363d !important;
        color: #58a6ff !important; font-family: 'Courier New', monospace !important;
        border-radius: 0 0 15px 15px !important; padding: 20px !important;
    }
    .stTextInput input:focus { border-color: #58a6ff !important; box-shadow: 0 0 15px rgba(88, 166, 255, 0.2) !important; }

    /* Action Button */
    div.stButton > button {
        background: linear-gradient(90deg, #1f6feb 0%, #0969da 100%) !important;
        border-radius: 12px !important; color: white !important; width: 100%;
        font-weight: 800 !important; letter-spacing: 1.5px !important; border: none !important;
        padding: 15px !important; text-transform: uppercase; transition: 0.4s ease;
    }
    div.stButton > button:hover { transform: translateY(-2px); box-shadow: 0 5px 20px rgba(31, 111, 235, 0.4); }

    /* Professional Info Boxes */
    .info-box {
        background: rgba(22, 27, 34, 0.5); padding: 25px;
        border-radius: 20px; border: 1px solid #30363d; height: 100%;
        transition: 0.3s ease;
    }
    .info-box:hover { border-color: #58a6ff; background: rgba(48, 54, 61, 0.2); }
    .threat-card {
        background: rgba(248, 81, 73, 0.08); padding: 18px;
        border-radius: 12px; border-left: 5px solid #f85149; margin-bottom: 10px;
    }
    </style>
    """, unsafe_allow_html=True)

# --- 3. HEADER SECTION (FIXED ATTRIBUTEERROR) ---
c1, c2, c3 = st.columns([1, 4, 1])

with c1:
    try: st.image("NTU logo.jpg", width=120)
    except: st.markdown("### 🏛️")

with c2:
    st.markdown(f"""
        <div class="hero-card">
            <p style="color: #58a6ff; font-weight: 700; margin-bottom: 12px;">
                <span style="font-size: 1.25rem;">C</span>ybersecurity 
                <span style="font-size: 1.25rem;">E</span>ngineering 
                <span style="font-size: 1.25rem;">D</span>epartment 
                <span style="font-size: 1.25rem;">S</span>tudents 
                <span style="color: #8b949e; font-weight: 400; margin-left: 10px;">| College of AI & Computer Engineering</span>
            </p>
            <h6 style="color: #8b949e; letter-spacing: 5px; font-weight: 700; margin-bottom: 5px;">NORTHERN TECHNICAL UNIVERSITY</h6>
            <h1 style="color: #ffffff; font-size: 3.2rem; font-weight: 900; margin: 0;">AI THREAT INTELLIGENCE</h1>
            <div style="height: 4px; background: #1f6feb; width: 70px; margin: 20px auto; border-radius: 10px;"></div>
        </div>
    """, unsafe_allow_html=True)

with c3:
    try: st.image("collegue logo.jpg", width=120)
    except: st.markdown("### 💻")

# --- 4. NEURAL LINK ANALYSIS TERMINAL ---
st.markdown("""
    <div class="terminal-header">
        <i class="bi bi-cpu-fill" style="color: #58a6ff; font-size: 1.5rem;"></i>
        <span class="terminal-title">Neural Link Analysis Terminal v2.0</span>
    </div>
""", unsafe_allow_html=True)

target_url = st.text_input("INPUT", label_visibility="collapsed", placeholder="SYSTEM READY: Input Target Vector (URL) for Deep Forensic Inspection...")

col_btn, _ = st.columns([1, 2])
with col_btn:
    scan_triggered = st.button("▶ INITIALIZE NEURAL SCAN")

if scan_triggered:
    if target_url:
        score, flags = deep_forensic_analysis(target_url)
        st.divider()
        
        r1, r2 = st.columns([1, 1.5])
        with r1:
            color = "#238636" if score > 75 else "#d29922" if score > 45 else "#f85149"
            fig = go.Figure(go.Indicator(
                mode="gauge+number", value=score,
                number={'suffix': "%", 'font': {'color': color, 'size': 70}},
                gauge={'bar': {'color': color}, 'bgcolor': "#010409", 'axis': {'range': [0, 100], 'visible': False}}
            ))
            fig.update_layout(height=320, paper_bgcolor='rgba(0,0,0,0)', font={'color': "white"}, margin=dict(t=0,b=0))
            st.plotly_chart(fig, use_container_width=True)
            
        with r2:
            st.markdown("### 📊 Forensic Intelligence Manifest")
            if score < 45: st.error("🛑 STATUS: CRITICAL THREAT IDENTIFIED")
            elif score < 75: st.warning("⚠️ STATUS: ELEVATED ANOMALIES DETECTED")
            else: st.success("✅ STATUS: INTEGRITY VERIFIED")

            for sev, msg in flags:
                st.markdown(f"<div class='threat-card'><strong>[{sev}]</strong> {msg}</div>", unsafe_allow_html=True)
            if not flags:
                st.info("System integrity check complete. No known heuristic anomalies detected.")

# --- 5. SYSTEM INFO FOOTER ---
st.write("<br>", unsafe_allow_html=True)
s1, s2 = st.columns(2)

with s1:
    st.markdown("""
        <div class="info-box">
            <div style="display:flex; align-items:center; gap:12px; color:#58a6ff; margin-bottom:15px;">
                <i class="bi bi-shield-lock-fill" style="font-size:1.5rem;"></i>
                <span style="font-weight:700; text-transform:uppercase;">Technical Support</span>
            </div>
            <p style="color:#8b949e; font-size:0.9rem;">Direct SOC administration and regional node support.</p>
            <strong>Telegram ID:</strong> <a href="https://t.me/shim_azu64" style="color:#58a6ff; text-decoration:none;">@shim_azu64</a><br>
            <strong>System ID:</strong> <code style="color:#79c0ff;">NTU-AI-64-STABLE</code><br>
            <strong>Status:</strong> <span style="color:#3fb950;">● Operational</span>
        </div>
    """, unsafe_allow_html=True)

with s2:
    st.markdown("""
        <div class="info-box">
            <div style="display:flex; align-items:center; gap:12px; color:#58a6ff; margin-bottom:15px;">
                <i class="bi bi-geo-alt-fill" style="font-size:1.5rem;"></i>
                <span style="font-weight:700; text-transform:uppercase;">Deployment Details</span>
            </div>
            <p style="color:#8b949e; font-size:0.9rem;">Regional edge computing node and database synchronicity.</p>
            <strong>Node Location:</strong> <span style="color:#d29922;">Kirkuk, Iraq</span><br>
            <strong>Database Sync:</strong> <span style="color:#8b949e;">Feb 2026</span><br>
            <strong>Network:</strong> <span style="color:#8b949e;">NTU-Private-Cloud</span>
        </div>
    """, unsafe_allow_html=True)

st.markdown("<br><center style='color: #484f58; font-size: 11px; letter-spacing: 2px;'>NORTHERN TECHNICAL UNIVERSITY | CYBERSECURITY ENGINEERING DEPARTMENT STUDENTS</center>", unsafe_allow_html=True)
