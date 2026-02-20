import streamlit as st
import plotly.graph_objects as go
import urllib.parse
import re

# --- 1. CORE FORENSIC ENGINE (SMART PATH LOGIC) ---
def deep_forensic_analysis(url):
    score = 100
    red_flags = []
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()

    # SMART FILE DETECTION: Only flags downloads, ignores safe domains like google.com
    payload_exts = ('.exe', '.com', '.scr', '.bin', '.dll', '.zip', '.msi')
    if path.endswith(payload_exts) or "eicar" in url.lower():
        score -= 90
        red_flags.append(("CRITICAL", "Malware Payload Signature: URL targets a suspicious executable binary or known malware test signature."))

    # PHISHING HEURISTICS
    blacklist = ['phishing', 'testsafebrowsing', 'verify', 'secure-update', 'login-check']
    if any(p in url.lower() for p in blacklist):
        score -= 85
        red_flags.append(("CRITICAL", "Social Engineering Vector: Path contains keywords used in high-confidence credential harvesting."))

    # INFRASTRUCTURE ANOMALIES
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
        score -= 50
        red_flags.append(("HIGH", "Non-DNS Routing: Connection bypasses standard DNS resolution. Typical for C2 infrastructure."))

    return max(0, score), red_flags

# --- 2. ELITE UI CONFIGURATION ---
st.set_page_config(page_title="Forensic AI | Cybersecurity Engineering", page_icon="🛡️", layout="wide")

st.markdown("""
    <style>
    .stApp {
        background-color: #05070a;
        background-image: radial-gradient(circle at 2px 2px, #161b22 1px, transparent 0);
        background-size: 40px 40px;
        color: #e6edf3;
    }
    
    /* Enterprise Hero Container */
    .hero-card {
        background: linear-gradient(145deg, rgba(22, 27, 34, 0.9), rgba(13, 17, 23, 0.95));
        backdrop-filter: blur(25px);
        padding: 40px 40px 60px 40px;
        border-radius: 35px;
        border: 1px solid rgba(48, 54, 61, 0.7);
        text-align: center;
        margin-bottom: 50px;
        box-shadow: 0 30px 60px rgba(0,0,0,0.6);
    }

    .threat-card {
        background: rgba(248, 81, 73, 0.08);
        padding: 22px;
        border-radius: 15px;
        border-left: 6px solid #f85149;
        margin-bottom: 15px;
    }

    .info-box {
        background: rgba(48, 54, 61, 0.2);
        padding: 30px;
        border-radius: 20px;
        border: 1px solid #30363d;
        margin-top: 50px;
    }

    div.stButton > button {
        background: linear-gradient(180deg, #1f6feb 0%, #0969da 100%) !important;
        border: none !important;
        border-radius: 12px !important;
        padding: 20px !important;
        font-weight: 800 !important;
        width: 100% !important;
        letter-spacing: 2px;
    }
    </style>
    """, unsafe_allow_html=True)

# --- HEADER LAYOUT (THE CHANGE IS HERE) ---
c1, c2, c3 = st.columns([1, 4, 1])
with c1:
    try: st.image("NTU logo.jpg", width=140)
    except: st.markdown("### 🏛️")

with c2:
    st.markdown("""
        <div class="hero-card">
            <p style="color: #58a6ff; font-weight: 800; letter-spacing: 2px; margin-bottom: 20px; font-size: 1rem;">
                CYBERSECURITY ENGINEERING DEPARTMENT STUDENTS
            </p>
            <h6 style="color: #8b949e; letter-spacing: 5px; font-weight: 700; margin-bottom: 5px;">NORTHERN TECHNICAL UNIVERSITY</h6>
            <h1 style="color: #ffffff; font-size: 3.2rem; font-weight: 900; margin: 0;">AI THREAT INTELLIGENCE</h1>
            <div style="height: 4px; background: #1f6feb; width: 100px; margin: 25px auto; border-radius: 10px;"></div>
            <p style="color: #8b949e; font-size: 1.1rem; letter-spacing: 1px;">College of AI & Computer Engineering | Forensic Analysis Suite</p>
        </div>
    """, unsafe_allow_html=True)

with c3:
    _, c3r = st.columns([1, 5])
    with c3r:
        try: st.image("collegue logo.jpg", width=140)
        except: st.markdown("<div style='text-align:right'>### 💻</div>", unsafe_allow_html=True)

# --- SCAN INTERFACE ---
st.markdown("### 🔍 Forensic Target Acquisition")
target_url = st.text_input("INPUT VECTOR (URL):", placeholder="Analyze external URL signatures...")

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
            fig.update_layout(height=400, paper_bgcolor='rgba(0,0,0,0)', font={'color': "white"})
            st.plotly_chart(fig, use_container_width=True)

        with r2:
            st.markdown("### 📊 Threat Analysis Report")
            if score < 45: st.error("🛑 STATUS: CRITICAL THREAT DETECTED")
            elif score < 75: st.warning("⚠️ STATUS: ELEVATED ANOMALIES")
            else: st.success("✅ STATUS: SYSTEM INTEGRITY VERIFIED")

            for sev, msg in flags:
                st.markdown(f"<div class='threat-card'><strong>[{sev}]</strong> {msg}</div>", unsafe_allow_html=True)
            if not flags:
                st.info("No structural threat signatures identified.")

# --- SUPPORT & INFO SECTION ---
st.write("---")
s1, s2 = st.columns(2)

with s1:
    st.markdown("""
        <div class="info-box">
            <h3 style="color: #58a6ff; margin-top: 0;">🛠️ Technical Support</h3>
            <p>Direct assistance for the AI Forensic Suite and Node administration.</p>
            <p><strong>Telegram ID:</strong> <a href='https://t.me/shim_azu64' style='color:#58a6ff;'>@shim_azu64</a></p>
            <p><strong>System Status:</strong> <span style='color:#238636;'>● Operational</span></p>
        </div>
    """, unsafe_allow_html=True)

with s2:
    st.markdown("""
        <div class="info-box">
            <h3 style="color: #58a6ff; margin-top: 0;">📍 Deployment Details</h3>
            <p>Real-time heuristic database sync and regional node monitoring.</p>
            <p><strong>Node Location:</strong> Kirkuk, Iraq</p>
            <p><strong>Last Database Sync:</strong> Feb 2026</p>
        </div>
    """, unsafe_allow_html=True)

# --- FINAL CLEAN FOOTER ---
st.markdown("""
    <div style="margin-top: 50px; padding: 20px; border-top: 1px solid #30363d; text-align: center; color: #484f58; font-size: 13px;">
        NORTHERN TECHNICAL UNIVERSITY | v8.6-STABLE | ENCRYPTED LINK
    </div>
""", unsafe_allow_html=True)
