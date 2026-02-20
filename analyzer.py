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

    # URL SHORTENER DETECTION
    shortener_list = ['bit.ly', 'tinyurl.com', 't.co', 'rebrand.ly', 'is.gd', 'buff.ly']
    if any(s in domain for s in shortener_list):
        score -= 70
        red_flags.append(("HIGH RISK", "URL Masking Detected: Shortened links are frequently used to hide malicious destinations."))

    # MALWARE & PHISHING HEURISTICS
    payload_exts = ('.exe', '.com', '.scr', '.bin', '.dll', '.zip', '.msi')
    if path.endswith(payload_exts) or "eicar" in url.lower():
        score -= 90
        red_flags.append(("CRITICAL", "Malware Payload: URL targets a suspicious binary executable or test signature."))

    if any(p in url.lower() for p in ['phishing', 'verify', 'login-check', 'secure-update']):
        score -= 80
        red_flags.append(("CRITICAL", "Social Engineering: High-confidence phishing keywords detected in path."))

    return max(0, score), red_flags

# --- 2. ELITE UI CONFIGURATION ---
st.set_page_config(page_title="Forensic AI | NTU", page_icon="🛡️", layout="wide")

# Load Bootstrap Icons for the "Prof Vibe" logos
st.markdown('<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css">', unsafe_allow_html=True)

st.markdown("""
    <style>
    .stApp { background-color: #05070a; color: #e6edf3; }
    .hero-card {
        background: linear-gradient(145deg, rgba(22, 27, 34, 0.9), rgba(13, 17, 23, 0.95));
        padding: 40px; border-radius: 35px; border: 1px solid rgba(48, 54, 61, 0.7);
        text-align: center; margin-bottom: 40px;
    }
    
    /* NEW: Prof Vibe Info Boxes */
    .info-box {
        background: rgba(48, 54, 61, 0.2); 
        padding: 25px;
        border-radius: 20px; 
        border: 1px solid #30363d;
        transition: 0.3s ease;
        height: 100%;
    }
    .info-box:hover {
        border-color: #58a6ff;
        background: rgba(48, 54, 61, 0.3);
    }
    .icon-header {
        display: flex;
        align-items: center;
        gap: 15px;
        margin-bottom: 15px;
        color: #58a6ff;
    }
    .icon-header i {
        font-size: 2rem;
    }
    .icon-header span {
        font-size: 1.2rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 1px;
    }

    .threat-card {
        background: rgba(248, 81, 73, 0.08); padding: 18px;
        border-radius: 12px; border-left: 5px solid #f85149; margin-bottom: 10px;
    }
    div.stButton > button {
        background: linear-gradient(180deg, #1f6feb 0%, #0969da 100%) !important;
        border-radius: 10px !important; color: white !important; width: 100%; font-weight: 700;
    }
    </style>
    """, unsafe_allow_html=True)

# --- HEADER ---
c1, c2, c3 = st.columns([1, 4, 1])
with c1:
    try: st.image("NTU logo.jpg", width=130)
    except: st.markdown("### 🏛️")

with c2:
    st.markdown(f"""
        <div class="hero-card">
            <p style="color: #58a6ff; font-weight: 700; margin-bottom: 10px;">
                <span style="font-size: 1.2rem;">C</span>ybersecurity 
                <span style="font-size: 1.2rem;">E</span>ngineering 
                <span style="font-size: 1.2rem;">D</span>epartment 
                <span style="font-size: 1.2rem;">S</span>tudents 
                <span style="color: #8b949e; font-weight: 400; margin-left: 10px;">| College of AI & Computer Engineering</span>
            </p>
            <h6 style="color: #8b949e; letter-spacing: 4px; font-weight: 700; margin-bottom: 5px;">NORTHERN TECHNICAL UNIVERSITY</h6>
            <h1 style="color: #ffffff; font-size: 3rem; font-weight: 900; margin: 0;">AI THREAT INTELLIGENCE</h1>
            <div style="height: 3px; background: #1f6feb; width: 60px; margin: 15px auto; border-radius: 10px;"></div>
        </div>
    """, unsafe_allow_html=True)

with c3:
    try: st.image("collegue logo.jpg", width=130)
    except: st.markdown("### 💻")

# --- SCANNER ---
st.markdown("### 🔍 Forensic Command Console")
target_url = st.text_input("INPUT VECTOR (URL):", placeholder="Paste target URL for deep inspection...")

if st.button("EXECUTE SYSTEM SCAN"):
    if target_url:
        score, flags = deep_forensic_analysis(target_url)
        st.divider()
        r1, r2 = st.columns([1, 1.5])
        with r1:
            color = "#238636" if score > 75 else "#d29922" if score > 45 else "#f85149"
            fig = go.Figure(go.Indicator(
                mode="gauge+number", value=score,
                number={'suffix': "%", 'font': {'color': color, 'size': 60}},
                gauge={'bar': {'color': color}, 'bgcolor': "#010409", 'axis': {'range': [0, 100], 'visible': False}}
            ))
            fig.update_layout(height=300, paper_bgcolor='rgba(0,0,0,0)', font={'color': "white"})
            st.plotly_chart(fig, use_container_width=True)
        with r2:
            st.markdown("### 📊 Investigation Report")
            if score < 45: st.error("🛑 STATUS: CRITICAL THREAT")
            for sev, msg in flags:
                st.markdown(f"<div class='threat-card'><strong>[{sev}]</strong> {msg}</div>", unsafe_allow_html=True)

# --- THE PROF VIBE LOGO BOXES ---
st.write("---")
s1, s2 = st.columns(2)

with s1:
    st.markdown("""
        <div class="info-box">
            <div class="icon-header">
                <i class="bi bi-shield-lock-fill"></i>
                <span>Technical Support</span>
            </div>
            <p style="color: #8b949e; font-size: 0.9rem; margin-bottom: 15px;">24/7 Security Operations Center (SOC) Support</p>
            <div style="display: flex; flex-direction: column; gap: 8px;">
                <div><strong style="color: #e6edf3;">Telegram ID:</strong> <a href="https://t.me/shim_azu64" style="color:#58a6ff; text-decoration: none;">@shim_azu64</a></div>
                <div><strong style="color: #e6edf3;">System ID:</strong> <code style="background: #161b22; padding: 2px 6px; border-radius: 4px; color: #79c0ff;">NTU-AI-64-STABLE</code></div>
                <div><strong style="color: #e6edf3;">Status:</strong> <span style="color: #3fb950;">● Operational</span></div>
            </div>
        </div>
    """, unsafe_allow_html=True)

with s2:
    st.markdown("""
        <div class="info-box">
            <div class="icon-header">
                <i class="bi bi-geo-alt-fill"></i>
                <span>Deployment Details</span>
            </div>
            <p style="color: #8b949e; font-size: 0.9rem; margin-bottom: 15px;">Edge Computing Node and Database Synchronicity</p>
            <div style="display: flex; flex-direction: column; gap: 8px;">
                <div><strong style="color: #e6edf3;">Node Location:</strong> <span style="color: #d29922;">Kirkuk, Iraq</span></div>
                <div><strong style="color: #e6edf3;">Database Sync:</strong> <span style="color: #8b949e;">Feb 2026</span></div>
                <div><strong style="color: #e6edf3;">Network:</strong> <span style="color: #8b949e;">NTU-Private-Cloud</span></div>
            </div>
        </div>
    """, unsafe_allow_html=True)

# --- FOOTER ---
st.markdown("<br><center style='color: #484f58; font-size: 12px; letter-spacing: 2px;'>NORTHERN TECHNICAL UNIVERSITY | CYBERSECURITY ENGINEERING DEPARTMENT STUDENTS</center>", unsafe_allow_html=True)
