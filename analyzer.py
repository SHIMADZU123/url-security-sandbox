import streamlit as st
import plotly.graph_objects as go
import urllib.parse
import re

# --- 1. CORE FORENSIC ENGINE ---
def deep_forensic_analysis(url):
    score = 100
    red_flags = []
    if not url.startswith(('http://', 'https://')): url = 'https://' + url
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.lower()
    
    # Shortener Detection
    if any(s in domain for s in ['bit.ly', 'tinyurl.com', 't.co', 'rebrand.ly']):
        score -= 70
        red_flags.append(("HIGH RISK", "URL Masking Detected: Shortened link hiding destination."))
    
    # Malware Signature Check
    if any(url.lower().endswith(ext) for ext in ['.exe', '.msi', '.zip', '.scr']):
        score -= 90
        red_flags.append(("CRITICAL", "Payload Signature: Suspicious executable detected."))
        
    return max(0, score), red_flags

# --- 2. ELITE UI CONFIGURATION ---
st.set_page_config(page_title="Forensic AI | NTU", page_icon="🛡️", layout="wide")
st.markdown('<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css">', unsafe_allow_html=True)

st.markdown("""
    <style>
    .stApp { background-color: #05070a; color: #e6edf3; }
    
    /* Hero Card */
    .hero-card {
        background: linear-gradient(145deg, rgba(22, 27, 34, 0.9), rgba(13, 17, 23, 0.95));
        padding: 40px; border-radius: 35px; border: 1px solid rgba(48, 54, 61, 0.7);
        text-align: center; margin-bottom: 40px;
    }

    /* THE UPGRADED CONSOLE SECTION */
    .terminal-header {
        display: flex; align-items: center; gap: 12px;
        background: rgba(31, 111, 235, 0.1);
        padding: 15px 25px; border-radius: 15px 15px 0 0;
        border: 1px solid rgba(31, 111, 235, 0.3);
        border-bottom: none;
    }
    .terminal-title {
        font-family: 'Courier New', monospace; font-weight: 800;
        letter-spacing: 2px; color: #58a6ff; text-transform: uppercase;
    }
    
    /* Custom Input Styling */
    .stTextInput input {
        background-color: #0d1117 !important;
        border: 1px solid #30363d !important;
        color: #58a6ff !important;
        font-family: 'Courier New', monospace !important;
        border-radius: 0 0 15px 15px !important;
        padding: 20px !important;
    }
    .stTextInput input:focus {
        border-color: #58a6ff !important;
        box-shadow: 0 0 15px rgba(88, 166, 255, 0.2) !important;
    }

    /* Modern Button */
    div.stButton > button {
        background: linear-gradient(90deg, #1f6feb 0%, #0969da 100%) !important;
        border: none !important; border-radius: 12px !important;
        padding: 15px !important; color: white !important;
        font-weight: 800 !important; letter-spacing: 1.5px !important;
        transition: 0.4s all ease !important;
        text-transform: uppercase;
    }
    div.stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 5px 20px rgba(31, 111, 235, 0.4);
    }
    
    .info-box {
        background: rgba(22, 27, 34, 0.5); padding: 25px;
        border-radius: 20px; border: 1px solid #30363d;
    }
    </style>
    """, unsafe_allow_html=True)

# --- 3. HEADER ---
c1, c2, c3 = st.columns([1, 4, 1])
with c1: st.image("NTU logo.jpg", width=120) if True else None
with c2:
    st.markdown(f"""
        <div class="hero-card">
            <p style="color: #58a6ff; font-weight: 700;">
                <span style="font-size: 1.2rem;">C</span>ybersecurity <span style="font-size: 1.2rem;">E</span>ngineering 
                <span style="font-size: 1.2rem;">D</span>epartment <span style="font-size: 1.2rem;">S</span>tudents 
                <span style="color: #8b949e; font-weight: 400; margin-left: 10px;">| College of AI</span>
            </p>
            <h1 style="color: #ffffff; font-size: 3rem; font-weight: 900; margin: 0;">AI THREAT INTELLIGENCE</h1>
        </div>
    """, unsafe_allow_html=True)
with c3: st.image("collegue logo.jpg", width=120) if True else None

# --- 4. THE NEW UPGRADED CONSOLE ---
st.markdown("""
    <div class="terminal-header">
        <i class="bi bi-cpu" style="color: #58a6ff; font-size: 1.5rem;"></i>
        <span class="terminal-title">Neural Link Analysis Terminal v2.0</span>
    </div>
""", unsafe_allow_html=True)

target_url = st.text_input("LABEL", label_visibility="collapsed", placeholder="SYSTEM READY: Input Target Vector (URL) for Neural Inspection...")

col_btn, _ = st.columns([1, 2])
with col_btn:
    if st.button("▶ INITIALIZE NEURAL SCAN"):
        if target_url:
            score, flags = deep_forensic_analysis(target_url)
            st.divider()
            
            r1, r2 = st.columns([1, 1.5])
            with r1:
                fig = go.Figure(go.Indicator(
                    mode="gauge+number", value=score,
                    number={'suffix': "%", 'font': {'color': "#58a6ff"}},
                    gauge={'bar': {'color': "#1f6feb"}, 'bgcolor': "#010409", 'axis': {'range': [0, 100], 'visible': False}}
                ))
                fig.update_layout(height=300, paper_bgcolor='rgba(0,0,0,0)', font={'color': "white"})
                st.plotly_chart(fig, use_container_width=True)
            with r2:
                st.markdown("### 📊 Intelligence Manifest")
                for sev, msg in flags:
                    st.error(f"**[{sev}]** {msg}")
                if not flags: st.success("INTEGRITY CLEAR: No malicious vectors detected.")

# --- 5. SYSTEM INFO ---
st.write("---")
s1, s2 = st.columns(2)
with s1:
    st.markdown("""<div class="info-box"><h4 style="color:#58a6ff;"><i class="bi bi-shield-lock"></i> Tech Support</h4>
    <strong>Telegram:</strong> @shim_azu64<br><strong>Status:</strong> <span style="color:#3fb950;">Operational</span></div>""", unsafe_allow_html=True)
with s2:
    st.markdown("""<div class="info-box"><h4 style="color:#58a6ff;"><i class="bi bi-geo-alt"></i> Deployment</h4>
    <strong>Node:</strong> Kirkuk, Iraq<br><strong>Network:</strong> Private Cloud</div>""", unsafe_allow_html=True)

st.markdown("<br><center style='color: #484f58; font-size: 12px;'>NORTHERN TECHNICAL UNIVERSITY | CYBERSECURITY ENGINEERING</center>", unsafe_allow_html=True)
