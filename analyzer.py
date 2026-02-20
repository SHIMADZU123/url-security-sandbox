import streamlit as st
import plotly.graph_objects as go
import urllib.parse
import re

# --- 1. SCAN CODE (STRICTLY PRESERVED) ---
def deep_forensic_analysis(url):
    score = 100
    red_flags = []
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    domain = urllib.parse.urlparse(url).netloc.lower()
    
    malware_patterns = ['eicar', '.exe', '.com', '.scr', '.bin', '.dll', '.zip']
    if any(p in url.lower() for p in malware_patterns):
        score -= 90
        red_flags.append(("CRITICAL", "Malware Signature Detected: URL contains references to known suspicious executable extensions."))

    blacklist = ['phishing', 'testsafebrowsing', 'verify', 'secure-update', 'signin-check']
    if any(p in url.lower() for p in blacklist):
        score -= 85
        red_flags.append(("CRITICAL", "Heuristic Phishing Match: URL architecture matches known social engineering deployment patterns."))

    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
        score -= 50
        red_flags.append(("CRITICAL", "IP-Based Routing: Bypass of DNS identified. Legitimate services do not host sensitive content on raw IP addresses."))

    if domain.startswith("xn--"):
        score -= 60
        red_flags.append(("CRITICAL", "Homograph Deception: Use of Punycode detected mimicking legitimate brands."))

    return max(0, score), red_flags

# --- 2. NEW PROFESSIONAL DISPLAY LOGIC ---
st.set_page_config(page_title="Forensic AI | NTU", page_icon="🛡️", layout="wide")

st.markdown("""
    <style>
    /* Premium Dark Theme */
    .stApp {
        background-color: #0d1117;
        background-image: radial-gradient(circle at 2px 2px, #161b22 1px, transparent 0);
        background-size: 40px 40px;
    }
    
    /* Modern Glass Header */
    .main-header {
        background: rgba(22, 27, 34, 0.8);
        backdrop-filter: blur(12px);
        padding: 40px;
        border-radius: 24px;
        border: 1px solid #30363d;
        text-align: center;
        box-shadow: 0 8px 32px rgba(0,0,0,0.4);
        margin-bottom: 30px;
    }

    /* Professional Forensic Logs */
    .forensic-card {
        background: #161b22;
        padding: 15px;
        border-radius: 10px;
        border-left: 5px solid #f85149;
        margin-bottom: 10px;
        font-family: 'Source Code Pro', monospace;
        font-size: 0.9rem;
    }

    /* Action Button Styling */
    div.stButton > button {
        background: linear-gradient(180deg, #1f6feb 0%, #0969da 100%) !important;
        color: white !important;
        border: 1px solid rgba(240,246,252,0.1) !important;
        border-radius: 8px !important;
        width: 100% !important;
        height: 50px !important;
        font-weight: 700 !important;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    </style>
    """, unsafe_allow_html=True)

# --- HEADER LAYOUT ---
h_col1, h_col2, h_col3 = st.columns([1, 4, 1])
with h_col1:
    try: st.image("NTU logo.jpg", width=120)
    except: st.title("🏛️")

with h_col2:
    st.markdown("""
        <div class="main-header">
            <h5 style="color: #8b949e; letter-spacing: 4px; margin-bottom: 0;">NORTHERN TECHNICAL UNIVERSITY</h5>
            <h1 style="color: #ffffff; font-size: 3rem; margin-top: 5px;">AI THREAT INTELLIGENCE</h1>
            <p style="color: #58a6ff; font-weight: 500;">COLLEGE OF AI & COMPUTER ENGINEERING | FORENSIC UNIT</p>
        </div>
    """, unsafe_allow_html=True)

with h_col3:
    # Right-aligned college logo
    c_r1, c_r2 = st.columns([1, 5])
    with c_r2:
        try: st.image("collegue logo.jpg", width=120)
        except: st.title("💻")

# --- CONTROL PANEL ---
st.markdown("### 🖥️ Forensic Command Console")
input_url = st.text_input("INPUT TARGET VECTOR (URL):", placeholder="https://")

if st.button("EXECUTE DEEP SYSTEM SCAN"):
    if input_url:
        score, flags = deep_forensic_analysis(input_url)
        
        st.divider()
        res_left, res_right = st.columns([1, 1.5])
        
        with res_left:
            # High-end Gauge
            color = "#238636" if score > 75 else "#d29922" if score > 45 else "#f85149"
            fig = go.Figure(go.Indicator(
                mode="gauge+number", value=score,
                number={'suffix': "%", 'font': {'color': color, 'size': 80}},
                gauge={
                    'bar': {'color': color},
                    'bgcolor': "#010409",
                    'axis': {'range': [0, 100], 'tickcolor': "#8b949e"},
                    'steps': [{'range': [0, 100], 'color': "rgba(48, 54, 61, 0.2)"}]
                }
            ))
            fig.update_layout(height=400, paper_bgcolor='rgba(0,0,0,0)', font={'color': "white"})
            st.plotly_chart(fig, use_container_width=True)

        with res_right:
            st.markdown("### 📋 Forensic Intel Report")
            if score < 45: st.error("🛑 SECURITY STATUS: CRITICAL THREAT")
            elif score < 75: st.warning("⚠️ SECURITY STATUS: ELEVATED RISK")
            else: st.success("✅ SECURITY STATUS: INTEGRITY VERIFIED")

            for severity, msg in flags:
                st.markdown(f"""
                    <div class="forensic-card">
                        <strong style="color:#f85149;">[{severity}]</strong> {msg}
                    </div>
                """, unsafe_allow_html=True)
            
            if not flags:
                st.info("No malicious signatures detected in URL structure.")

# --- FOOTER ---
st.markdown("""
    <div style="position: fixed; bottom: 0; left: 0; width: 100%; background: #0d1117; border-top: 1px solid #30363d; padding: 10px; text-align: center; color: #484f58; font-size: 12px;">
        NTU FORENSIC NODE | SUPPORT: @shim_azu64 | SYSTEM v6.0-ELITE
    </div>
""", unsafe_allow_html=True)
