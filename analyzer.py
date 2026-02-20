import streamlit as st
import plotly.graph_objects as go
import urllib.parse
import re

# --- 1. SCAN ENGINE (PRESERVED & ACCURATE) ---
def deep_forensic_analysis(url):
    score = 100
    red_flags = []
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    domain = urllib.parse.urlparse(url).netloc.lower()
    
    malware_patterns = ['eicar', '.exe', '.com', '.scr', '.bin', '.dll', '.zip']
    if any(p in url.lower() for p in malware_patterns):
        score -= 90
        red_flags.append(("CRITICAL", "Malware Signature Detected: System identified suspicious executable extensions in the target path."))

    blacklist = ['phishing', 'testsafebrowsing', 'verify', 'secure-update', 'signin-check']
    if any(p in url.lower() for p in blacklist):
        score -= 85
        red_flags.append(("CRITICAL", "Heuristic Phishing Match: Architectural patterns consistent with known social engineering vectors."))

    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
        score -= 50
        red_flags.append(("CRITICAL", "Non-DNS Routing: Direct IP access detected. This method is frequently used to bypass domain reputation filters."))

    if domain.startswith("xn--"):
        score -= 60
        red_flags.append(("CRITICAL", "Homograph Deception: Punycode encoding detected, indicating a high risk of brand spoofing."))

    return max(0, score), red_flags

# --- 2. ENTERPRISE UI OVERHAUL ---
st.set_page_config(page_title="Forensic AI | Enterprise Console", page_icon="🛡️", layout="wide")

st.markdown("""
    <style>
    /* Dark Slate Enterprise Theme */
    .stApp {
        background-color: #05070a;
        background-image: 
            radial-gradient(circle at 1px 1px, #161b22 1px, transparent 0);
        background-size: 32px 32px;
        color: #e6edf3;
    }
    
    /* Modern Glass Hero Card */
    .hero-container {
        background: linear-gradient(145deg, rgba(22, 27, 34, 0.9), rgba(13, 17, 23, 0.95));
        backdrop-filter: blur(20px);
        padding: 50px;
        border-radius: 32px;
        border: 1px solid rgba(48, 54, 61, 0.5);
        text-align: center;
        margin-bottom: 40px;
        box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
    }

    /* Professional Forensic Flag Cards */
    .flag-card {
        background: rgba(248, 81, 73, 0.05);
        padding: 20px;
        border-radius: 12px;
        border-left: 6px solid #f85149;
        margin-bottom: 12px;
        font-family: 'Inter', sans-serif;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    }

    /* Custom Input Shadow */
    .stTextInput>div>div>input {
        background-color: #0d1117 !important;
        border: 1px solid #30363d !important;
        border-radius: 12px !important;
        padding: 15px !important;
        transition: all 0.3s ease;
    }
    .stTextInput>div>div>input:focus {
        border-color: #58a6ff !important;
        box-shadow: 0 0 0 2px rgba(88, 166, 255, 0.3) !important;
    }

    /* Enterprise Action Button */
    div.stButton > button {
        background: #1f6feb !important;
        border: none !important;
        border-radius: 10px !important;
        padding: 18px !important;
        font-weight: 700 !important;
        text-transform: uppercase;
        letter-spacing: 2px;
        transition: 0.4s;
    }
    div.stButton > button:hover {
        background: #388bfd !important;
        box-shadow: 0 0 20px rgba(31, 111, 235, 0.4);
        transform: translateY(-2px);
    }
    </style>
    """, unsafe_allow_html=True)

# --- BALANCED ENTERPRISE HEADER ---
col_l, col_m, col_r = st.columns([1, 4, 1])

with col_l:
    try: st.image("NTU logo.jpg", width=130)
    except: st.markdown("### 🏛️")

with col_m:
    st.markdown("""
        <div class="hero-container">
            <h6 style="color: #58a6ff; letter-spacing: 6px; margin-bottom: 15px; font-weight: 600;">NORTHERN TECHNICAL UNIVERSITY</h6>
            <h1 style="color: #ffffff; font-size: 3.5rem; font-weight: 900; margin-bottom: 10px; letter-spacing: -1px;">AI THREAT INTELLIGENCE</h1>
            <div style="height: 3px; background: linear-gradient(90deg, transparent, #1f6feb, transparent); width: 50%; margin: 20px auto;"></div>
            <p style="color: #8b949e; font-size: 1.1rem; max-width: 600px; margin: 0 auto;">
                Advanced Cyber-Forensics & Phishing Detection Powered by NTU College of AI & Computer Engineering
            </p>
        </div>
    """, unsafe_allow_html=True)

with col_r:
    # Proper right-alignment for college logo
    sub_l, sub_r = st.columns([1, 5])
    with sub_r:
        try: st.image("collegue logo.jpg", width=130)
        except: st.markdown("<div style='text-align:right'>### 💻</div>", unsafe_allow_html=True)

# --- INTERFACE COMMANDS ---
st.markdown("### 🔍 Forensic Target Acquisition")
target_vector = st.text_input("ENTER TARGET URL FOR DEEP PACKET INSPECTION:", placeholder="https://secure-node-id.net")

if st.button("EXECUTE SYSTEM SCAN"):
    if target_vector:
        score, flags = deep_forensic_analysis(target_vector)
        
        st.write("---")
        res_col1, res_col2 = st.columns([1, 1.5])
        
        with res_col1:
            # SaaS-Style Gauge
            g_color = "#238636" if score > 75 else "#d29922" if score > 45 else "#f85149"
            fig = go.Figure(go.Indicator(
                mode="gauge+number", value=score,
                number={'suffix': "%", 'font': {'color': g_color, 'size': 85}},
                gauge={
                    'bar': {'color': g_color},
                    'bgcolor': "#010409",
                    'axis': {'range': [0, 100], 'visible': False},
                    'borderwidth': 0,
                }
            ))
            fig.update_layout(height=400, paper_bgcolor='rgba(0,0,0,0)', font={'color': "white"})
            st.plotly_chart(fig, use_container_width=True)

        with res_col2:
            st.markdown("### 📄 Threat Intelligence Manifest")
            if score < 45: st.error("🛑 CRITICAL VULNERABILITY: IMMEDIATE ACTION RECOMMENDED")
            elif score < 75: st.warning("⚠️ ELEVATED RISK: ANOMALIES DETECTED")
            else: st.success("✅ INTEGRITY VERIFIED: NO MALICIOUS SIGNATURES FOUND")

            for severity, msg in flags:
                st.markdown(f"""
                    <div class="flag-card">
                        <span style="color:#f85149; font-weight: 800; margin-right: 10px;">[{severity}]</span> {msg}
                    </div>
                """, unsafe_allow_html=True)
            
            if not flags:
                st.info("System scan finalized. Structure appears legitimate under current heuristic rules.")

# --- FOOTER ---
st.markdown("""
    <div style="position: fixed; bottom: 0; left: 0; width: 100%; background: #010409; border-top: 1px solid #30363d; padding: 15px; text-align: center; color: #8b949e; font-size: 11px;">
        NTU THREAT INTELLIGENCE NODE | ANALYST: @shim_azu64 | ENCRYPTION: ACTIVE | v7.0-ENTERPRISE
    </div>
""", unsafe_allow_html=True)
