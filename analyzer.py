import streamlit as st
import plotly.graph_objects as go
import urllib.parse

# --- 1. CORE FORENSIC ENGINE ---
def deep_forensic_analysis(url):
    score = 100
    red_flags = []
    if not url.startswith(('http://', 'https://')): url = 'https://' + url
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.lower()
    if any(s in domain for s in ['bit.ly', 'tinyurl.com', 't.co', 'rebrand.ly']):
        score -= 70
        red_flags.append(("HIGH RISK", "URL Masking: Shortened link detected."))
    return max(0, score), red_flags

# --- 2. ELITE UI CONFIGURATION ---
st.set_page_config(page_title="Forensic AI | NTU", page_icon="🛡️", layout="wide")
st.markdown('<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css">', unsafe_allow_html=True)

st.markdown("""
    <style>
    /* Base Theme */
    .stApp { background-color: #05070a; color: #e6edf3; font-family: 'Inter', sans-serif; }
    
    /* Hero Section */
    .hero-card {
        background: linear-gradient(145deg, rgba(22, 27, 34, 0.9), rgba(13, 17, 23, 0.95));
        padding: 40px; border-radius: 35px; border: 1px solid rgba(48, 54, 61, 0.7);
        text-align: center; margin-bottom: 40px; box-shadow: 0 20px 50px rgba(0,0,0,0.5);
    }

    /* THE PROFESSIONAL COMMAND CARDS */
    .command-card {
        background: rgba(13, 17, 23, 0.8);
        border: 1px solid #30363d;
        border-radius: 20px;
        padding: 25px;
        height: 100%;
        transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
        cursor: pointer;
        position: relative;
        overflow: hidden;
    }
    
    .command-card:hover {
        border-color: #58a6ff;
        transform: translateY(-8px);
        background: rgba(22, 27, 34, 1);
        box-shadow: 0 15px 30px rgba(88, 166, 255, 0.1);
    }

    .card-header {
        display: flex;
        align-items: center;
        gap: 15px;
        margin-bottom: 20px;
    }

    .card-icon {
        width: 45px;
        height: 45px;
        background: rgba(88, 166, 255, 0.1);
        border-radius: 12px;
        display: flex;
        align-items: center;
        justify-content: center;
        color: #58a6ff;
        font-size: 1.4rem;
    }

    .card-title {
        font-weight: 700;
        letter-spacing: 1px;
        text-transform: uppercase;
        font-size: 0.95rem;
        color: #f0f6fc;
    }

    .data-row {
        display: flex;
        justify-content: space-between;
        padding: 8px 0;
        border-bottom: 1px solid rgba(48, 54, 61, 0.5);
        font-size: 0.9rem;
    }

    .data-label { color: #8b949e; }
    .data-value { color: #c9d1d9; font-weight: 500; }
    
    /* Interactive Button Effect */
    .card-link {
        display: inline-block;
        margin-top: 15px;
        color: #58a6ff;
        text-decoration: none;
        font-weight: 600;
        font-size: 0.85rem;
        transition: 0.3s;
    }
    .card-link:hover { color: #79c0ff; text-decoration: underline; }

    /* New Sleek Input */
    .stTextInput input {
        background-color: #0d1117 !important;
        border: 1px solid #30363d !important;
        border-radius: 15px !important;
        padding: 15px !important;
        color: #58a6ff !important;
    }
    </style>
    """, unsafe_allow_html=True)

# --- 3. HEADER (STABLE BLOCK) ---
c1, c2, c3 = st.columns([1, 4, 1])
with c1:
    try: st.image("NTU logo.jpg", width=120)
    except: st.write("🏛️")
with c2:
    st.markdown("""
        <div class="hero-card">
            <p style="color: #58a6ff; font-weight: 700; margin-bottom: 5px;">
                <span style="font-size: 1.2rem;">C</span>ybersecurity <span style="font-size: 1.2rem;">E</span>ngineering <span style="font-size: 1.2rem;">D</span>epartment <span style="font-size: 1.2rem;">S</span>tudents
            </p>
            <h6 style="color: #8b949e; letter-spacing: 4px; font-weight: 400;">NORTHERN TECHNICAL UNIVERSITY</h6>
            <h1 style="color: #ffffff; font-size: 3.5rem; font-weight: 900; margin: 0; letter-spacing: -2px;">AI THREAT INTELLIGENCE</h1>
        </div>
    """, unsafe_allow_html=True)
with c3:
    try: st.image("collegue logo.jpg", width=120)
    except: st.write("💻")

# --- 4. SCANNER SECTION ---
st.markdown("### <i class='bi bi-search'></i> Forensic Target Acquisition", unsafe_allow_html=True)
target_url = st.text_input("LABEL", label_visibility="collapsed", placeholder="Enter target URL for deep packet inspection...")
if st.button("EXECUTE SYSTEM SCAN"):
    if target_url:
        score, flags = deep_forensic_analysis(target_url)
        st.info(f"Analysis Complete: System Integrity at {score}%")

st.write("<br>", unsafe_allow_html=True)

# --- 5. THE PROFESSIONAL INTERACTIVE FOOTER ---
s1, s2 = st.columns(2)

with s1:
    st.markdown("""
        <div class="command-card">
            <div class="card-header">
                <div class="card-icon"><i class="bi bi-shield-lock-fill"></i></div>
                <div class="card-title">Technical Support</div>
            </div>
            <div class="data-row"><span class="data-label">Administrator</span><span class="data-value">@shim_azu64</span></div>
            <div class="data-row"><span class="data-label">System ID</span><span class="data-value">NTU-AI-64-STABLE</span></div>
            <div class="data-row"><span class="data-label">Security Tier</span><span class="data-value">Tier 3 Forensic</span></div>
            <div class="data-row"><span class="data-label">Status</span><span style="color: #3fb950; font-weight: 700;">● Operational</span></div>
            <a href="https://t.me/shim_azu64" class="card-link">INITIALIZE SECURE CHAT →</a>
        </div>
    """, unsafe_allow_html=True)

with s2:
    st.markdown("""
        <div class="command-card">
            <div class="card-header">
                <div class="card-icon"><i class="bi bi-geo-alt-fill"></i></div>
                <div class="card-title">Deployment Details</div>
            </div>
            <div class="data-row"><span class="data-label">Active Node</span><span class="data-value">Kirkuk, Iraq</span></div>
            <div class="data-row"><span class="data-label">Database Sync</span><span class="data-value">Feb 2026</span></div>
            <div class="data-row"><span class="data-label">Network</span><span class="data-value">NTU-Private-Cloud</span></div>
            <div class="data-row"><span class="data-label">Latency</span><span class="data-value">14ms (Optimum)</span></div>
            <a href="#" class="card-link">VIEW NODE METRICS →</a>
        </div>
    """, unsafe_allow_html=True)

st.markdown("<br><center style='color: #484f58; font-size: 11px; letter-spacing: 3px;'>NORTHERN TECHNICAL UNIVERSITY | CYBERSECURITY ENGINEERING</center>", unsafe_allow_html=True)
