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
    if any(s in domain for s in ['bit.ly', 'tinyurl.com', 't.co']):
        score -= 70
        red_flags.append(("HIGH RISK", "URL Masking Detected."))
    return max(0, score), red_flags

# --- 2. UI CONFIGURATION ---
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

    /* THE NEW SLEEK SEARCH BAR SECTION */
    .search-container {
        background: rgba(255, 255, 255, 0.03);
        backdrop-filter: blur(10px);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 20px;
        padding: 30px;
        margin-bottom: 30px;
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
    }
    
    .search-label {
        font-size: 0.85rem;
        text-transform: uppercase;
        letter-spacing: 2px;
        color: #8b949e;
        margin-bottom: 15px;
        display: flex;
        align-items: center;
        gap: 10px;
    }

    /* Streamlit Input Overrides */
    .stTextInput input {
        background-color: rgba(255, 255, 255, 0.05) !important;
        border: 1px solid rgba(88, 166, 255, 0.2) !important;
        color: #ffffff !important;
        border-radius: 12px !important;
        padding: 15px 20px !important;
        font-size: 1.1rem !important;
    }
    .stTextInput input:focus {
        border-color: #58a6ff !important;
        background-color: rgba(255, 255, 255, 0.08) !important;
        box-shadow: 0 0 20px rgba(88, 166, 255, 0.15) !important;
    }

    /* Modern Button */
    div.stButton > button {
        background: #1f6feb !important;
        border: none !important;
        border-radius: 12px !important;
        padding: 12px 30px !important;
        color: white !important;
        font-weight: 600 !important;
        transition: 0.3s all ease !important;
    }
    div.stButton > button:hover {
        background: #388bfd !important;
        box-shadow: 0 0 25px rgba(31, 111, 235, 0.5);
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
            </p>
            <h1 style="color: #ffffff; font-size: 3rem; font-weight: 900; margin: 0;">AI THREAT INTELLIGENCE</h1>
        </div>
    """, unsafe_allow_html=True)
with c3: st.image("collegue logo.jpg", width=120) if True else None

# --- 4. THE NEW GLASS SEARCH BAR ---
st.markdown("""
    <div class="search-label">
        <i class="bi bi-shield-shaded"></i> Forensic Analysis Target Acquisition
    </div>
""", unsafe_allow_html=True)

# Using a container to apply the glass effect
with st.container():
    target_url = st.text_input("INPUT", label_visibility="collapsed", placeholder="Enter URL to analyze signatures...")
    
    col_btn, _ = st.columns([1, 3])
    with col_btn:
        if st.button("EXECUTE SCAN"):
            if target_url:
                score, flags = deep_forensic_analysis(target_url)
                st.success(f"Analysis complete. Security Score: {score}%")

# --- 5. SYSTEM INFO ---
st.write("---")
s1, s2 = st.columns(2)
with s1:
    st.markdown("""<div style="background:rgba(22,27,34,0.5); padding:20px; border-radius:15px; border:1px solid #30363d;">
    <h4 style="color:#58a6ff;"><i class="bi bi-headset"></i> Support</h4>@shim_azu64</div>""", unsafe_allow_html=True)
with s2:
    st.markdown("""<div style="background:rgba(22,27,34,0.5); padding:20px; border-radius:15px; border:1px solid #30363d;">
    <h4 style="color:#58a6ff;"><i class="bi bi-cpu"></i> Node</h4>Kirkuk, Iraq</div>""", unsafe_allow_html=True)
