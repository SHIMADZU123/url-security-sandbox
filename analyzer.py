import streamlit as st
import plotly.graph_objects as go
import urllib.parse

# --- 1. CORE FORENSIC ENGINE ---
def deep_forensic_analysis(url):
    score = 100
    red_flags = []
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.lower()

    # Detection Logic
    if any(s in domain for s in ['bit.ly', 'tinyurl.com', 't.co', 'rebrand.ly']):
        score -= 70
        red_flags.append(("HIGH RISK", "URL Masking: Shortened link detected."))
    
    if any(url.lower().endswith(ext) for ext in ['.exe', '.msi', '.zip']):
        score -= 90
        red_flags.append(("CRITICAL", "Payload: Suspicious executable detected."))

    return max(0, score), red_flags

# --- 2. ELITE UI CONFIGURATION ---
st.set_page_config(page_title="Forensic AI | NTU", page_icon="🛡️", layout="wide")

# Styling: Glassmorphism & Sleek Inputs
st.markdown("""
    <style>
    .stApp { background-color: #05070a; color: #e6edf3; }
    
    /* Header Card */
    .hero-card {
        background: linear-gradient(145deg, rgba(22, 27, 34, 0.9), rgba(13, 17, 23, 0.95));
        padding: 40px; border-radius: 35px; border: 1px solid rgba(48, 54, 61, 0.7);
        text-align: center; margin-bottom: 40px;
    }

    /* THE NEW SLEEK SEARCH BAR */
    .search-wrapper {
        background: rgba(255, 255, 255, 0.03);
        padding: 25px; border-radius: 20px;
        border: 1px solid rgba(88, 166, 255, 0.1);
        margin-bottom: 20px;
    }
    
    .stTextInput input {
        background-color: #0d1117 !important;
        border: 1px solid #30363d !important;
        color: #58a6ff !important;
        border-radius: 12px !important;
        padding: 15px !important;
    }
    
    .stTextInput input:focus {
        border-color: #58a6ff !important;
        box-shadow: 0 0 15px rgba(88, 166, 255, 0.1) !important;
    }

    /* Modern Button */
    div.stButton > button {
        background: #1f6feb !important;
        border-radius: 10px !important; color: white !important;
        width: 100%; font-weight: 700 !important; border: none !important;
        padding: 12px !important; transition: 0.3s ease;
    }
    div.stButton > button:hover { transform: translateY(-2px); box-shadow: 0 5px 15px rgba(31, 111, 235, 0.3); }
    </style>
    """, unsafe_allow_html=True)

# --- 3. HEADER (FIXED: No more AttributeError) ---
c1, c2, c3 = st.columns([1, 4, 1])

with c1:
    try:
        st.image("NTU logo.jpg", width=120)
    except:
        st.write("🏛️")

with c2:
    st.markdown(f"""
        <div class="hero-card">
            <p style="color: #58a6ff; font-weight: 700; margin-bottom: 12px;">
                <span style="font-size: 1.25rem;">C</span>ybersecurity 
                <span style="font-size: 1.25rem;">E</span>ngineering 
                <span style="font-size: 1.25rem;">D</span>epartment 
                <span style="font-size: 1.25rem;">S</span>tudents 
            </p>
            <h6 style="color: #8b949e; letter-spacing: 5px; font-weight: 700;">NORTHERN TECHNICAL UNIVERSITY</h6>
            <h1 style="color: #ffffff; font-size: 3.2rem; font-weight: 900; margin: 0;">AI THREAT INTELLIGENCE</h1>
        </div>
    """, unsafe_allow_html=True)

with c3:
    try:
        st.image("collegue logo.jpg", width=120)
    except:
        st.write("💻")

# --- 4. THE NEW SEARCH INTERFACE ---
st.markdown("### 🔍 Forensic Target Acquisition")
with st.container():
    target_url = st.text_input("URL INPUT", label_visibility="collapsed", placeholder="Enter target URL for deep packet inspection...")
    
    btn_col, _ = st.columns([1, 3])
    with btn_col:
        if st.button("EXECUTE SYSTEM SCAN"):
            if target_url:
                score, flags = deep_forensic_analysis(target_url)
                st.divider()
                # (Remaining result logic here)
                st.write(f"**Security Integrity Score: {score}%**")
                for sev, msg in flags:
                    st.error(f"**[{sev}]** {msg}")

# --- 5. SYSTEM INFO ---
st.write("---")
st.markdown("<center style='color: #484f58; font-size: 12px;'>NORTHERN TECHNICAL UNIVERSITY | CYBERSECURITY ENGINEERING</center>", unsafe_allow_html=True)
