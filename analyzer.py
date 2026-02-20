import streamlit as st
import requests
import whois
import ssl
import socket
import urllib.parse
from datetime import datetime
import base64
import re
import plotly.graph_objects as go

# --- PAGE CONFIGURATION ---
st.set_page_config(page_title="AI Threat Intelligence", page_icon="🛡️", layout="wide")

# --- CUSTOM CSS FOR ANIMATION & STYLE ---
st.markdown("""
    <style>
    .main { background-color: #0e1117; }
    div.stButton > button:first-child {
        background-color: #0068c9;
        color: white;
        width: 100%;
        border-radius: 10px;
    }
    .footer {
        position: fixed;
        left: 0;
        bottom: 0;
        width: 100%;
        background-color: #0e1117;
        color: gray;
        text-align: center;
        padding: 10px;
        font-size: 14px;
        border-top: 1px solid #31333F;
    }
    </style>
    """, unsafe_allow_html=True)

# --- SIDEBAR (Educational Component) ---
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/shield.png", width=80)
    st.markdown("### 📚 Analysis Engine")
    st.info("Our AI uses **Heuristic Scanning** to detect patterns used by attackers before they are reported to blacklists.")
    st.divider()
    st.markdown("**College:** AI & Computer Engineering")
    st.markdown("**University:** Northern Technical University")

# --- PROFESSIONAL HEADER ---
head_col1, head_col2, head_col3 = st.columns([1, 4, 1])

with head_col1:
    try:
        st.image("NTU logo.jpg", use_container_width=True)
    except:
        st.write("🏛️ **NTU**")

with head_col2:
    st.markdown("<h1 style='text-align: center; color: white; margin-bottom: 0;'>Welcome to the AI Threat Intelligence</h1>", unsafe_allow_html=True)
    st.markdown("<h4 style='text-align: center; color: #FFCB70; margin-top: 0;'>Powered by Northern Technical University | AI & Computer Engineering College</h4>", unsafe_allow_html=True)
    st.markdown("<p style='text-align: center; color: #bdc3c7;'>Advanced URL Security & Phishing Detection System</p>", unsafe_allow_html=True)

with head_col3:
    try:
        st.image("collegue logo.jpg", use_container_width=True)
    except:
        st.write("💻 **AI & CE**")

st.divider()

# --- SECURITY ENGINE FUNCTIONS ---
def get_domain_age(domain):
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list): creation = creation[0]
        return (datetime.now() - creation).days if creation else None
    except: return None

def check_ssl(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                return True
    except: return False

def analyze_url(url):
    # Starting score is 100 (Perfectly Safe)
    score = 100
    findings = []
    
    # 1. Check for IP Address instead of Domain
    domain = urllib.parse.urlparse(url).netloc
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
        score -= 40
        findings.append("🚨 Link uses a raw IP address (Highly Suspicious)")

    # 2. Check for SSL
    if not url.startswith("https"):
        score -= 20
        findings.append("🔓 No Encryption (HTTP used instead of HTTPS)")
    elif not check_ssl(domain):
        score -= 15
        findings.append("⚠️ SSL Certificate is invalid or expired")

    # 3. Check for urgency keywords
    scam_keywords = ['login', 'verify', 'update', 'banking', 'secure', 'account']
    if any(key in url.lower() for key in scam_keywords):
        score -= 10
        findings.append("🎣 Contains phishing-style keywords")

    # 4. Check domain age
    age = get_domain_age(domain)
    if age and age < 30:
        score -= 30
        findings.append(f"⚠️ Brand New Domain (Created {age} days ago)")

    return max(0, score), findings

# --- MAIN INTERFACE ---
url_input = st.text_input("🔗 Enter the URL to scan:", placeholder="https://example.com")

if st.button("Initialize Live Scan"):
    if not url_input or "." not in url_input:
        st.error("Please enter a valid URL.")
    else:
        with st.spinner("Analyzing threat vectors..."):
            score, findings = analyze_url(url_input)
            
            # --- LIVE GAUGE SECTION ---
            col_gauge, col_details = st.columns([1, 1])
            
            with col_gauge:
                # Dynamic Color selection
                color = "#28a745" if score > 75 else "#ffa500" if score > 40 else "#d32f2f"
                
                fig = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=score,
                    domain={'x': [0, 1], 'y': [0, 1]},
                    title={'text': "Safety Score", 'font': {'size': 24}},
                    gauge={
                        'axis': {'range': [0, 100], 'tickcolor': "white"},
                        'bar': {'color': color},
                        'bgcolor': "white",
                        'steps': [
                            {'range': [0, 40], 'color': "#f8d7da"},
                            {'range': [40, 75], 'color': "#fff3cd"},
                            {'range': [75, 100], 'color': "#d4edda"}
                        ],
                        'threshold': {'line': {'color': "black", 'width': 4}, 'value': score}
                    }
                ))
                fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', font={'color': "white", 'family': "Arial"})
                st.plotly_chart(fig, use_container_width=True)

            with col_details:
                st.subheader("Scan Report")
                if score > 75:
                    st.success("✅ This URL appears safe.")
                elif score > 40:
                    st.warning("⚠️ Proceed with caution. Issues detected.")
                else:
                    st.error("🛑 DANGER: High probability of phishing.")
                
                for f in findings:
                    st.write(f)

# --- PERMANENT CONTACT FOOTER ---
st.markdown(
    f"""
    <div class="footer">
        <p>For any help or technical support, please contact us. <br>
        <b>Telegram Support ID: @shim_azu64</b></p>
    </div>
    """,
    unsafe_allow_html=True
)
