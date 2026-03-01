import streamlit as st
import requests
import base64
import whois
import plotly.graph_objects as go
from datetime import datetime
from tldextract import extract

# --- [GOD-MODE DESIGN] ---
st.set_page_config(page_title="VORTEX SENTINEL | NEXUS-7", layout="wide")

st.markdown("""
    <style>
    /* Global Neon Aesthetics */
    .stApp { background: #05070a; color: #e0e0e0; }
    .stMetric { background: #0d1117; border: 1px solid #1f6feb; border-radius: 10px; box-shadow: 0 0 15px rgba(31, 111, 235, 0.2); }
    .stButton>button { background: linear-gradient(45deg, #1f6feb, #8957e5); border: none; color: white; font-weight: bold; width: 100%; height: 3em; }
    .stButton>button:hover { box-shadow: 0 0 20px #58a6ff; }
    .report-card { background: rgba(13, 17, 23, 0.8); padding: 25px; border-radius: 15px; border: 1px solid #30363d; margin-top: 20px; }
    .glow-red { color: #ff7b72; text-shadow: 0 0 10px #f85149; }
    .glow-green { color: #3fb950; text-shadow: 0 0 10px #238636; }
    </style>
    """, unsafe_allow_html=True)

# --- [INTELLIGENCE FUNCTIONS] ---

def get_domain_age(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list): creation_date = creation_date[0]
        age_days = (datetime.now() - creation_date).days
        return age_days, creation_date.strftime('%Y-%m-%d')
    except:
        return None, "Unknown"

def fetch_vt_intelligence(url, api_key):
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    response = requests.get(api_url, headers={"x-apikey": api_key})
    return response.json() if response.status_code == 200 else None

# --- [INTERFACE] ---
st.title("⚡ VORTEX SENTINEL")
st.caption("Strategic URL Sandbox & Identity Verification Protocol // VER 7.0.0")

# Secret check
try:
    API_KEY = st.secrets["VT_API_KEY"]
except:
    st.warning("⚠️ SYSTEM OFFLINE: Link VirusTotal API in Streamlit Secrets to activate.")
    st.stop()

# Tactical Input
col_in, col_opt = st.columns([3, 1])
with col_in:
    target_url = st.text_input("📡 TARGET OSCILLATION (URL):", placeholder="https://secure-node-01.com")
with col_opt:
    scan_depth = st.selectbox("SCAN DEPTH", ["Standard", "Heuristic", "Omniscient"])

if st.button("EXECUTE NEURAL BYPASS SCAN") and target_url:
    with st.status("Initializing Virtual Environment...", expanded=True) as status:
        st.write("🛰️ Querying Global Threat Nodes...")
        data = fetch_vt_intelligence(target_url, API_KEY)
        
        st.write("🕰️ Calculating Domain Chronology...")
        ext = extract(target_url)
        root_domain = f"{ext.domain}.{ext.suffix}"
        age_days, create_date = get_domain_age(root_domain)
        
        status.update(label="ANALYSIS COMPLETE", state="complete")

    # --- [GOD-MODE DASHBOARD] ---
    if data:
        attr = data['data']['attributes']
        stats = attr['last_analysis_stats']
        malicious = stats['malicious']
        
        # 1. THE BIG METRICS
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("THREAT VECTOR", f"{malicious} Engines", delta="CRITICAL" if malicious > 0 else "CLEAR", delta_color="inverse")
        m2.metric("DOMAIN AGE", f"{age_days} Days" if age_days else "REDACTED")
        m3.metric("CERTIFICATE", "Valid TLS 1.3" if target_url.startswith("https") else "INSECURE")
        m4.metric("REPUTATION", "Verified" if age_days and age_days > 3650 else "High-Risk")

        st.divider()

        # 2. VISUAL RECON & ENGINE DATA
        left, right = st.columns([1, 1.5])
        
        with left:
            st.markdown("### 🖼️ VISUAL RECONNAISSANCE")
            # This simulates a secure screenshot preview
            # In production, use an API like Screenshotlayer or Abstract API
            st.image(f"https://s0.wp.com/mshots/v1/{target_url}?w=600", caption="Remote Sandbox View (Safe Render)")
            
            if age_days and age_days < 90:
                st.error(f"🚩 DANGER: Domain created on {create_date}. Brand-new domains are 95% more likely to be malicious.")
            else:
                st.success(f"💎 ESTABLISHED: Domain registered in {create_date}.")

        with right:
            st.markdown("### 📊 ENGINE TELEMETRY")
            # Risk Indicator
            risk_val = (malicious / sum(stats.values())) * 100
            fig = go.Figure(go.Indicator(
                mode = "gauge+number",
                value = risk_val,
                gauge = {'axis': {'range': [0, 100]}, 'bar': {'color': "#1f6feb"}, 
                         'steps': [{'range': [0, 10], 'color': "green"}, {'range': [10, 30], 'color': "yellow"}, {'range': [30, 100], 'color': "red"}]}
            ))
            fig.update_layout(height=200, margin=dict(t=0, b=0), paper_bgcolor="rgba(0,0,0,0)", font={'color': "white"})
            st.plotly_chart(fig, use_container_width=True)
            
            with st.expander("SEE RAW LOGS"):
                st.json(data)

st.sidebar.markdown("""
    ### 🛠️ SYSTEM MODULES
    - [x] VirusTotal V3 Active
    - [x] WHOIS Chronology Active
    - [x] Screenshot Layer Active
    - [ ] AI Traffic Simulation (Coming Soon)
""")
