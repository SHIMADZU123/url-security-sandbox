import streamlit as st
import requests
import base64
import time
import pandas as pd
from tldextract import extract
api_key = st.secrets["VT_API_KEY"]
# --- CONFIG & THEME ---
st.set_page_config(page_title="Vortex Sentinel V3", page_icon="⚡", layout="wide")

# Professional Dark Glassmorphism CSS
st.markdown("""
    <style>
    .stApp { background: #0b0e14; color: #e0e0e0; }
    .status-card { padding: 20px; border-radius: 12px; margin-bottom: 20px; border: 1px solid #30363d; }
    .threat-detected { background: rgba(255, 75, 75, 0.1); border: 1px solid #ff4b4b; color: #ff4b4b; }
    .threat-clean { background: rgba(0, 200, 83, 0.1); border: 1px solid #00c853; color: #00c853; }
    </style>
    """, unsafe_allow_html=True)

# --- VIRUSTOTAL LOGIC ---
def get_vt_report(url, api_key):
    # VT requires URL to be base64 encoded (unpadded) for lookup
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": api_key, "accept": "application/json"}
    
    response = requests.get(api_url, headers=headers)
    return response.json() if response.status_code == 200 else None

# --- UI LAYOUT ---
st.sidebar.title("🛠️ Control Center")
vt_key = st.sidebar.text_input("Enter VirusTotal API Key", type="password", help="Get yours at virustotal.com")
st.sidebar.divider()
st.sidebar.caption("Scan Mode: Heuristic + Global Threat Intelligence")

st.title("⚡ Vortex Sentinel | Cyber Sandbox")
st.markdown("##### Real-time URL threat intelligence & brand validation")

target_url = st.text_input("Target URL:", placeholder="https://suspicious-site.com/login")

if st.button("RUN DEEP SCAN") and target_url:
    if not vt_key:
        st.warning("Please enter a VirusTotal API Key in the sidebar for full power.")
    
    with st.status("Initializing Neural Analysis...", expanded=True) as status:
        # Step 1: Local Heuristics
        st.write("🔍 Running local heuristic checks...")
        ext = extract(target_url)
        is_suspicious_tld = ext.suffix in ['xyz', 'top', 'zip', 'gq']
        
        # Step 2: API Intelligence
        st.write("🌐 Querying VirusTotal Global Database...")
        report = get_vt_report(target_url, vt_key) if vt_key else None
        
        time.sleep(1)
        status.update(label="Scanning Complete", state="complete")

    # --- RESULT DASHBOARD ---
    if report and "data" in report:
        stats = report["data"]["attributes"]["last_analysis_stats"]
        malicious_count = stats["malicious"]
        
        # Threat Banner
        if malicious_count > 0:
            st.markdown(f'<div class="status-card threat-detected"><h3>🚨 THREAT DETECTED: {malicious_count} Engines Flagged This URL</h3></div>', unsafe_allow_html=True)
        else:
            st.markdown(f'<div class="status-card threat-clean"><h3>✅ CLEAN: No known threats detected</h3></div>', unsafe_allow_html=True)

        # Metrics
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Malicious", stats['malicious'], delta_color="inverse")
        c2.metric("Suspicious", stats['suspicious'])
        c3.metric("Harmless", stats['harmless'])
        c4.metric("Engine Total", sum(stats.values()))

        # Detailed Engine Data
        with st.expander("👁️ View Individual Engine Results"):
            results = report["data"]["attributes"]["last_analysis_results"]
            df_results = pd.DataFrame([
                {"Engine": k, "Category": v["category"], "Result": v["result"]} 
                for k, v in results.items()
            ])
            st.table(df_results.sort_values(by="Category"))

    else:
        st.info("Analysis finished with local heuristics. Connect API for deep scan results.")
        if is_suspicious_tld:
            st.error(f"🚩 High Risk TLD detected: .{ext.suffix} is often used in malware.")
