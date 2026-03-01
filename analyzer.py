import streamlit as st
import requests
import base64
import plotly.graph_objects as go
from bs4 import BeautifulSoup
from tldextract import extract

# --- PAGE SETUP ---
st.set_page_config(page_title="Vortex Sentinel Pro", layout="wide")

# --- CSS FOR COMPACT UI ---
st.markdown("""
    <style>
    .preview-box { background-color: #161b22; padding: 20px; border-radius: 10px; border: 1px solid #30363d; }
    .brand-text { color: #58a6ff; font-weight: bold; }
    </style>
    """, unsafe_allow_html=True)

# Secure API Key Fetch
try:
    VT_API_KEY = st.secrets["VT_API_KEY"]
except:
    st.error("🔑 API Key Missing! Add 'VT_API_KEY' to your Streamlit Secrets.")
    st.stop()

# --- FUNCTION: SAFE PREVIEW (SCRAPER) ---
def get_site_preview(url):
    try:
        # We use a generic User-Agent to avoid being blocked, but we don't execute JS
        response = requests.get(url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
        soup = BeautifulSoup(response.content, 'html.parser')
        
        title = soup.title.string if soup.title else "No Title Found"
        meta_desc = soup.find("meta", attrs={"name": "description"})
        desc = meta_desc["content"] if meta_desc else "No description available."
        
        return {"title": title, "desc": desc, "status": "Success"}
    except Exception as e:
        return {"status": "Error", "message": str(e)}

# --- FUNCTION: RISK GAUGE ---
def draw_risk_meter(score):
    fig = go.Figure(go.Indicator(
        mode = "gauge+number",
        value = score,
        domain = {'x': [0, 1], 'y': [0, 1]},
        gauge = {
            'axis': {'range': [0, 100]},
            'bar': {'color': "#21262d"},
            'steps': [
                {'range': [0, 20], 'color': "#238636"},
                {'range': [20, 50], 'color': "#d29922"},
                {'range': [50, 100], 'color': "#da3633"}
            ],
            'threshold': {'line': {'color': "white", 'width': 4}, 'value': score}
        }
    ))
    fig.update_layout(height=250, margin=dict(l=20, r=20, t=40, b=20), paper_bgcolor='rgba(0,0,0,0)', font={'color': "white"})
    return fig

# --- MAIN APP ---
st.title("🛡️ Vortex Sentinel | Pro Sandbox")
url_input = st.text_input("Analyze URL:", placeholder="https://example.com")

if st.button("🔍 START DEEP ANALYSIS") and url_input:
    # 1. VIRUSTOTAL SCAN
    url_id = base64.urlsafe_b64encode(url_input.encode()).decode().strip("=")
    vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    
    with st.spinner("Analyzing Threat Intelligence..."):
        vt_res = requests.get(vt_url, headers={"x-apikey": VT_API_KEY})
        
        if vt_res.status_code == 200:
            data = vt_res.json()['data']['attributes']
            stats = data['last_analysis_stats']
            risk_score = (stats['malicious'] / sum(stats.values())) * 100 if sum(stats.values()) > 0 else 0
            
            # --- LAYOUT: 3 COLUMNS ---
            col1, col2, col3 = st.columns([1, 1, 1])
            
            with col1:
                st.plotly_chart(draw_risk_meter(risk_score), use_container_width=True)
            
            with col2:
                st.subheader("Security Stats")
                st.write(f"🛑 Malicious: **{stats['malicious']}**")
                st.write(f"⚠️ Suspicious: **{stats['suspicious']}**")
                st.write(f"✅ Harmless: **{stats['harmless']}**")
                st.divider()
                st.caption(f"Domain: {extract(url_input).registered_domain}")

            with col3:
                st.subheader("🕵️ Safe Preview")
                preview = get_site_preview(url_input)
                if preview["status"] == "Success":
                    st.markdown(f"""
                    <div class="preview-box">
                        <p class="brand-text">Site Title:</p>
                        <p>{preview['title']}</p>
                        <p class="brand-text">Meta Description:</p>
                        <p style="font-size: 0.8em;">{preview['desc']}</p>
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.error("Could not fetch preview. Site may be offline or blocking scrapers.")

        else:
            st.error("Error connecting to VirusTotal. Check your API key or URL format.")
