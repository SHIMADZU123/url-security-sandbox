import streamlit as st
import requests
import base64
import whois
from datetime import datetime
import re

# --- CONFIGURATION ---
# Replace with your actual VirusTotal API Key
VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY_HERE"

def get_url_id(url):
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

def analyze_link(url):
    score = 100
    reports = []
    
    # 1. VirusTotal Reputation Check (Weight: Critical)
    url_id = get_url_id(url)
    vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": VT_API_KEY}
    
    try:
        response = requests.get(vt_url, headers=headers)
        if response.status_code == 200:
            vt_data = response.json()['data']['attributes']['last_analysis_stats']
            malicious = vt_data.get('malicious', 0)
            if malicious > 0:
                score -= (malicious * 20) # Heavy penalty for each engine flag
                reports.append(f"🚨 {malicious} Security Engines flagged this as Malicious.")
    except:
        reports.append("⚠️ Could not reach Reputation Database.")

    # 2. Domain Age Check (Weight: High)
    try:
        domain_info = whois.whois(url)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list): creation_date = creation_date[0]
        
        if creation_date:
            age_days = (datetime.now() - creation_date).days
            if age_days < 30:
                score -= 40
                reports.append(f"⚠️ Domain is very new ({age_days} days old). High risk of Phishing.")
            else:
                reports.append(f"✅ Domain has established history ({age_days} days).")
    except:
        reports.append("❓ Domain registration details are hidden or unavailable.")

    # 3. Heuristic Check (Weight: Medium)
    # Check for too many subdomains or suspicious keywords
    suspicious_keywords = ['login', 'verify', 'update', 'banking', 'secure']
    if any(keyword in url.lower() for keyword in suspicious_keywords):
        score -= 15
        reports.append("🔍 URL contains sensitive keywords often used in scams.")

    # Final score clamping (0-100)
    final_score = max(0, min(score, 100))
    return final_score, reports

# --- STREAMLIT UI ---
st.set_page_config(page_title="Security Command Center", layout="wide")
st.title("🖥️ Security Command Center")
st.markdown("### INPUT TARGET URL FOR REAL-TIME FORENSICS:")

target_url = st.text_input("Enter URL", placeholder="https://example.com")

if st.button("EXECUTE DEEP SYSTEM SCAN"):
    if target_url:
        # Clean the URL (Fixing the double https:// issue)
        clean_url = target_url.strip().replace("https://https://", "https://")
        
        with st.spinner("Performing Multi-Layered Analysis..."):
            safety_score, intelligence_report = analyze_link(clean_url)
            
            # Display Gauge Logic
            # Note: You should plug 'safety_score' into your Plotly Gauge Chart code here
            st.write(f"## Final Safety Score: {safety_score}%")
            
            # Display Intelligence Report
            with st.expander("🔍 View Threat Intelligence Report", expanded=True):
                for item in intelligence_report:
                    st.write(item)
                
                if safety_score < 50:
                    st.error("VERDICT: HIGH THREAT DETECTED. DO NOT PROCEED.")
                elif safety_score < 80:
                    st.warning("VERDICT: SUSPICIOUS ACTIVITY. PROCEED WITH CAUTION.")
                else:
                    st.success("VERDICT: LINK APPEARS CLEAN.")
    else:
        st.error("Please provide a valid URL.")
