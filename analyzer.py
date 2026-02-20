import streamlit as st
import requests
import whois
import ssl
import socket
import urllib.parse
from datetime import datetime
import base64
import plotly.graph_objects as go

# --- 1. DEEP ANALYSIS FUNCTIONS ---

def unshorten_url(url):
    """Follows redirects to find the true destination of a shortened link."""
    try:
        session = requests.Session()
        response = session.head(url, allow_redirects=True, timeout=5)
        return response.url
    except:
        return url

def get_domain_age(domain):
    """Checks the WHOIS record to see how old the domain is (in days)."""
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if type(creation_date) is list:
            creation_date = creation_date[0]
        if creation_date:
            age = (datetime.now() - creation_date).days
            return age
        return None
    except:
        return None

def check_ssl(domain):
    """Verifies if the domain has a valid SSL certificate."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return True, "Valid SSL Certificate"
    except Exception as e:
        return False, str(e)

def get_vt_report(url):
    """Checks VirusTotal for malicious flags."""
    try:
        if "VT_API_KEY" not in st.secrets:
            return 0, "VirusTotal API Key missing in Streamlit Secrets."
        api_key = st.secrets["VT_API_KEY"]
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": api_key}
        response = requests.get(vt_url, headers=headers)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            return stats.get('malicious', 0), stats
        return 0, "Error connecting to VirusTotal."
    except:
        return 0, "API Error"

# --- 2. MAIN SECURITY ENGINE ---

def analyze_threat(raw_url):
    results = {
        "score": 100, 
        "flags": [], 
        "final_url": "", 
        "domain": "", 
        "age_days": None,
        "ssl_valid": False,
        "vt_malicious": 0
    }
    
    # 1. Unshorten the URL
    final_url = unshorten_url(raw_url)
    results["final_url"] = final_url
    
    if raw_url != final_url:
        results["flags"].append("🔀 **URL Redirect:** The original link was shortened to hide the true destination.")
        results["score"] -= 10

    # Extract Domain
    parsed_url = urllib.parse.urlparse(final_url)
    domain = parsed_url.netloc
    results["domain"] = domain

    # 2. SSL Check
    if parsed_url.scheme == "https":
        ssl_valid, ssl_msg = check_ssl(domain)
        results["ssl_valid"] = ssl_valid
        if not ssl_valid:
            results["score"] -= 25
            results["flags"].append(f"🔓 **Invalid SSL:** Connection is not secure. ({ssl_msg})")
    else:
        results["score"] -= 30
        results["flags"].append("🔓 **No SSL (HTTP):** This site does not use basic encryption.")

    # 3. Domain Age (WHOIS)
    age = get_domain_age(domain)
    results["age_days"] = age
    if age is not None:
        if age < 30:
            results["score"] -= 30
            results["flags"].append(f"⚠️ **Brand New Domain:** This website is only {age} days old. Phishing sites are rarely older than a few weeks.")
    else:
        results["flags"].append("❓ **Hidden WHOIS:** Could not verify when this website was created.")

    # 4. VirusTotal Intelligence
    vt_flags, vt_raw = get_vt_report(final_url)
    results["vt_malicious"] = vt_flags
    if vt_flags > 0:
        results["score"] -= (vt_flags * 15)
        results["flags"].append(f"🚨 **VirusTotal Alert:** {vt_flags} security engines flagged this URL as MALICIOUS.")

    # Ensure score doesn't drop below 0
    results["score"] = max(0, results["score"])
    return results

# --- 3. UI / DASHBOARD ---

st.set_page_config(page_title="Threat Intel Dashboard", page_icon="🛡️", layout="wide")

st.title("🛡️ Threat Intelligence Dashboard")
st.markdown("Analyze URLs for hidden redirects, domain age, SSL validity, and malware signatures.")

target_url = st.text_input("Enter URL to scan:", "https://")

if st.button("Run Deep Analysis"):
    if not target_url.startswith("http"):
        st.error("Please enter a valid URL starting with http:// or https://")
    else:
        with st.spinner("Running global intelligence checks..."):
            report = analyze_threat(target_url)
            score = report["score"]

            # --- TOP SECTION: Visual Verdict ---
            col1, col2 = st.columns([1, 2])
            
            with col1:
                # Plotly Gauge Chart
                gauge_color = "green" if score >= 80 else "orange" if score >= 50 else "red"
                fig = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=score,
                    title={'text': "Security Score"},
                    gauge={
                        'axis': {'range': [0, 100]},
                        'bar': {'color': gauge_color},
                        'steps': [
                            {'range': [0, 49], 'color': "#ffcccc"},
                            {'range': [50, 79], 'color': "#ffe6cc"},
                            {'range': [80, 100], 'color': "#ccffcc"}
                        ]
                    }
                ))
                fig.update_layout(height=250, margin=dict(l=20, r=20, t=30, b=20))
                st.plotly_chart(fig, use_container_width=True)

            with col2:
                st.markdown("### Executive Summary")
                if score >= 80:
                    st.success("✅ **LIKELY SAFE:** No major threats detected.")
                elif score >= 50:
                    st.warning("⚠️ **SUSPICIOUS:** Proceed with caution. Review the flags below.")
                else:
                    st.error("🛑 **HIGH RISK:** This link exhibits severe malicious traits. DO NOT CLICK.")
                
                # Streamlit Metrics
                m1, m2, m3 = st.columns(3)
                m1.metric("VT Detections", f"{report['vt_malicious']} Engines")
                m2.metric("Domain Age", f"{report['age_days']} Days" if report['age_days'] else "Unknown")
                m3.metric("SSL Status", "Valid 🔒" if report['ssl_valid'] else "Invalid 🔓")

            st.divider()

            # --- MIDDLE SECTION: Red Flags ---
            st.subheader("🚩 Threat Indicators")
            if report["flags"]:
                for flag in report["flags"]:
                    st.error(flag) if "🚨" in flag else st.warning(flag)
            else:
                st.info("✨ No threat indicators found.")

            # --- BOTTOM SECTION: Technical Details (Collapsible) ---
            with st.expander("🔬 View Raw Technical Data (For Analysts)"):
                st.write("**Original URL:**", target_url)
                st.write("**Final Destination:**", report["final_url"])
                st.write("**Extracted Domain:**", report["domain"])
                st.json(report)
