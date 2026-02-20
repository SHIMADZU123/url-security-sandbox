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

# --- EDUCATIONAL SIDEBAR ---
with st.sidebar:
    st.markdown("### 📚 Security Education")
    st.markdown("What Red Flags does our AI look for?")
    st.error("🚨 **Structural Tricks:**\nHackers use tricks like IP addresses instead of domains, or the `@` symbol to hide the real website.")
    st.warning("⚠️ **Brand New Domains:**\nPhishing sites are often shut down quickly. A website less than 30 days old is highly suspicious.")
    st.info("🔓 **Missing Encryption (SSL):**\nLegitimate websites encrypt your data. If a site uses `http://` instead of `https://`, hackers can intercept your passwords.")
    st.warning("🔀 **Hidden Redirects:**\nHackers use link shorteners (like bit.ly) to hide the true, dangerous destination of a link.")
    st.error("🎣 **Phishing Keywords:**\nScam links often try to create urgency using words like 'login', 'verify', or 'invoice'.")

# --- PROFESSIONAL ACADEMIC HEADER ---
head_col1, head_col2, head_col3 = st.columns([1, 3, 1])

with head_col1:
    try:
        st.image("NTU logo.jpg", use_container_width=True)
    except Exception:
        st.error("There Is An Error, Please Contact us. Telegram ID: @shim_azu64")

with head_col2:
    st.markdown("<h1 style='text-align: center;'>Welcome to the AI Threat Intelligence</h1>", unsafe_allow_html=True)
    st.markdown("<h4 style='text-align: center; color: gray;'>Powered by Northern Technical University | AI & Computer Engineering College Students</h4>", unsafe_allow_html=True)
    st.markdown("<p style='text-align: center;'>Advanced URL Security & Phishing Detection System</p>", unsafe_allow_html=True)

with head_col3:
    try:
        st.image("collegue logo.jpg", use_container_width=True)
    except Exception:
        st.error("There Is An Error, Please Contact us. Telegram ID: @shim_azu64")

st.divider()

# --- 1. ANALYSIS FUNCTIONS ---
def unshorten_url(url):
    try:
        session = requests.Session()
        response = session.head(url, allow_redirects=True, timeout=5)
        return response.url
    except:
        return url

def get_domain_age(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if type(creation_date) is list:
            creation_date = creation_date[0]
        if creation_date:
            return (datetime.now() - creation_date).days
        return None
    except:
        return None

def check_ssl(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                return True, "Valid SSL Certificate"
    except Exception as e:
        return False, str(e)

def get_vt_report(url):
    try:
        if "VT_API_KEY" not in st.secrets:
            return 0, "API Key missing."
        api_key = st.secrets["VT_API_KEY"]
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        response = requests.get(vt_url, headers={"x-apikey": api_key})
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            return stats.get('malicious', 0), stats
        return 0, "API Error"
    except:
        return 0, "API Error"

# --- 2. SECURITY ENGINE ---
def analyze_threat(raw_url):
    results = {"score": 100, "flags": [], "final_url": "", "domain": "", "age_days": None, "ssl_valid": False, "vt_malicious": 0}
    
    final_url = unshorten_url(raw_url)
    results["final_url"] = final_url
    if raw_url != final_url:
        results["flags"].append("🔀 **URL Redirect:** The original link was shortened to hide the true destination.")
        results["score"] -= 10

    domain = urllib.parse.urlparse(final_url).netloc
    results["domain"] = domain
    clean_domain = domain.replace("www.", "")

    if re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", clean_domain):
        results["score"] -= 40
        results["flags"].append("🚨 **IP Address Domain:** The link uses an IP address instead of a standard name.")
    
    if "@" in final_url:
        results["score"] -= 30
        results["flags"].append("🚨 **'@' Symbol Trick:** The link contains an '@' symbol, used to hide the real destination.")
    
    if clean_domain.count(".") >= 3:
        results["score"] -= 15
        results["flags"].append("⚠️ **Too Many Subdomains:** The domain has an unusual number of dots.")

    if "-" in clean_domain:
        results["score"] -= 10
        results["flags"].append("⚠️ **Hyphenated Domain:** Scammers use hyphens to create fake lookalike domains.")

    if len(final_url) > 75:
        results["score"] -= 10
        results["flags"].append("⚠️ **Unusually Long URL:** Excessively long links can hide malicious parts of the address.")

    suspicious_words = ['login', 'verify', 'update', 'secure', 'account', 'banking', 'free', 'admin', 'invoice']
    if any(word in final_url.lower() for word in suspicious_words):
        results["score"] -= 20
        results["flags"].append("⚠️ **Phishing Keywords:** The link uses words designed to trick you into entering a password.")

    if final_url.startswith("https"):
        ssl_valid, ssl_msg = check_ssl(domain)
        results["ssl_valid"] = ssl_valid
        if not ssl_valid:
            results["score"] -= 25
            results["flags"].append(f"🔓 **Invalid SSL:** Connection is not secure. ({ssl_msg})")
    else:
        results["score"] -= 30
        results["flags"].append("🔓 **No SSL (HTTP):** This site does not use basic encryption.")

    age = get_domain_age(domain)
    results["age_days"] = age
    if age is not None and age < 30:
        results["score"] -= 30
        results["flags"].append(f"⚠️ **Brand New Domain:** Website is only {age} days old (Common in phishing).")
    elif age is None and not re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", clean_domain):
        results["score"] -= 10
        results["flags"].append("❓ **Hidden WHOIS:** Could not verify the creation date of this website.")

    vt_flags, vt_msg = get_vt_report(final_url)
    results["vt_malicious"] = vt_flags
    if vt_flags > 0:
        results["score"] -= (vt_flags * 15)
        results["flags"].append(f"🚨 **Malware Alert:** {vt_flags} security engines flagged this URL.")

    results["score"] = max(0, min(100, results["score"]))
    return results

# --- 3. DASHBOARD UI ---
st.markdown("### 🔍 Start URL Inspection")
target_url = st.text_input("Enter target URL for security scanning:", "https://")

if st.button("Initialize Deep Scan", type="primary"):
    parsed_url = urllib.parse.urlparse(target_url)
    
    if not target_url.startswith("http") or not parsed_url.netloc:
        st.error("The link is invalid.")
    else:
        with st.spinner("Querying global threat intelligence databases..."):
            try:
                report = analyze_threat(target_url)
                score = report["score"]
    
                st.divider()
                col_chart, col_metrics = st.columns([1.5, 2])
                
                with col_chart:
                    gauge_color = "#28a745" if score >= 80 else "#ffc107" if score >= 50 else "#dc3545"
                    fig = go.Figure(go.Indicator(
                        mode="gauge+number",
                        value=score,
                        title={'text': "Safety Score", 'font': {'size': 24}},
                        gauge={'axis': {'range': [0, 100]}, 'bar': {'color': gauge_color}}
                    ))
                    fig.update_layout(height=280, margin=dict(l=20, r=20, t=40, b=20))
                    st.plotly_chart(fig, use_container_width=True)
    
                with col_metrics:
                    st.markdown("### Executive Summary")
                    if score >= 80:
                        st.success("✅ **STATUS: SECURE**")
                    elif score >= 50:
                        st.warning("⚠️ **STATUS: SUSPICIOUS**")
                    else:
                        st.error("🛑 **STATUS: MALICIOUS**")
                    
                    m1, m2, m3 = st.columns(3)
                    m1.metric("VT Flags", f"{report['vt_malicious']}")
                    m2.metric("Domain Age", f"{report['age_days']}d" if report['age_days'] else "N/A")
                    m3.metric("SSL Status", "Secure 🔒" if report['ssl_valid'] else "Insecure 🔓")
    
                st.subheader("🚩 Threat Indicators")
                if report["flags"]:
                    for flag in report["flags"]:
                        st.write(flag)
                else:
                    st.info("✨ Clean: No structural threats detected.")
                    
            except Exception:
                st.error("There Is An Error, Please Contact us. Telegram ID: @shim_azu64")
