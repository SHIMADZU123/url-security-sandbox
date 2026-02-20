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
# Using highly reliable public CDNs so the images never break on the live web app!
NTU_LOGO_URL = "blob:https://gemini.google.com/c7fde64c-4f15-47c5-9d5a-d5db9a28c12d"
AI_LOGO_URL = "blob:https://gemini.google.com/f7bb8681-8d82-4773-957d-72abc6748727" # Guaranteed public icon server

head_col1, head_col2, head_col3 = st.columns([1, 3, 1])

with head_col1:
    try:
        st.image(NTU_LOGO_URL, use_container_width=True)
    except:
        st.info("🎓 NTU Logo")

with head_col2:
    st.markdown("<h1 style='text-align: center;'>AI Threat Intelligence Dashboard</h1>", unsafe_allow_html=True)
    st.markdown("<h4 style='text-align: center; color: gray;'>Northern Technical University | AI & Computer Engineering</h4>", unsafe_allow_html=True)
    st.markdown("<p style='text-align: center;'>Advanced URL Security & Phishing Detection System</p>", unsafe_allow_html=True)

with head_col3:
    try:
        st.image(AI_LOGO_URL, use_container_width=True)
    except:
        st.info("🧠 AI Logo")

st.divider()
# --- 1. DEEP ANALYSIS FUNCTIONS ---
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

# --- 2. MAIN SECURITY ENGINE ---
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

    # ==========================================
    # NEW: STRUCTURAL URL RED FLAGS ANALYSIS
    # ==========================================
    
    # 1. IP Address Detection (e.g., http://192.168.1.1/login)
    if re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", clean_domain):
        results["score"] -= 40
        results["flags"].append("🚨 **IP Address Domain:** The link uses an IP address instead of a standard name. This is a massive red flag for phishing.")
    
    # 2. "@" Symbol Trick (e.g., http://google.com@baddomain.com)
    if "@" in final_url:
        results["score"] -= 30
        results["flags"].append("🚨 **'@' Symbol Trick:** The link contains an '@' symbol, which hackers use to trick your browser into hiding the real destination.")
    
    # 3. Multiple Subdomains (e.g., login.secure.update.paypal.com.baddomain.com)
    if clean_domain.count(".") >= 3:
        results["score"] -= 15
        results["flags"].append("⚠️ **Too Many Subdomains:** The domain has an unusual number of dots, which is a trick used to mimic legitimate websites.")

    # 4. Hyphenated Domain (e.g., paypal-security.com)
    if "-" in clean_domain:
        results["score"] -= 10
        results["flags"].append("⚠️ **Hyphenated Domain:** The domain contains a hyphen (-). Scammers frequently use hyphens to create fake lookalike domains.")

    # 5. Extremely Long URL
    if len(final_url) > 75:
        results["score"] -= 10
        results["flags"].append("⚠️ **Unusually Long URL:** Hackers often use excessively long links to hide malicious parts of the web address from the user.")

    # ==========================================

    # Keyword Check
    suspicious_words = ['login', 'verify', 'update', 'secure', 'account', 'banking', 'free', 'admin', 'invoice']
    if any(word in final_url.lower() for word in suspicious_words):
        results["score"] -= 20
        results["flags"].append("⚠️ **Phishing Keywords:** The link uses words designed to trick you into entering a password.")

    # SSL Check
    if final_url.startswith("https"):
        ssl_valid, ssl_msg = check_ssl(domain)
        results["ssl_valid"] = ssl_valid
        if not ssl_valid:
            results["score"] -= 25
            results["flags"].append(f"🔓 **Invalid SSL:** Connection is not secure. ({ssl_msg})")
    else:
        results["score"] -= 30
        results["flags"].append("🔓 **No SSL (HTTP):** This site does not use basic encryption.")

    # Domain Age Check
    age = get_domain_age(domain)
    results["age_days"] = age
    if age is not None and age < 30:
        results["score"] -= 30
        results["flags"].append(f"⚠️ **Brand New Domain:** Website is only {age} days old (Common in phishing).")
    elif age is None and not re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", clean_domain):
        results["score"] -= 10
        results["flags"].append("❓ **Hidden WHOIS:** Could not verify the creation date of this website.")

    # VirusTotal Checks
    vt_flags, vt_msg = get_vt_report(final_url)
    results["vt_malicious"] = vt_flags
    if vt_flags > 0:
        results["score"] -= (vt_flags * 15)
        results["flags"].append(f"🚨 **Malware Alert:** {vt_flags} security engines flagged this URL.")
    elif "API Key missing" in str(vt_msg):
        results["flags"].append("🔌 **System Warning:** VirusTotal Database is disconnected (Missing API Key).")

    results["score"] = max(0, results["score"])
    return results

# --- 3. DASHBOARD UI ---
st.markdown("### 🔍 Start URL Inspection")
target_url = st.text_input("Enter target URL for security scanning:", "https://")

if st.button("Initialize Deep Scan", type="primary"):
    if not target_url.startswith("http"):
        st.error("Invalid input. Please enter a valid URL starting with http:// or https://")
    else:
        with st.spinner("Querying global threat intelligence databases..."):
            report = analyze_threat(target_url)
            score = report["score"]

            st.divider()
            
            # Top Section
            col_chart, col_metrics = st.columns([1.5, 2])
            
            with col_chart:
                gauge_color = "#28a745" if score >= 80 else "#ffc107" if score >= 50 else "#dc3545"
                fig = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=score,
                    title={'text': "Calculated Safety Score", 'font': {'size': 24}},
                    gauge={
                        'axis': {'range': [0, 100]},
                        'bar': {'color': gauge_color},
                        'steps': [
                            {'range': [0, 49], 'color': "#ffe6e6"},
                            {'range': [50, 79], 'color': "#fff3cd"},
                            {'range': [80, 100], 'color': "#e2f0e5"}
                        ]
                    }
                ))
                fig.update_layout(height=280, margin=dict(l=20, r=20, t=40, b=20))
                st.plotly_chart(fig, use_container_width=True)

            with col_metrics:
                st.markdown("### Executive Summary")
                if score >= 80:
                    st.success("✅ **STATUS: SECURE** - No critical threats detected.")
                elif score >= 50:
                    st.warning("⚠️ **STATUS: SUSPICIOUS** - Proceed with caution.")
                else:
                    st.error("🛑 **STATUS: MALICIOUS** - High-risk indicators present.")
                
                m1, m2, m3 = st.columns(3)
                m1.metric("VirusTotal Hits", f"{report['vt_malicious']} Flags")
                m2.metric("Domain Age", f"{report['age_days']} Days" if report['age_days'] else "Unknown")
                m3.metric("Encryption", "Valid SSL 🔒" if report['ssl_valid'] else "Invalid 🔓")

            # Middle Section: Findings
            st.subheader("🚩 Threat Indicators Found (The Red Flags)")
            if report["flags"]:
                for flag in report["flags"]:
                    if "🚨" in flag or "🔓" in flag or "🛑" in flag:
                        st.error(flag)
                    elif "🔌" in flag:
                        st.info(flag)
                    else:
                        st.warning(flag)
            else:
                st.info("✨ Clean: Zero threat indicators detected during scan.")

            # Bottom Section: Raw Data
            with st.expander("🔬 View Raw Forensic Data"):
                st.write(f"**Target URL:** `{target_url}`")
                st.write(f"**Resolved Destination:** `{report['final_url']}`")
                st.write(f"**Root Domain:** `{report['domain']}`")
