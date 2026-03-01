# app.py
import re
import ssl
import socket
from urllib.parse import urlparse

import requests
import validators
import streamlit as st

# Page config
st.set_page_config(page_title="LinkTrust", page_icon="🔒", layout="centered")

# Styling
CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');
html, body, [class*="css"]  { font-family: Inter, system-ui, -apple-system, "Segoe UI", Roboto, Arial; }
.stApp { background: linear-gradient(180deg,#f6fbff 0%, #eef6ff 100%); color: #0b1220; }
.header { display:flex; align-items:center; gap:14px; margin-bottom:14px; }
.brand { font-weight:700; font-size:22px; color:#0b1220; }
.tagline { color:#475569; font-size:13px; }
.card { background: rgba(255,255,255,0.9); border-radius:14px; padding:20px; box-shadow: 0 8px 30px rgba(15,23,42,0.06); }
.input-row { display:flex; gap:12px; align-items:center; }
.input { flex:1; }
.btn { background: linear-gradient(90deg,#0ea5a4,#06b6d4); color:white; padding:10px 14px; border-radius:10px; border:none; font-weight:600; }
.badge-good { background:#ecfdf5; color:#027a48; padding:14px 20px; border-radius:999px; font-weight:700; font-size:20px; }
.badge-bad { background:#fff1f0; color:#9b1c1c; padding:14px 20px; border-radius:999px; font-weight:700; font-size:20px; }
.small { color:#64748b; font-size:13px; }
.kv { display:flex; justify-content:space-between; padding:8px 0; border-bottom:1px dashed #eef2f7; }
.kv:last-child { border-bottom:none; }
.copy { background:#f1f5f9; padding:8px 10px; border-radius:8px; font-size:13px; color:#0b1220; }
.footer { color:#94a3b8; font-size:12px; margin-top:12px; text-align:center; }
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)

# Header
st.markdown("<div class='header'><div class='brand'>LinkTrust</div><div class='tagline'>Fast, clear verdicts for links</div></div>", unsafe_allow_html=True)

# Card
st.markdown("<div class='card'>", unsafe_allow_html=True)

# Heuristics
SUSPICIOUS_PATTERNS = [r"login\.", r"signin", r"verify", r"confirm", r"account", r"update", r"secure", r"free-?gift", r"\.zip$", r"\.exe$"]
BLOCKLIST_DOMAINS = {"malicious-example.test", "bad-domain.test"}

def is_suspicious(parsed, raw):
    host = (parsed.netloc or "").lower()
    if any(b in host for b in BLOCKLIST_DOMAINS):
        return True, "Domain is on a blocklist"
    for pat in SUSPICIOUS_PATTERNS:
        if re.search(pat, raw, flags=re.I):
            return True, "Contains suspicious keywords or file types"
    if len(host) > 60 or host.count(".") >= 5:
        return True, "Unusually long or deeply nested domain"
    return False, ""

def quick_ssl_check(hostname, port=443, timeout=3):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                ssock.getpeercert()
        return True
    except Exception:
        return False

def analyze(url_text, timeout=6):
    out = {"valid": False, "reachable": False, "https": False, "status": None, "final": None, "suspicious": False, "reason": ""}
    raw = (url_text or "").strip()
    if not raw:
        out["reason"] = "No link provided"
        return out
    if not raw.startswith(("http://", "https://")):
        raw = "http://" + raw
    out["final"] = raw
    if not validators.url(raw):
        out["reason"] = "Invalid link format"
        return out
    out["valid"] = True
    parsed = urlparse(raw)
    susp, sreason = is_suspicious(parsed, raw)
    out["suspicious"] = susp
    if susp:
        out["reason"] = sreason
    headers = {"User-Agent": "LinkTrust/1.0"}
    try:
        r = requests.get(raw, headers=headers, timeout=timeout, allow_redirects=True, verify=True)
        out["reachable"] = True
        out["status"] = r.status_code
        out["final"] = r.url
        out["https"] = r.url.startswith("https://")
        if r.status_code >= 400:
            out["reason"] = f"Server returned {r.status_code}"
    except requests.exceptions.SSLError:
        out["reason"] = "SSL/TLS error"
    except requests.exceptions.ConnectTimeout:
        out["reason"] = "Connection timed out"
    except requests.exceptions.RequestException as e:
        out["reason"] = "Network error"
    # quick SSL sanity
    if parsed.hostname and out["https"]:
        if not quick_ssl_check(parsed.hostname):
            out["reason"] = out["reason"] or "HTTPS present but certificate check failed"
    return out

# Input and action
col1, col2 = st.columns([4,1])
with col1:
    url = st.text_input("Enter link", placeholder="https://example.com")
with col2:
    check = st.button("Check", key="check", help="Click to analyze the link")

if check:
    with st.spinner("Analyzing link…"):
        result = analyze(url)
    # Verdict
    verdict = "Good"
    badge = "badge-good"
    explanation = "This link appears safe."
    if not result["valid"]:
        verdict = "Bad"; badge = "badge-bad"; explanation = result["reason"] or "Invalid link."
    elif not result["reachable"]:
        verdict = "Bad"; badge = "badge-bad"; explanation = result["reason"] or "Cannot reach site."
    elif result["suspicious"]:
        verdict = "Bad"; badge = "badge-bad"; explanation = result["reason"] or "Suspicious content detected."
    elif result["status"] and result["status"] >= 400:
        verdict = "Bad"; badge = "badge-bad"; explanation = f"Site returned status {result['status']}."
    elif not result["https"]:
        verdict = "Bad"; badge = "badge-bad"; explanation = "Site is not using HTTPS."

    # Big verdict row
    st.markdown(
        f"<div style='display:flex;align-items:center;gap:16px;margin-top:12px'>"
        f"<div class='{badge}'>{verdict}</div>"
        f"<div class='small'>{explanation}</div>"
        f"</div>",
        unsafe_allow_html=True
    )

    # Quick details
    st.markdown("<hr/>", unsafe_allow_html=True)
    st.markdown("<div class='small'><strong>Quick details</strong></div>", unsafe_allow_html=True)
    final_url = result.get("final") or ""
    status = result.get("status") or "—"
    https = "Yes" if result.get("https") else "No"
    redirects = "Yes" if final_url and final_url != (url if url.startswith(("http://","https://")) else "http://"+url) else "No"

    st.markdown(
        f"<div class='kv'><div><strong>Final URL</strong><div class='small copy'>{final_url}</div></div>"
        f"<div><strong>Status</strong><div class='small'>{status}</div></div></div>",
        unsafe_allow_html=True
    )
    st.markdown(
        f"<div class='kv'><div><strong>HTTPS</strong><div class='small'>{https}</div></div>"
        f"<div><strong>Redirects</strong><div class='small'>{redirects}</div></div></div>",
        unsafe_allow_html=True
    )

    # Copy button (Streamlit native)
    st.write("")  # spacing
    st.download_button("Copy final URL", data=final_url, file_name="final_url.txt", mime="text/plain")

else:
    st.markdown("<div class='small' style='margin-top:12px'>Paste a link and click Check for a clear Good or Bad verdict.</div>", unsafe_allow_html=True)

st.markdown("</div>", unsafe_allow_html=True)
st.markdown("<div class='footer'>LinkTrust provides a quick passive check. For critical decisions use a dedicated security service.</div>", unsafe_allow_html=True)
