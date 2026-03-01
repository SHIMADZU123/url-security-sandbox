# app.py
import re
import ssl
import socket
from urllib.parse import urlparse

import requests
import validators
import streamlit as st

# -------------------------
# Page config and styling
# -------------------------
st.set_page_config(page_title="LinkTrust Checker", page_icon="🔒", layout="centered")

CSS = """
<style>
body { font-family: Inter, system-ui, -apple-system, "Segoe UI", Roboto, Arial; }
.stApp { background: linear-gradient(180deg,#f7fbff 0%, #eef6ff 100%); color: #0b1220; }
.header { display:flex; align-items:center; gap:12px; margin-bottom:10px; }
.brand { font-weight:700; font-size:20px; color:#0b1220; }
.card { background: #ffffff; border-radius:12px; padding:18px; box-shadow: 0 6px 18px rgba(11,18,32,0.06); }
.badge-good { background:#e6f9f0; color:#0b8a5f; padding:8px 12px; border-radius:999px; font-weight:700; }
.badge-bad { background:#fff1f0; color:#b42318; padding:8px 12px; border-radius:999px; font-weight:700; }
.small { color:#6b7280; font-size:13px; }
.kv { display:flex; justify-content:space-between; padding:8px 0; border-bottom:1px dashed #eef2f7; }
.kv:last-child { border-bottom:none; }
input[type="text"] { padding:10px; border-radius:8px; border:1px solid #e6eef8; width:100%; }
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)

HEADER_HTML = """
<div class='header'>
  <div class='brand'>LinkTrust Checker</div>
  <div class='small'>Fast, clear verdicts for links</div>
</div>
<div class='card'>
"""
st.markdown(HEADER_HTML, unsafe_allow_html=True)

# -------------------------
# Heuristics and helpers
# -------------------------
SUSPICIOUS_PATTERNS = [
    r"login\.", r"signin", r"verify", r"confirm", r"account", r"update", r"secure", r"free-?gift",
    r"\.zip$", r"\.exe$", r"@.*\.", r"\/\/.*\..*\/.*\..*\/"
]

BLOCKLIST_DOMAINS = {
    "malicious-example.test",
    "bad-domain.test"
}

def is_suspicious_url(parsed, raw):
    host = (parsed.netloc or "").lower()
    if any(b in host for b in BLOCKLIST_DOMAINS):
        return True, "Domain is on a local blocklist"
    for pat in SUSPICIOUS_PATTERNS:
        if re.search(pat, raw, flags=re.I):
            return True, "URL contains suspicious keywords or file types"
    if len(host) > 60 or host.count(".") >= 5:
        return True, "Unusually long or deeply nested domain"
    return False, ""

def check_ssl(hostname, port=443, timeout=4):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        return True, cert
    except Exception:
        return False, None

def analyze_link(raw_url, timeout=8):
    result = {"url": raw_url, "valid": False, "reachable": False, "https": False,
              "status_code": None, "final_url": None, "redirects": 0, "suspicious": False, "reason": ""}
    raw_url = (raw_url or "").strip()
    if not raw_url:
        result["reason"] = "No URL provided"
        return result

    if not raw_url.startswith(("http://", "https://")):
        raw_url = "http://" + raw_url
    result["url"] = raw_url

    if not validators.url(raw_url):
        result["reason"] = "Invalid URL format"
        return result
    result["valid"] = True

    parsed = urlparse(raw_url)
    suspicious, sreason = is_suspicious_url(parsed, raw_url)
    result["suspicious"] = suspicious
    if suspicious:
        result["reason"] = sreason

    headers = {"User-Agent": "LinkTrust/1.0"}
    try:
        resp = requests.get(raw_url, headers=headers, timeout=timeout, allow_redirects=True, verify=True)
        result["reachable"] = True
        result["status_code"] = resp.status_code
        result["final_url"] = resp.url
        result["redirects"] = len(resp.history)
        result["https"] = resp.url.startswith("https://")
        if resp.status_code >= 400:
            result["reason"] = f"Server returned status {resp.status_code}"
    except requests.exceptions.SSLError:
        result["reason"] = "SSL/TLS error"
    except requests.exceptions.ConnectTimeout:
        result["reason"] = "Connection timed out"
    except requests.exceptions.RequestException as e:
        result["reason"] = f"Network error: {str(e)}"

    if parsed.hostname:
        ok, cert = check_ssl(parsed.hostname)
        if not ok and result["https"]:
            result["reason"] = result["reason"] or "HTTPS present but SSL check failed"

    return result

# -------------------------
# UI controls
# -------------------------
url_input = st.text_input("Enter a link to check", placeholder="https://example.com")
col1, col2 = st.columns([3,1])
with col2:
    run = st.button("Check Link", key="check")

if run:
    with st.spinner("Checking link…"):
        res = analyze_link(url_input)
    verdict = "Good"
    badge_class = "badge-good"
    explanation = "This link looks safe."
    if not res["valid"]:
        verdict = "Bad"; badge_class = "badge-bad"; explanation = res["reason"] or "Invalid link format."
    elif not res["reachable"]:
        verdict = "Bad"; badge_class = "badge-bad"; explanation = res["reason"] or "Could not reach the site."
    elif res["suspicious"]:
        verdict = "Bad"; badge_class = "badge-bad"; explanation = res["reason"] or "Suspicious patterns detected."
    elif res["status_code"] and res["status_code"] >= 400:
        verdict = "Bad"; badge_class = "badge-bad"; explanation = f"Site returned status {res['status_code']}."
    elif not res["https"]:
        verdict = "Bad"; badge_class = "badge-bad"; explanation = "Site is not using HTTPS; connection may be insecure."

    st.markdown(
        f"<div style='display:flex;align-items:center;gap:12px'><div class='{badge_class}'>{verdict}</div>"
        f"<div class='small'>{explanation}</div></div>",
        unsafe_allow_html=True
    )

    st.markdown("<hr/>", unsafe_allow_html=True)
    st.markdown("**Quick details**")
    st.markdown(
        f"<div class='kv'><div><strong>Final URL</strong><div class='small'>{res.get('final_url') or res.get('url')}</div></div>"
        f"<div><strong>Status</strong><div class='small'>{res.get('status_code') or '—'}</div></div></div>",
        unsafe_allow_html=True
    )
    st.markdown(
        f"<div class='kv'><div><strong>HTTPS</strong><div class='small'>{'Yes' if res.get('https') else 'No'}</div></div>"
        f"<div><strong>Redirects</strong><div class='small'>{res.get('redirects')}</div></div></div>",
        unsafe_allow_html=True
    )
else:
    st.markdown("<div class='small' style='margin-top:8px'>Paste a link above and click Check Link for a clear Good / Bad verdict.</div>", unsafe_allow_html=True)

st.markdown("</div>", unsafe_allow_html=True)
st.markdown("<div style='margin-top:12px;color:#6b7280;font-size:12px'>LinkTrust Checker provides a quick, passive assessment only. For high-risk decisions, use a dedicated security service.</div>", unsafe_allow_html=True)
