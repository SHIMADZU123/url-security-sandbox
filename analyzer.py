# app.py
"""
LinkTrust Pro — compact URL risk scorer with percentage and polished UI.
Save as app.py and run with: streamlit run app.py
"""

import os
import math
import re
import ssl
import socket
import datetime
from urllib.parse import urlparse

import requests
import validators
import streamlit as st

# Optional whois (best-effort)
try:
    import whois as whois_lib
    WHOIS_AVAILABLE = True
except Exception:
    WHOIS_AVAILABLE = False

# -------------------------
# Page config and styling
# -------------------------
st.set_page_config(page_title="LinkTrust Pro", page_icon="🔒", layout="centered")

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');
html, body, [class*="css"] { font-family: Inter, system-ui, -apple-system, "Segoe UI", Roboto, Arial; }
.stApp { background: linear-gradient(180deg,#f8fbff 0%, #eef6ff 100%); color: #0b1220; }
.header { display:flex; align-items:center; justify-content:space-between; gap:12px; margin-bottom:18px; }
.brand { font-weight:700; font-size:20px; color:#0b1220; }
.card { background: linear-gradient(180deg, rgba(255,255,255,0.95), rgba(255,255,255,0.9)); border-radius:14px; padding:20px; box-shadow: 0 10px 30px rgba(15,23,42,0.06); width:100%; max-width:900px; margin:auto; }
.input-row { display:flex; gap:12px; align-items:center; }
.input { flex:1; }
.btn { background: linear-gradient(90deg,#0ea5a4,#06b6d4); color:white; padding:10px 14px; border-radius:10px; border:none; font-weight:700; }
.gauge { display:flex; align-items:center; gap:18px; margin-top:12px; }
.score-circle { width:120px; height:120px; border-radius:999px; display:flex; align-items:center; justify-content:center; font-weight:800; font-size:28px; color:white; }
.good { background: linear-gradient(90deg,#10b981,#059669); box-shadow: 0 6px 18px rgba(16,185,129,0.18); }
.warn { background: linear-gradient(90deg,#f59e0b,#f97316); box-shadow: 0 6px 18px rgba(245,158,11,0.12); }
.bad { background: linear-gradient(90deg,#ef4444,#b91c1c); box-shadow: 0 6px 18px rgba(239,68,68,0.12); }
.small { color:#475569; font-size:13px; }
.kv { display:flex; justify-content:space-between; padding:8px 0; border-bottom:1px dashed #eef2f7; }
.kv:last-child { border-bottom:none; }
.detail { background:#f8fafc; padding:10px; border-radius:8px; font-size:13px; color:#0b1220; }
.footer { color:#94a3b8; font-size:12px; margin-top:12px; text-align:center; }
.badge { font-size:12px; padding:6px 10px; border-radius:999px; background:#eef2ff; color:#0369a1; font-weight:700; }
.copy { background:#f1f5f9; padding:8px 10px; border-radius:8px; font-size:13px; color:#0b1220; }
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)

st.markdown(
    """
    <div class='header'>
      <div class='brand'>LinkTrust Pro</div>
      <div class='small'>Percentage risk score • Passive checks • Optional API integrations</div>
    </div>
    """,
    unsafe_allow_html=True,
)
st.markdown("<div class='card'>", unsafe_allow_html=True)

# -------------------------
# Heuristics and scoring
# -------------------------
SUSPICIOUS_PATTERNS = [
    r"login\.", r"signin", r"verify", r"confirm", r"account", r"update", r"secure",
    r"free-?gift", r"\.zip$", r"\.exe$", r"download", r"pay", r"invoice", r"bank",
    r"password", r"reset", r"token", r"verify-email"
]

BLOCKLIST_DOMAINS = {"malicious-example.test", "bad-domain.test"}  # extendable

def hostname_entropy(hostname
