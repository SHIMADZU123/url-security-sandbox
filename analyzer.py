# app.py
"""
LinkTrust Pro — compact, professional URL risk scorer with percentage and polished UI.
Save as app.py and run with: streamlit run app.py
"""

import os
import math
import re
import ssl
import socket
import statistics
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
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)

st.markdown("<div class='header'><div class='brand'>LinkTrust Pro</div><div class='small'>Percentage risk score • Passive checks • Optional API integrations</div></div>", unsafe_allow_html=True)
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

def hostname_entropy(hostname: str) -> float:
    if not hostname:
        return 0.0
    s = hostname.replace(".", "")
    freqs = [s.count(c) / len(s) for c in set(s)]
    ent = -sum(p * math.log2(p) for p in freqs if p > 0)
    return ent

def is_ip_address(host: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))

def dns_resolves(hostname: str) -> bool:
    try:
        socket.gethostbyname(hostname)
        return True
    except Exception:
        return False

def whois_age_years(hostname: str):
    if not WHOIS_AVAILABLE:
        return None
    try:
        w = whois_lib.whois(hostname)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if created:
            delta = (st._now() if hasattr(st, "_now") else __import__("datetime").datetime.utcnow()) - created
            return delta.days / 365.0
    except Exception:
        return None
    return None

def score_url(raw_url: str, vt_score: float = None) -> dict:
    """
    Returns a dict with:
      - score (0..100) where higher means more risky
      - breakdown: list of (label, weight, contribution)
      - verdict: Good/Moderate/Bad
    """
    raw = (raw_url or "").strip()
    breakdown = []
    score = 0.0

    # 1. Format validity (weight 10)
    if not raw:
        breakdown.append(("Empty URL", 10, 10))
        score += 10
        return finalize(score, breakdown)
    if not raw.startswith(("http://", "https://")):
        raw = "http://" + raw
    if not validators.url(raw):
        breakdown.append(("Invalid format", 15, 15))
        score += 15
        return finalize(score, breakdown)

    parsed = urlparse(raw)
    host = (parsed.hostname or "").lower()

    # 2. Blocklist (weight 30)
    if any(b in host for b in BLOCKLIST_DOMAINS):
        breakdown.append(("Known blocklist", 30, 30))
        score += 30

    # 3. IP address in host (weight 20)
    if is_ip_address(host):
        breakdown.append(("IP address used", 20, 20))
        score += 20

    # 4. Suspicious keywords (weight 18)
    for pat in SUSPICIOUS_PATTERNS:
        if re.search(pat, raw, flags=re.I):
            breakdown.append(("Suspicious keyword", 18, 18))
            score += 18
            break

    # 5. Hostname entropy / length (weight 12)
    ent = hostname_entropy(host)
    if ent > 3.5 or len(host) > 50:
        contrib = 12
        breakdown.append(("High entropy/long host", 12, contrib))
        score += contrib

    # 6. DNS resolution (weight 8)
    if not dns_resolves(host):
        breakdown.append(("DNS does not resolve", 8, 8))
        score += 8

    # 7. Reachability & HTTP status (weight 20)
    http_contrib = 0
    try:
        headers = {"User-Agent": "LinkTrustPro/1.0"}
        resp = requests.get(raw, headers=headers, timeout=6, allow_redirects=True, verify=True)
        status
