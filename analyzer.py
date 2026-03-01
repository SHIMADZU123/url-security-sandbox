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
from urllib.parse import urlparse
import datetime

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
.score-circle { width:120px; height:120px; border-radius
