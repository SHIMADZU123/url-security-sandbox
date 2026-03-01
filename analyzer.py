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
.header { display:flex; align-items:center; gap:12px; }
.brand { font-weight:700; font-size:20px; color:#0b1220; }
.card { background: #ffffff; border-radius:12px; padding:18px; box-shadow: 0 6px 18px rgba(11,18,32,0.06); }
.badge-good { background:#e6f9f0; color:#0b8a5f; padding:8px 12px; border-radius:999px; font-weight:700; }
.badge-bad { background:#fff1f0; color:#b42318; padding:8px 12px; border-radius:999px; font-weight:700; }
.small { color:#6b7280; font-size:13px; }
.kv { display:flex; justify-content:space-between; padding:8px 0; border-bottom:1px dashed #eef2f7; }
.kv:last-child { border-bottom:none; }
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)

st.markdown("<div class='header'><div class='brand'>LinkTrust Checker
