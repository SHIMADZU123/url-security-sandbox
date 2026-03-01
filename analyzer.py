# app.py
import json
import socket
import ssl
import datetime
from urllib.parse import urlparse, urljoin

import requests
import validators
import tldextract
from bs4 import BeautifulSoup

import streamlit as st

# Optional whois
try:
    import whois as whois_lib
    WHOIS_AVAILABLE = True
except Exception:
    WHOIS_AVAILABLE = False

# -------------------------
# Styling for professional vibes
# -------------------------
st.set_page_config(page_title="URL SandBox Analyzer", page_icon="🧪", layout="wide")

CUSTOM_CSS = """
<style>
:root{
  --bg:#0f1724;
  --card:#0b1220;
  --accent:#0ea5a4;
  --muted:#94a3b8;
  --glass: rgba(255,255,255,0.03);
}
body {
  background: linear-gradient(180deg, #071029 0%, #071a2a 100%);
  color: #e6eef8;
  font-family: Inter, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial;
}
.stApp > header { display: none; }
.main .block-container { padding-top: 1rem; padding-left: 2rem; padding-right: 2rem; }
.card {
  background: var(--glass);
  border: 1px solid rgba(255,255,255,0.04);
  border-radius: 12px;
  padding: 18px;
  box-shadow: 0 6px 18px rgba(2,6,23,0.6);
}
.kv {
  display:flex;
  justify-content:space-between;
  gap: 12px;
  align-items:center;
  padding:8px 0;
  border-bottom: 1px dashed rgba(255,255,255,0.02);
}
.kv:last-child { border-bottom: none; }
.small { color: var(--muted); font-size: 13px; }
.badge {
  background: linear-gradient(90deg, rgba(14,165,164,0.12), rgba(14,165,164,0.06));
  color: var(--accent);
  padding: 6px 10px;
  border-radius: 999px;
  font-weight:600;
  font-size:13px;
}
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

# -------------------------
# Utility functions
# -------------------------
def normalize_url(raw_url: str) -> str:
    raw_url = raw_url.strip()
    if not raw_url:
        return ""
    if not raw_url.startswith(("http://", "https://")):
        raw_url = "http://" + raw_url
    return raw_url

def get_ssl_info(hostname: str, port: int = 443, timeout: int = 5):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        subject = dict(x[0] for x in cert.get("subject", ()))
        not_before = datetime.datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y %Z")
        not_after = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
        return {
            "subject_common_name": subject.get("commonName"),
            "issuer_common_name": issuer.get("commonName"),
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "serialNumber": cert.get("serialNumber"),
        }
    except Exception as e:
        return {"error": str(e)}

def analyze_url(url: str, timeout: int = 12):
    result = {
        "url": url,
        "normalized": None,
        "valid": False,
        "http": {},
        "meta": {},
        "links": {"internal": [], "external": []},
        "forms": [],
        "ssl": {},
        "whois": None,
        "error": None
    }
    try:
        normalized = normalize_url(url)
        result["normalized"] = normalized
        if not validators.url(normalized):
            result["error"] = "Invalid URL format"
            return result
        result["valid"] = True

        # HTTP request
        headers = {"User-Agent": "URL-Sandbox-Analyzer/1.0 (+https://github.com/yourname)"}
        resp = requests.get(normalized, headers=headers, timeout=timeout, allow_redirects=True, verify=True)
        result["http"] = {
            "status_code": resp.status_code,
            "final_url": resp.url,
            "elapsed_ms": int(resp.elapsed.total_seconds() * 1000),
            "headers": dict(resp.headers),
            "content_length": len(resp.content),
        }

        content_type = resp.headers.get("Content-Type", "")
        result["meta"]["content_type"] = content_type

        # Parse HTML if applicable
        if "html" in content_type.lower():
            soup = BeautifulSoup(resp.text, "html.parser")
            title_tag = soup.title.string.strip() if soup.title and soup.title.string else ""
            meta_desc = ""
            md = soup.find("meta", attrs={"name":"description"})
            if md and md.get("content"):
                meta_desc = md.get("content").strip()
            # Extract links
            parsed_root = urlparse(resp.url)
            root_domain = tldextract.extract(parsed_root.netloc).registered_domain
            for a in soup.find_all("a", href=True):
                href = a.get("href").strip()
                # normalize relative links
                href_full = urljoin(resp.url, href)
                parsed = urlparse(href_full)
                if not parsed.scheme.startswith("http"):
                    continue
                link_domain = tldextract.extract(parsed.netloc).registered_domain
                if link_domain == root_domain:
                    result["links"]["internal"].append(href_full)
                else:
                    result["links"]["external"].append(href_full)
            # Forms
            for form in soup.find_all("form"):
                f = {
                    "action": urljoin(resp.url, form.get("action") or ""),
                    "method": (form.get("method") or "GET").upper(),
                    "inputs": []
                }
                for inp in form.find_all(["input","textarea","select"]):
                    name = inp.get("name") or inp.get("id") or ""
                    itype = inp.get("type") or inp.name
                    f["inputs"].append({"name": name, "type": itype})
                result["forms"].append(f)

            result["meta"]["title"] = title_tag
            result["meta"]["description"] = meta_desc

        # SSL info
        parsed = urlparse(normalized)
        hostname = parsed.hostname
        if hostname:
            result["ssl"] = get_ssl_info(hostname)

        # WHOIS (optional)
        if WHOIS_AVAILABLE and hostname:
            try:
                w = whois_lib.whois(hostname)
                # keep only a few fields
                result["whois"] = {
                    "domain_name": w.domain_name,
                    "registrar": w.registrar,
                    "creation_date": str(w.creation_date),
                    "expiration_date": str(w.expiration_date),
                    "name_servers": w.name_servers
                }
            except Exception as e:
                result["whois"] = {"error": str(e)}

    except requests.exceptions.RequestException as re:
        result["error"] = f"Request error: {str(re)}"
    except Exception as e:
        result["error"] = f"Unexpected error: {str(e)}"
    return result

# -------------------------
# UI Layout
# -------------------------
st.markdown("<div style='display:flex;align-items:center;gap:16px;margin-bottom:12px'>"
            "<div style='font-size:28px;font-weight:700'>URL SandBox Analyzer</div>"
            "<div class='badge'>Professional</div>"
            "</div>", unsafe_allow_html=True)

with st.sidebar:
    st.markdown("## Controls")
    url_input = st.text_input("Enter URL to analyze", placeholder="https://example.com")
    timeout = st.slider("Request timeout (seconds)", min_value=5, max_value=30, value=12)
    enable_whois = st.checkbox("Enable WHOIS lookup (optional)", value=False)
    if enable_whois and not WHOIS_AVAILABLE:
        st.info("WHOIS library not installed. Install `python-whois` to enable this feature.")
    st.markdown("---")
    st.markdown("**Output options**")
    pretty_json = st.checkbox("Show pretty JSON report", value=True)
    st.markdown("---")
    st.markdown("Built by a professional template — clean, secure, and audit-friendly.")

col1, col2 = st.columns([2, 1])

with col1:
    st.markdown("<div class='card'>", unsafe_allow_html=True)
    st.subheader("Analyze")
    if st.button("Run Analysis", key="run"):
        if not url_input:
            st.warning("Please enter a URL to analyze.")
        else:
            with st.spinner("Analyzing URL..."):
                analysis = analyze_url(url_input, timeout=timeout)
            st.success("Analysis complete")
            st.session_state["last_analysis"] = analysis
    else:
        analysis = st.session_state.get("last_analysis", None)
    st.markdown("</div>", unsafe_allow_html=True)

with col2:
    st.markdown("<div class='card'>", unsafe_allow_html=True)
    st.subheader("Quick Info")
    if "last_analysis" in st.session_state:
        la = st.session_state["last_analysis"]
        st.markdown(f"<div class='kv'><div><strong>URL</strong><div class='small'>{la.get('normalized') or la.get('url')}</div></div>"
                    f"<div><span class='badge'>{'Valid' if la.get('valid') else 'Invalid'}</span></div></div>", unsafe_allow_html=True)
        http = la.get("http", {})
        st.markdown(f"<div class='kv'><div><strong>Status</strong><div class='small'>{http.get('status_code')}</div></div>"
                    f"<div><strong>Time</strong><div class='small'>{http.get('elapsed_ms')} ms</div></div></div>", unsafe_allow_html=True)
        st.markdown(f"<div class='kv'><div><strong>Content Type</strong><div class='small'>{la.get('meta',{}).get('content_type')}</div></div>"
                    f"<div><strong>Links</strong><div class='small'>Internal: {len(la.get('links',{}).get('internal',[]))} • External: {len(la.get('links',{}).get('external',[]))}</div></div></div>", unsafe_allow_html=True)
    else:
        st.markdown("No analysis run yet. Enter a URL and click Run Analysis.")
    st.markdown("</div>", unsafe_allow_html=True)

st.markdown("---")

# -------------------------
# Detailed results
# -------------------------
if "last_analysis" in st.session_state:
    la = st.session_state["last_analysis"]

    st.header("Detailed Report")
    # Left column: HTTP + meta
    a, b = st.columns([2, 1])
    with a:
        st.subheader("HTTP Summary")
        http = la.get("http", {})
        if la.get("error"):
            st.error(f"Analysis error: {la.get('error')}")
        st.write({
            "Final URL": http.get("final_url"),
            "Status code": http.get("status_code"),
            "Response time (ms)": http.get("elapsed_ms"),
            "Content length (bytes)": http.get("content_length"),
        })
        st.markdown("**Headers**")
        headers = http.get("headers") or {}
        st.table({k: headers[k] for k in list(headers)[:12]})  # show first 12 headers

        st.markdown("**Page Metadata**")
        st.write({
            "Title": la.get("meta", {}).get("title"),
            "Description": la.get("meta", {}).get("description"),
            "Content Type": la.get("meta", {}).get("content_type"),
        })

        st.markdown("**Forms Detected**")
        if la.get("forms"):
            for idx, f in enumerate(la.get("forms")):
                st.markdown(f"**Form {idx+1}** — Method: `{f.get('method')}` • Action: `{f.get('action')}`")
                st.table(f.get("inputs") or [])
        else:
            st.info("No forms detected or page not HTML.")

    with b:
        st.subheader("Security & Domain")
        st.markdown("**SSL Certificate**")
        ssl_info = la.get("ssl") or {}
        if ssl_info.get("error"):
            st.warning(f"SSL lookup failed: {ssl_info.get('error')}")
        else:
            st.write({
                "Subject CN": ssl_info.get("subject_common_name"),
                "Issuer": ssl_info.get("issuer_common_name"),
                "Valid from": ssl_info.get("not_before"),
                "Valid until": ssl_info.get("not_after"),
            })

        st.markdown("**WHOIS**")
        if la.get("whois"):
            st.json(la.get("whois"))
        else:
            if enable_whois and WHOIS_AVAILABLE:
                st.info("WHOIS lookup returned no data.")
            else:
                st.info("WHOIS not enabled or not available.")

    st.markdown("---")
    st.subheader("Links")
    internal = la.get("links", {}).get("internal", [])[:200]
    external = la.get("links", {}).get("external", [])[:200]
    st.markdown(f"**Internal links** ({len(la.get('links',{}).get('internal',[]))})")
    if internal:
        for u in internal[:50]:
            st.write(f"- {u}")
    else:
        st.write("No internal links found or not HTML content.")

    st.markdown(f"**External links** ({len(la.get('links',{}).get('external',[]))})")
    if external:
        for u in external[:50]:
            st.write(f"- {u}")
    else:
        st.write("No external links found or not HTML content.")

    st.markdown("---")
    st.subheader("Export")
    report_json = json.dumps(la, indent=2)
    if pretty_json:
        st.code(report_json, language="json")
    st.download_button("Download JSON report", data=report_json, file_name="url_sandbox_report.json", mime="application/json")

else:
    st.info("Run an analysis to see results here.")

# -------------------------
# Footer
# -------------------------
st.mark
