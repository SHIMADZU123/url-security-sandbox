def deep_path_inspection(url):
    """
    Uniquely analyzes the path and subdomains for platform-abuse.
    """
    # 1. Keywords that should NEVER be in a trusted infrastructure path
    danger_keywords = ["phishing", "login", "verify", "secure", "account-update", "signin"]
    path_segments = url.lower().split('/')
    
    # 2. Platform domains often abused by hackers
    platform_domains = ["appspot.com", "github.io", "firebaseapp.com", "vercel.app", "pages.dev"]
    
    ext = extract(url)
    root = f"{ext.domain}.{ext.suffix}"
    
    warnings = []
    
    # Check if a trusted platform is hosting a 'danger' keyword
    if root in platform_domains:
        for word in danger_keywords:
            if word in url.lower():
                warnings.append(f"INFRASTRUCTURE_ABUSE: {word.upper()} detected on cloud platform.")
                
    # 3. Entropy Check: Random strings in subdomains (common in generated phishing)
    if len(ext.subdomain) > 20:
        warnings.append("HIGH_ENTROPY: Suspiciously long subdomain detected.")
        
    return warnings

# --- INTEGRATION ---
# Inside your 'EXECUTE_DECONSTRUCTION' block:
path_warnings = deep_path_inspection(target)

if path_warnings:
    phantom_score = 100 # FORCE CRITICAL
    for w in path_warnings:
        st.warning(f"⚠️ {w}")
