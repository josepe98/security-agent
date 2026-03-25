#!/usr/bin/env python3
"""
Web Security Testing Agent
Performs passive security checks on websites and generates an interactive HTML report.
Usage: python security_agent.py <url1> [url2] [url3] ...
"""

__version__ = "1.4.0"

import sys
import ssl
import socket
import json
import datetime
import time
import re
import uuid
import random
import urllib.parse
import argparse
from pathlib import Path

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("Please install requests: pip install requests")
    sys.exit(1)

try:
    import dns.resolver
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

try:
    from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

# ─────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────

TIMEOUT = 10
BLIND_SQLI_DELAY = 4   # seconds a sleep() payload should pause the server

# Rotate through realistic browser User-Agents to avoid fingerprinting
ROTATING_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
]
USER_AGENT = random.choice(ROTATING_USER_AGENTS)

# Common subdomains worth probing
COMMON_SUBDOMAINS = [
    "www", "api", "dev", "staging", "stage", "test", "admin", "portal",
    "app", "mail", "remote", "vpn", "beta", "preview", "dashboard",
    "static", "assets", "cdn", "media", "uploads", "docs", "support",
]

# Patterns to search for in JavaScript files — secrets, keys, endpoints
JS_SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
    (r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"][a-zA-Z0-9_\-]{16,}['\"]", "API Key"),
    (r"(?i)(secret[_-]?key|secret)\s*[=:]\s*['\"][a-zA-Z0-9_\-]{16,}['\"]", "Secret Key"),
    (r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{6,}['\"]", "Hardcoded Password"),
    (r"eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}", "JWT Token"),
    (r"(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}", "Bearer Token"),
    (r"xox[baprs]-[0-9A-Za-z\-]{10,}", "Slack Token"),
    (r"(?i)(private.?key|rsa.?key)\s*[=:]\s*['\"][^'\"]{20,}['\"]", "Private Key Reference"),
    (r"(?i)(db|database)[_-]?(password|pass|pwd)\s*[=:]\s*['\"][^'\"]{4,}['\"]", "Database Password"),
    (r"(?i)access.?token\s*[=:]\s*['\"][a-zA-Z0-9_\-\.]{16,}['\"]", "Access Token"),
    (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key"),
    (r"(?i)mongodb(\+srv)?://[^\s'\"]+", "MongoDB Connection String"),
    (r"(?i)postgres(ql)?://[^\s'\"]+", "PostgreSQL Connection String"),
    (r"(?i)mysql://[^\s'\"]+", "MySQL Connection String"),
]

# Patterns for detecting PII in unauthenticated API responses (SECURITY.md §3a)
PII_PATTERNS = [
    (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', "Email Address"),
    (r'\b\d{3}-\d{2}-\d{4}\b', "Potential SSN"),
    (r'(?<!\d)\+?1?\s*\(?\d{3}\)?[\s.\-]\d{3}[\s.\-]\d{4}(?!\d)', "Phone Number"),
    (r'\b4[0-9]{12}(?:[0-9]{3})?\b|\b5[1-5][0-9]{14}\b|\b3[47][0-9]{13}\b', "Credit Card Number"),
]

# ── Technology fingerprints split into three actionable categories ──
#
# MANAGED_PLATFORMS  — hosted services with their own security teams.
#   The URLs/headers that reveal these are public by design and cannot
#   be hidden without leaving the platform. No remediation needed.
#
# SELF_HOSTED_FRAMEWORKS — software you run yourself.
#   Version disclosure is genuinely risky here because CVEs are
#   version-specific. Keep updated and strip version strings.
#
# FRONTEND_FRAMEWORKS — client-side JS frameworks.
#   Visible in the browser bundle by design; not a meaningful signal
#   for attackers. No remediation needed.

MANAGED_PLATFORMS = [
    (r"supabase\.co",                         "Supabase"),
    (r"firebaseapp\.com|firebase\.google\.com","Firebase"),
    (r"auth0\.com|\.auth0\.com",              "Auth0"),
    (r"clerk\.dev|clerk\.accounts",           "Clerk"),
    (r"cognito.*amazonaws",                   "AWS Cognito"),
    (r"x-vercel|vercel\.app|\.vercel\.app",   "Vercel"),
    (r"\.netlify\.app|x-nf-request-id",       "Netlify"),
    (r"cloudflare|cf-ray",                    "Cloudflare"),
    (r"heroku|herokussl|x-heroku",            "Heroku"),
    (r"awselb|x-amzn-|amazonaws\.com",        "AWS"),
    (r"shopify\.com|Shopify\.theme",          "Shopify"),
    (r"squarespace\.com|static\.squarespace", "Squarespace"),
    (r"wixsite\.com|wix\.com/",               "Wix"),
    (r"ghost\.io|content\.ghost\.org",        "Ghost (Managed)"),
]

SELF_HOSTED_FRAMEWORKS = [
    (r"/wp-content/|wp-json|xmlrpc\.php",         "WordPress"),
    (r"Drupal\.settings|drupal\.js|/sites/default/files", "Drupal"),
    (r"Joomla!|/components/com_|/modules/mod_",   "Joomla"),
    (r"laravel_session|XSRF-TOKEN.*laravel",       "Laravel"),
    (r"csrfmiddlewaretoken",                       "Django"),
    (r"__rails|rails-ujs",                        "Ruby on Rails"),
    (r"X-Powered-By: Express|connect\.sid",       "Express.js"),
    (r"X-Powered-By: PHP|phpsessid",              "PHP"),
    (r"asp\.net_sessionid|x-aspnet-version",      "ASP.NET"),
    (r"jsessionid|x-java-servlet",                "Java/Tomcat"),
]

FRONTEND_FRAMEWORKS = [
    (r"__NEXT_DATA__|/_next/static",   "Next.js"),
    (r"__nuxt__|/_nuxt/",              "Nuxt.js"),
    (r"ng-version=|angular\.min\.js",  "Angular"),
    (r"react\.development\.js|react-dom", "React"),
    (r"vue\.runtime|__vue__",          "Vue.js"),
]

# Flat list for any code that still needs a single iterable
TECH_FINGERPRINTS = MANAGED_PLATFORMS + SELF_HOSTED_FRAMEWORKS + FRONTEND_FRAMEWORKS

# Patterns that reveal specific version numbers — the real risk
VERSION_DISCLOSURE_PATTERNS = [
    # HTTP headers
    (r"nginx/(\d+\.\d+[\.\d]*)",             "nginx",      "header"),
    (r"Apache/(\d+\.\d+[\.\d]*)",            "Apache",     "header"),
    (r"Microsoft-IIS/(\d+\.\d+)",            "IIS",        "header"),
    (r"PHP/(\d+\.\d+[\.\d]*)",               "PHP",        "header"),
    (r"Express/(\d+\.\d+[\.\d]*)",           "Express.js", "header"),
    (r"OpenSSL/(\d+\.\d+[\.\d]*)",           "OpenSSL",    "header"),
    (r"X-AspNet-Version:\s*(\d+\.\d+[\.\d]*)","ASP.NET",   "header"),
    # HTML meta generator tags
    (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', "Generator meta tag", "html"),
    (r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']generator["\']', "Generator meta tag", "html"),
    # Inline version strings in HTML/JS
    (r"WordPress\s+([\d\.]+)",               "WordPress",  "html"),
    (r"Drupal\s+([\d\.]+)",                  "Drupal",     "html"),
    (r"ng-version=[\"']([\d\.]+)[\"']",      "Angular",    "html"),
    (r"jQuery\s+v?([\d\.]+)",                "jQuery",     "html"),
    (r"Bootstrap\s+v?([\d\.]+)",             "Bootstrap",  "html"),
]

SENSITIVE_PATHS = [
    "/.env", "/.git/HEAD", "/.git/config", "/config.php", "/wp-config.php",
    "/backup.sql", "/database.sql", "/dump.sql", "/.DS_Store",
    "/phpinfo.php", "/info.php", "/test.php", "/.htaccess", "/web.config",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/.well-known/security.txt",
    # Backup / recovery artefacts (SECURITY.md §2)
    "/backup.zip", "/site.zip", "/archive.zip", "/_backup.zip",
    "/backup.tar.gz", "/backup.tar", "/db_backup.sql",
    "/database_backup.sql", "/.backup", "/restore.php", "/install.php",
]

# Content signatures that confirm a sensitive file is genuine (not an SPA catch-all)
SENSITIVE_FILE_SIGNATURES = {
    "/.env":        [r"^[A-Z_]+=", r"(?i)(DB_|DATABASE_|SECRET|API_KEY|PASSWORD)"],
    "/.git/HEAD":   [r"^ref:\s+refs/"],
    "/.git/config": [r"\[core\]", r"\[remote\s"],
    "/config.php":  [r"<\?php", r"(?i)(password|database|db_host)"],
    "/wp-config.php": [r"DB_NAME", r"DB_PASSWORD", r"table_prefix"],
    "/backup.sql":  [r"(?i)(CREATE\s+TABLE|INSERT\s+INTO|DROP\s+TABLE)"],
    "/database.sql": [r"(?i)(CREATE\s+TABLE|INSERT\s+INTO|DROP\s+TABLE)"],
    "/dump.sql":    [r"(?i)(CREATE\s+TABLE|INSERT\s+INTO|DROP\s+TABLE)"],
    "/.DS_Store":   [r"\x00\x00\x00\x01Bud1"],  # binary magic bytes
    "/phpinfo.php": [r"phpinfo\(\)", r"PHP Version"],
    "/info.php":    [r"phpinfo\(\)", r"PHP Version"],
    "/test.php":    [r"<\?php"],
    "/.htaccess":   [r"(?i)(RewriteEngine|Deny\s+from|AuthType|Options)"],
    "/web.config":  [r"<configuration", r"<system\.web"],
    "/robots.txt":  [r"(?i)(User-agent|Disallow|Allow|Sitemap):"],
    "/sitemap.xml": [r"<urlset|<sitemapindex"],
    "/crossdomain.xml": [r"<cross-domain-policy"],
    "/clientaccesspolicy.xml": [r"<access-policy"],
    "/.well-known/security.txt": [r"(?i)(Contact:|Expires:|Encryption:|Policy:)"],
    # Backup / recovery artefacts
    "/db_backup.sql":       [r"(?i)(CREATE\s+TABLE|INSERT\s+INTO|DROP\s+TABLE)"],
    "/database_backup.sql": [r"(?i)(CREATE\s+TABLE|INSERT\s+INTO|DROP\s+TABLE)"],
    "/restore.php":         [r"<\?php"],
    "/install.php":         [r"<\?php"],
    # Binary archives — no text signatures; any non-SPA 200 is suspicious
}

ADMIN_PATHS = [
    "/admin", "/admin/", "/wp-admin/", "/administrator/", "/login",
    "/login.php", "/user/login", "/auth/login", "/signin", "/dashboard",
    "/cpanel", "/phpmyadmin", "/adminer.php", "/manager/html",
]

API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/swagger", "/swagger-ui.html",
    "/openapi.json", "/api-docs", "/graphql", "/v1", "/v2",
    "/.well-known/openid-configuration",
]

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Enforces HTTPS connections (HSTS)",
        "severity": "HIGH",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
    },
    "Content-Security-Policy": {
        "description": "Prevents XSS and data injection attacks",
        "severity": "HIGH",
        "recommendation": "Define a Content-Security-Policy header to restrict resource loading."
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking attacks",
        "severity": "MEDIUM",
        "recommendation": "Add: X-Frame-Options: DENY or SAMEORIGIN"
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME-type sniffing",
        "severity": "MEDIUM",
        "recommendation": "Add: X-Content-Type-Options: nosniff"
    },
    "Referrer-Policy": {
        "description": "Controls referrer information in requests",
        "severity": "LOW",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "description": "Controls browser feature access",
        "severity": "LOW",
        "recommendation": "Add: Permissions-Policy to restrict camera, microphone, geolocation, etc."
    },
    "X-XSS-Protection": {
        "description": "Legacy XSS protection header (deprecated but still useful)",
        "severity": "LOW",
        "recommendation": "Add: X-XSS-Protection: 1; mode=block (or rely on CSP instead)"
    },
    "Cache-Control": {
        "description": "Controls caching of sensitive pages",
        "severity": "LOW",
        "recommendation": "Consider: Cache-Control: no-store for sensitive pages"
    },
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "PASS": 5}


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def get_session():
    s = requests.Session()
    s.headers.update({
        "User-Agent": random.choice(ROTATING_USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-GB,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
    })
    return s


def stealth_delay(stealth=False):
    """Pause briefly between requests to avoid rate-limit and WAF triggers."""
    if stealth:
        time.sleep(random.uniform(1.5, 4.0))
    else:
        time.sleep(random.uniform(0.2, 0.7))


def safe_get(session, url, stealth=False, **kwargs):
    try:
        r = session.get(url, timeout=TIMEOUT, verify=False,
                        allow_redirects=True, **kwargs)
        stealth_delay(stealth)
        return r
    except Exception:
        return None


def finding(severity, title, detail, recommendation=None, evidence=None):
    return {
        "severity": severity,
        "title": title,
        "detail": detail,
        "recommendation": recommendation or "",
        "evidence": evidence or "",
    }


# ─────────────────────────────────────────────
# CHECK MODULES
# ─────────────────────────────────────────────

def check_ssl_tls(hostname, port=443):
    results = []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                tls_version = ssock.version()
                cipher = ssock.cipher()

                # TLS version check
                if tls_version in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
                    results.append(finding(
                        "HIGH", "Outdated TLS Version",
                        f"Server uses {tls_version} which is deprecated and insecure.",
                        "Upgrade to TLS 1.2 or TLS 1.3.",
                        tls_version
                    ))
                else:
                    results.append(finding(
                        "PASS", "TLS Version",
                        f"Server uses {tls_version}.",
                        evidence=tls_version
                    ))

                # Certificate expiry
                not_after = cert.get("notAfter")
                if not_after:
                    exp_date = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_left = (exp_date - datetime.datetime.utcnow()).days
                    if days_left < 0:
                        results.append(finding("CRITICAL", "SSL Certificate Expired",
                            f"Certificate expired {abs(days_left)} days ago.",
                            "Renew the SSL certificate immediately.", not_after))
                    elif days_left < 30:
                        results.append(finding("HIGH", "SSL Certificate Expiring Soon",
                            f"Certificate expires in {days_left} days.",
                            "Renew the SSL certificate before it expires.", not_after))
                    else:
                        results.append(finding("PASS", "SSL Certificate Valid",
                            f"Certificate valid for {days_left} more days.", evidence=not_after))

                # Subject alternative names
                san = cert.get("subjectAltName", [])
                san_values = [v for _, v in san]
                results.append(finding("INFO", "Certificate Subject Alt Names",
                    f"SANs: {', '.join(san_values[:5])}" if san_values else "No SANs found.",
                    evidence=", ".join(san_values[:5])))

                # Cipher suite
                results.append(finding("INFO", "Active Cipher Suite",
                    f"Cipher: {cipher[0]}, Protocol: {cipher[1]}, Bits: {cipher[2]}",
                    evidence=str(cipher)))

    except ssl.SSLCertVerificationError as e:
        results.append(finding("HIGH", "SSL Certificate Verification Failed",
            str(e), "Fix the SSL certificate chain / trust."))
    except ssl.SSLError as e:
        results.append(finding("HIGH", "SSL/TLS Error", str(e)))
    except ConnectionRefusedError:
        results.append(finding("INFO", "HTTPS Not Available on Port 443",
            "Port 443 is closed or not responding.",
            "Ensure HTTPS is enabled and port 443 is open."))
    except Exception as e:
        results.append(finding("INFO", "SSL Check Error", str(e)))

    return results


def check_security_headers(response):
    results = []
    headers = {k.lower(): v for k, v in response.headers.items()}

    for header_name, meta in SECURITY_HEADERS.items():
        if header_name.lower() in headers:
            val = headers[header_name.lower()]
            # Extra validation for HSTS
            if header_name == "Strict-Transport-Security":
                if "max-age" not in val.lower():
                    results.append(finding("MEDIUM", f"Weak {header_name}",
                        "HSTS header present but missing max-age directive.",
                        meta["recommendation"], val))
                elif int(re.search(r"max-age=(\d+)", val, re.I).group(1)) < 31536000:
                    results.append(finding("LOW", f"Short HSTS max-age",
                        "HSTS max-age is less than 1 year.",
                        meta["recommendation"], val))
                else:
                    results.append(finding("PASS", f"{header_name} Present",
                        meta["description"], evidence=val))
            else:
                results.append(finding("PASS", f"{header_name} Present",
                    meta["description"], evidence=val))
        else:
            results.append(finding(meta["severity"], f"Missing {header_name}",
                meta["description"], meta["recommendation"]))

    # Note: version number and technology disclosure checks have moved to
    # check_version_disclosure() and check_fingerprint() for more nuanced analysis.

    return results


def check_https_redirect(session, url):
    results = []
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme == "https":
        http_url = url.replace("https://", "http://", 1)
    else:
        http_url = url

    try:
        r = requests.get(http_url, timeout=TIMEOUT, allow_redirects=False,
                         headers={"User-Agent": USER_AGENT}, verify=False)
        if r.status_code in (301, 302, 307, 308):
            location = r.headers.get("Location", "")
            if location.startswith("https://"):
                results.append(finding("PASS", "HTTP → HTTPS Redirect",
                    f"Redirects to HTTPS ({r.status_code}).", evidence=location))
            else:
                results.append(finding("MEDIUM", "HTTP Does Not Redirect to HTTPS",
                    f"HTTP redirect points to: {location}",
                    "Ensure all HTTP traffic is redirected to HTTPS.", location))
        elif r.status_code == 200:
            results.append(finding("HIGH", "HTTP Not Redirected to HTTPS",
                "Site is accessible over plain HTTP without redirection.",
                "Configure a 301 redirect from HTTP to HTTPS."))
        else:
            results.append(finding("INFO", f"HTTP Status {r.status_code}",
                f"HTTP request returned status {r.status_code}."))
    except Exception as e:
        results.append(finding("INFO", "HTTP Redirect Check Failed", str(e)))

    return results


def detect_spa_baseline(session, base_url):
    """Fetch a random nonsense path to detect SPA catch-all routing.
    Returns (body_text, content_length) if the site returns 200 for unknown paths,
    or (None, None) if the site properly returns 404."""
    random_slug = uuid.uuid4().hex[:16]
    canary_url = base_url.rstrip("/") + f"/__spa_detect_{random_slug}"
    r = safe_get(session, canary_url)
    if r is not None and r.status_code == 200 and len(r.content) > 0:
        return r.text, len(r.content)
    return None, None


def _matches_spa_baseline(response_text, response_size, spa_baseline_text, spa_baseline_size):
    """Check if a response looks like the SPA catch-all page."""
    if spa_baseline_text is None:
        return False
    # Same size is a strong signal; also check content similarity
    if response_size == spa_baseline_size:
        return True
    # Allow small size variance (e.g. injected nonce differences) and check text overlap
    if abs(response_size - spa_baseline_size) < 50:
        # Compare first 200 chars — SPA shells are nearly identical
        if response_text[:200] == spa_baseline_text[:200]:
            return True
    return False


def _content_confirms_sensitive_file(path, response_text):
    """Check if the response body actually looks like the sensitive file type."""
    signatures = SENSITIVE_FILE_SIGNATURES.get(path, [])
    if not signatures:
        return True  # No signatures defined — can't disprove, keep the finding
    sample = response_text[:4000]
    return any(re.search(sig, sample) for sig in signatures)


def check_sensitive_files(session, base_url, spa_baseline=None):
    results = []
    exposed = []
    spa_text, spa_size = spa_baseline or (None, None)
    spa_suppressed = 0

    for path in SENSITIVE_PATHS:
        url = base_url.rstrip("/") + path
        r = safe_get(session, url)
        if r is None:
            continue
        if r.status_code == 200 and len(r.content) > 0:
            # Make sure it's not a soft 404
            content = r.text[:200].lower()
            if "not found" not in content and "404" not in content:
                # SPA catch-all detection: skip if response matches the baseline
                if _matches_spa_baseline(r.text, len(r.content), spa_text, spa_size):
                    if not _content_confirms_sensitive_file(path, r.text):
                        spa_suppressed += 1
                        continue
                exposed.append((path, r.status_code, len(r.content)))

    if exposed:
        for path, status, size in exposed:
            sev = "CRITICAL" if path in ("/.env", "/.git/HEAD", "/.git/config",
                                          "/wp-config.php", "/config.php") else "MEDIUM"
            results.append(finding(sev, f"Sensitive File Exposed: {path}",
                f"File accessible at {path} (HTTP {status}, {size} bytes).",
                f"Restrict access to {path} via server configuration.",
                f"URL: {base_url.rstrip('/')}{path}"))
    else:
        results.append(finding("PASS", "Sensitive Files Not Exposed",
            "No common sensitive files found publicly accessible."))

    if spa_suppressed:
        results.append(finding("INFO", f"SPA Catch-All Detected ({spa_suppressed} paths suppressed)",
            f"This site returns its index page for unknown paths. "
            f"{spa_suppressed} sensitive-file probe(s) were suppressed as false positives.",
            "Consider returning 404 for unknown paths instead of serving the SPA shell."))

    return results


def check_admin_panels(session, base_url, spa_baseline=None):
    results = []
    found = []
    spa_text, spa_size = spa_baseline or (None, None)
    spa_suppressed = 0

    for path in ADMIN_PATHS:
        url = base_url.rstrip("/") + path
        r = safe_get(session, url)
        if r is None:
            continue
        if r.status_code in (200, 401, 403):
            # For 200 responses, check if it's just the SPA catch-all
            if r.status_code == 200 and _matches_spa_baseline(r.text, len(r.content), spa_text, spa_size):
                spa_suppressed += 1
                continue
            found.append((path, r.status_code))

    if found:
        for path, status in found:
            if status == 200:
                results.append(finding("MEDIUM", f"Admin/Login Panel Accessible: {path}",
                    f"Admin or login page found at {path} (HTTP {status}).",
                    "Ensure admin interfaces are properly secured, behind VPN, or IP-restricted.",
                    f"{base_url.rstrip('/')}{path}"))
            else:
                results.append(finding("INFO", f"Admin Path Returns {status}: {path}",
                    f"Path {path} returns HTTP {status} (possibly restricted but exists).",
                    evidence=f"{base_url.rstrip('/')}{path}"))
    else:
        results.append(finding("PASS", "No Common Admin Panels Found",
            "No common admin paths returned accessible responses."))

    if spa_suppressed:
        results.append(finding("INFO", f"SPA Catch-All: {spa_suppressed} admin path(s) suppressed",
            f"{spa_suppressed} admin path probe(s) returned the SPA shell page and were suppressed.",
            "Consider returning 404 for unknown paths instead of serving the SPA shell."))

    return results


def check_api_endpoints(session, base_url, spa_baseline=None):
    results = []
    found = []
    spa_text, spa_size = spa_baseline or (None, None)
    spa_suppressed = 0

    for path in API_PATHS:
        url = base_url.rstrip("/") + path
        r = safe_get(session, url)
        if r is None:
            continue
        if r.status_code in (200, 401, 403):
            # For 200 responses, check if it's just the SPA catch-all
            if r.status_code == 200 and _matches_spa_baseline(r.text, len(r.content), spa_text, spa_size):
                spa_suppressed += 1
                continue
            content_type = r.headers.get("Content-Type", "")
            found.append((path, r.status_code, content_type, r.text[:20000]))

    cors_checked = False
    for path, status, ct, body in found:
        if status == 200:
            results.append(finding("INFO", f"API Endpoint Found: {path}",
                f"API endpoint at {path} returns HTTP 200.",
                "Ensure API endpoints require authentication where appropriate.",
                f"{base_url.rstrip('/')}{path}"))

            # Check CORS on first accessible API endpoint
            if not cors_checked:
                cors_checked = True
                url = base_url.rstrip("/") + path
                try:
                    r2 = session.options(url, timeout=TIMEOUT, verify=False,
                                         headers={"Origin": "https://evil.com",
                                                  "User-Agent": USER_AGENT})
                    acao = r2.headers.get("Access-Control-Allow-Origin", "")
                    acac = r2.headers.get("Access-Control-Allow-Credentials", "")
                    if acao == "*":
                        results.append(finding("MEDIUM", "Overly Permissive CORS Policy",
                            "API allows requests from any origin (*).",
                            "Restrict CORS to trusted origins only.", f"ACAO: {acao}"))
                    elif acao == "https://evil.com":
                        results.append(finding("HIGH", "CORS Reflects Arbitrary Origins",
                            "API reflects arbitrary Origin headers, enabling cross-origin attacks.",
                            "Validate and whitelist specific trusted origins.", f"ACAO: {acao}"))
                    elif acao:
                        results.append(finding("PASS", "CORS Configured",
                            f"CORS allows: {acao}", evidence=acao))

                    if acac.lower() == "true" and acao in ("*", "https://evil.com"):
                        results.append(finding("HIGH", "CORS Allows Credentials from Any Origin",
                            "Credentials are allowed from wildcard or reflected origins.",
                            "Never combine Access-Control-Allow-Credentials: true with a wildcard origin."))
                except Exception:
                    pass

            # PII / bulk-data exposure check (SECURITY.md §3a — data minimisation)
            pii_hits = []
            for pattern, label in PII_PATTERNS:
                matches = re.findall(pattern, body)
                if matches:
                    pii_hits.append((label, matches[0] if isinstance(matches[0], str) else matches[0][0], len(matches)))
            # Bulk user-record check for JSON arrays
            if "json" in ct.lower():
                try:
                    data = json.loads(body)
                    if isinstance(data, list) and len(data) > 5 and data and isinstance(data[0], dict):
                        identity_keys = {"email", "username", "name", "phone", "address", "user_id", "userid"}
                        found_keys = identity_keys & {k.lower() for k in data[0].keys()}
                        if found_keys:
                            pii_hits.append((
                                f"Bulk User Record List ({len(data)} items, fields: {', '.join(sorted(found_keys))})",
                                str(data[0])[:120], len(data)
                            ))
                except Exception:
                    pass
            for label, sample, count in pii_hits:
                results.append(finding("HIGH", f"PII Exposed in Unauthenticated API Response: {label}",
                    f"Endpoint {path} returned {count} instance(s) of {label} without requiring authentication.",
                    "Require authentication on all API endpoints that return user data. "
                    "Return only the minimum data necessary; avoid bulk list endpoints that expose all records.",
                    sample[:120]))

    if not found:
        results.append(finding("PASS", "No Common API Endpoints Exposed",
            "No common API paths returned accessible responses."))

    # Check for rate limiting headers on auth/API endpoints (not homepage)
    rate_check_paths = ["/api/auth/login", "/auth/login", "/api/login", "/login", "/api/token"]
    rate_checked_url = None
    rate_headers = []
    for path in rate_check_paths:
        candidate = base_url.rstrip("/") + path
        r = safe_get(session, candidate)
        if r and r.status_code != 404:
            rate_headers = [h for h in r.headers if "rate" in h.lower() or "retry" in h.lower() or "x-ratelimit" in h.lower()]
            rate_checked_url = candidate
            break
    if not rate_checked_url:
        # Fall back to homepage if no auth endpoint found
        r = safe_get(session, base_url)
        if r:
            rate_headers = [h for h in r.headers if "rate" in h.lower() or "retry" in h.lower() or "x-ratelimit" in h.lower()]
            rate_checked_url = base_url
    if rate_checked_url:
        if not rate_headers:
            results.append(finding("LOW", "No Rate Limiting Headers Detected",
                f"No rate limiting headers found on {rate_checked_url}.",
                "Implement rate limiting on login endpoints and APIs (e.g., X-RateLimit-* headers)."))
        else:
            results.append(finding("PASS", "Rate Limiting Headers Present",
                f"Headers on {rate_checked_url}: {', '.join(rate_headers)}"))

    if spa_suppressed:
        results.append(finding("INFO", f"SPA Catch-All: {spa_suppressed} API path(s) suppressed",
            f"{spa_suppressed} API path probe(s) returned the SPA shell page and were suppressed.",
            "Consider returning 404 for unknown paths instead of serving the SPA shell."))

    return results


def check_authentication(session, base_url):
    results = []

    # Find login forms
    login_urls = []
    for path in ["/login", "/signin", "/user/login", "/auth/login", ""]:
        url = base_url.rstrip("/") + path
        r = safe_get(session, url)
        if r and r.status_code == 200:
            if any(kw in r.text.lower() for kw in ["password", "passwd", "login", "sign in", "email"]):
                login_urls.append((url, r.text))
                break  # check first found login page

    for url, html in login_urls:
        # Check if form submits over HTTPS
        forms = re.findall(r'<form[^>]+action=["\']([^"\']*)["\']', html, re.I)
        for action in forms:
            if action.startswith("http://"):
                results.append(finding("HIGH", "Login Form Submits Over HTTP",
                    f"Form action points to plain HTTP: {action}",
                    "Ensure all form submissions use HTTPS.", action))

        # Check for autocomplete on password fields
        if re.search(r'<input[^>]+type=["\']password["\'][^>]+autocomplete=["\']on["\']', html, re.I):
            results.append(finding("LOW", "Password Field Has Autocomplete Enabled",
                "Password inputs with autocomplete='on' can expose credentials.",
                "Add autocomplete='off' or autocomplete='new-password' to password fields."))
        else:
            results.append(finding("PASS", "Password Autocomplete Appears Controlled",
                "No obvious autocomplete='on' found on password fields."))

        # Check for CSRF token — skip if site uses stateless JWT Bearer auth (no session cookies)
        try:
            probe = session.head(url, timeout=TIMEOUT, verify=False, allow_redirects=True)
            has_session_cookie = any(
                c for c in probe.cookies
                if any(kw in c.name.lower() for kw in ("session", "sess", "sid", "auth", "token"))
            )
        except Exception:
            has_session_cookie = True  # assume cookie-based if we can't tell
        if has_session_cookie:
            if not re.search(r'(csrf|_token|nonce|authenticity)', html, re.I):
                results.append(finding("MEDIUM", "No CSRF Token Detected in Login Form",
                    "No CSRF token pattern found in login page HTML.",
                    "Add CSRF tokens to all state-changing forms."))
            else:
                results.append(finding("PASS", "CSRF Token Pattern Detected",
                    "A CSRF token or nonce pattern was found in the login page."))
        else:
            results.append(finding("PASS", "CSRF Not Applicable (Stateless Auth)",
                "No session cookies detected — site appears to use stateless JWT Bearer auth, "
                "which is not vulnerable to CSRF."))

        # Check for 2FA / MFA signals (SECURITY.md §1b)
        twofa_text_signals = [
            "two-factor", "two factor", "2fa", "mfa", "multi-factor",
            "authenticator", "verification code", "one-time", "totp",
        ]
        has_2fa_text = any(sig in html.lower() for sig in twofa_text_signals)
        has_otp_field = bool(re.search(
            r'<input[^>]+(?:name|id|placeholder)=["\'][^"\']*(?:otp|totp|mfa|2fa|code)[^"\']*["\']',
            html, re.I))
        has_otp_autocomplete = bool(re.search(r'autocomplete=["\']one-time-code["\']', html, re.I))
        if has_2fa_text or has_otp_field or has_otp_autocomplete:
            results.append(finding("PASS", "Two-Factor Authentication Signals Detected",
                "Login page contains evidence of 2FA/MFA support (OTP input fields or authenticator text)."))
        else:
            results.append(finding("LOW", "No Two-Factor Authentication Detected",
                "Login page shows no evidence of two-factor or multi-factor authentication.",
                "Implement TOTP-based 2FA (e.g. Google Authenticator) especially for admin and "
                "high-privilege accounts. Consider requiring 2FA for vote submission and board member access."))

        # Check cookie flags on login attempt (HEAD request)
        try:
            r2 = session.head(url, timeout=TIMEOUT, verify=False, allow_redirects=True)
            for cookie in r2.cookies:
                flags = []
                if not cookie.secure:
                    flags.append("missing Secure flag")
                if not cookie.has_nonstandard_attr("HttpOnly"):
                    flags.append("missing HttpOnly flag")
                if flags:
                    results.append(finding("MEDIUM", f"Cookie '{cookie.name}' Has Weak Flags",
                        f"Cookie issues: {', '.join(flags)}.",
                        "Set Secure and HttpOnly flags on all session cookies.",
                        f"Cookie: {cookie.name}"))
                else:
                    results.append(finding("PASS", f"Cookie '{cookie.name}' Has Secure Flags",
                        "Cookie has Secure and HttpOnly flags set."))
        except Exception:
            pass

    if not login_urls:
        results.append(finding("INFO", "No Login Page Found at Common Paths",
            "Could not locate a login form at common paths. Manual review recommended."))

    return results


def check_brute_force(session, base_url, stealth=False):
    """Send repeated failed login attempts and test for rate limiting / account lockout (SECURITY.md §1b)."""
    results = []
    login_form_action = None
    post_fields = {}

    for path in ["/login", "/signin", "/user/login", "/auth/login", ""]:
        url = base_url.rstrip("/") + path
        r = safe_get(session, url, stealth=stealth)
        if not r or r.status_code != 200:
            continue
        if not any(kw in r.text.lower() for kw in ["password", "passwd"]):
            continue

        # Extract form action
        action_m = re.search(r'<form[^>]+action=["\']([^"\']*)["\']', r.text, re.I)
        action = action_m.group(1) if action_m else path
        if not action.startswith("http"):
            action = urllib.parse.urljoin(base_url, action)

        # Find password field name
        pw_m = (re.search(r'<input[^>]+type=["\']password["\'][^>]+name=["\']([^"\']+)["\']', r.text, re.I) or
                re.search(r'<input[^>]+name=["\']([^"\']+)["\'][^>]+type=["\']password["\']', r.text, re.I))
        if not pw_m:
            continue

        post_fields = {pw_m.group(1): "WrongPassword123!"}

        # Find username/email field
        user_m = re.search(
            r'<input[^>]*name=["\']([^"\']*(?:email|user|login|name)[^"\']*)["\']',
            r.text, re.I)
        if user_m:
            post_fields[user_m.group(1)] = "testuser@example.com"

        # Extract CSRF token from form if present (so failures aren't masked by CSRF rejection)
        csrf_m = re.search(
            r'<input[^>]+name=["\']([^"\']*(?:csrf|token|nonce|authenticity)[^"\']*)["\'][^>]+value=["\']([^"\']+)["\']',
            r.text, re.I)
        if csrf_m:
            post_fields[csrf_m.group(1)] = csrf_m.group(2)

        login_form_action = action
        break

    if not login_form_action:
        results.append(finding("INFO", "Brute Force Check: No Login Form Found",
            "Could not locate a login form with a password field at common paths."))
        return results

    rate_limited = False
    lockout_triggered = False
    attempts = 0

    for _ in range(6):
        try:
            r = session.post(
                login_form_action, data=post_fields,
                timeout=TIMEOUT, verify=False, allow_redirects=True,
                headers={"User-Agent": random.choice(ROTATING_USER_AGENTS)})
            attempts += 1

            if r.status_code in (429, 503):
                rate_limited = True
                break
            if r.status_code == 403 and any(
                    p in r.text.lower() for p in ["rate", "too many", "blocked", "throttl"]):
                rate_limited = True
                break

            lockout_phrases = [
                "account locked", "too many attempts", "account disabled",
                "temporarily locked", "try again later", "temporarily suspended",
                "suspicious activity", "account has been locked",
            ]
            if any(phrase in r.text.lower() for phrase in lockout_phrases):
                lockout_triggered = True
                break

            if stealth:
                time.sleep(random.uniform(0.2, 0.5))
        except Exception:
            pass

    if rate_limited:
        results.append(finding("PASS", "Rate Limiting Enforced on Login Endpoint",
            f"Server returned a rate-limiting response after {attempts} failed attempt(s).",
            evidence=f"Triggered after {attempts} attempt(s) to {login_form_action}"))
    elif lockout_triggered:
        results.append(finding("PASS", "Account Lockout Enforced on Login Endpoint",
            f"Server returned an account lockout message after {attempts} failed attempt(s).",
            evidence=f"Triggered after {attempts} attempt(s) to {login_form_action}"))
    else:
        results.append(finding("HIGH", "No Brute Force Protection Detected",
            f"Sent {attempts} failed login attempt(s) to {login_form_action} without triggering "
            f"rate limiting or account lockout.",
            "Implement account lockout after 5–10 failed attempts and/or rate limiting (HTTP 429). "
            "Consider CAPTCHA after repeated failures. "
            "Geofence admin login endpoints to known IP ranges where possible.",
            f"Endpoint: {login_form_action}"))

    return results


def check_mixed_content(session, base_url):
    results = []
    if not base_url.startswith("https://"):
        return results

    r = safe_get(session, base_url)
    if not r:
        return results

    http_resources = re.findall(r'(?:src|href|action)=["\']http://[^"\']+["\']', r.text, re.I)
    http_resources = list(set(http_resources))[:10]

    if http_resources:
        results.append(finding("MEDIUM", "Potential Mixed Content Found",
            f"Found {len(http_resources)} HTTP resource(s) on an HTTPS page.",
            "Replace all HTTP resource URLs with HTTPS equivalents.",
            "; ".join(http_resources[:5])))
    else:
        results.append(finding("PASS", "No Mixed Content Detected",
            "No obvious HTTP resources found on this HTTPS page."))

    return results


# ─────────────────────────────────────────────
# TECHNOLOGY FINGERPRINTING  (passive)
# ─────────────────────────────────────────────

def check_fingerprint(response, all_headers):
    """Detect technologies and give category-appropriate advice for each."""
    results = []
    all_detected = set()

    body = response.text if response else ""
    header_str = " ".join(f"{k}: {v}" for k, v in all_headers.items())
    combined = body + " " + header_str

    # Cookie names
    cookie_names = [c.lower() for c in response.cookies.keys()] if response else []

    # ── Detect by category ──
    managed   = set()
    self_hosted = set()
    frontend  = set()

    for pattern, tech in MANAGED_PLATFORMS:
        if re.search(pattern, combined, re.I):
            managed.add(tech)

    for pattern, tech in SELF_HOSTED_FRAMEWORKS:
        if re.search(pattern, combined, re.I):
            self_hosted.add(tech)

    # Cookie-based detection for self-hosted
    if any("laravel" in c or "xsrf" in c for c in cookie_names):
        self_hosted.add("Laravel")
    if "phpsessid" in cookie_names:
        self_hosted.add("PHP")
    if "asp.net_sessionid" in cookie_names or "aspsessionid" in cookie_names:
        self_hosted.add("ASP.NET")
    if "jsessionid" in cookie_names:
        self_hosted.add("Java/Tomcat")
    if "rack.session" in cookie_names:
        self_hosted.add("Ruby on Rails")

    for pattern, tech in FRONTEND_FRAMEWORKS:
        if re.search(pattern, combined, re.I):
            frontend.add(tech)

    all_detected = managed | self_hosted | frontend

    # ── Managed platforms: no action needed ──
    if managed:
        results.append(finding("INFO",
            f"Managed Platform(s) Detected: {', '.join(sorted(managed))}",
            "These services are identifiable by design — their URLs, DNS records, and headers "
            "are public infrastructure. Hiding them would require leaving the platform and "
            "provides no real security benefit.",
            "No action needed. Security comes from correct platform configuration "
            "(e.g. Supabase RLS policies, Vercel access controls) — not obscurity.",
            ", ".join(sorted(managed))))

    # ── Frontend frameworks: visible by design ──
    if frontend:
        results.append(finding("INFO",
            f"Frontend Framework(s) Detected: {', '.join(sorted(frontend))}",
            "Client-side frameworks are visible in the browser bundle by design. "
            "An attacker gains nothing actionable from knowing you use React or Next.js.",
            "No action needed. Focus security effort on your application logic, "
            "API authentication, and RLS/access control rules.",
            ", ".join(sorted(frontend))))

    # ── Self-hosted frameworks: version disclosure is the real risk ──
    if self_hosted:
        results.append(finding("LOW",
            f"Self-Hosted Framework(s) Detected: {', '.join(sorted(self_hosted))}",
            "Unlike managed platforms, self-hosted software requires you to apply patches. "
            "The framework name alone is not a serious risk — but version strings are, "
            "because CVEs are version-specific. See the Version Disclosure section.",
            "Keep all self-hosted software updated. The version number check below "
            "will tell you specifically what to strip.",
            ", ".join(sorted(self_hosted))))

        if "WordPress" in self_hosted:
            results.append(finding("MEDIUM", "WordPress Detected — Elevated Risk",
                "WordPress is the most actively exploited CMS. The risk comes from "
                "outdated plugins and themes, not the platform itself.",
                "Keep core, plugins, and themes updated. Disable XML-RPC if unused (/xmlrpc.php). "
                "Consider a WordPress-tuned WAF ruleset."))

        if "PHP" in self_hosted or any(t in self_hosted for t in ["WordPress", "Drupal", "Joomla"]):
            results.append(finding("LOW", "PHP Stack Detected",
                "PHP applications are susceptible to LFI, RFI, and unsafe deserialization "
                "if php.ini is not hardened.",
                "Set: expose_php=Off, disable_functions=exec,passthru,shell_exec,system, "
                "open_basedir to restrict file access."))

    if not all_detected:
        results.append(finding("INFO", "No Technology Fingerprint Matched",
            "Could not identify the underlying framework or CMS from response signatures."))

    return results, all_detected


def check_version_disclosure(response):
    """Hunt for specific version numbers in headers and HTML — the genuinely risky disclosure."""
    results = []
    if not response:
        return results

    headers_str = " ".join(f"{k}: {v}" for k, v in response.headers.items())
    body = response.text[:50000]  # first 50KB is enough
    versions_found = []

    for pattern, tech, source in VERSION_DISCLOSURE_PATTERNS:
        search_target = headers_str if source == "header" else body
        m = re.search(pattern, search_target, re.I)
        if m:
            version_str = m.group(1) if m.lastindex else m.group(0)
            versions_found.append((tech, version_str.strip(), source))

    if versions_found:
        for tech, version, source in versions_found:
            loc = "HTTP header" if source == "header" else "HTML source"
            results.append(finding("MEDIUM",
                f"Version Number Disclosed: {tech} {version}",
                f"Exact version '{version}' is visible in the {loc}. "
                f"Attackers can cross-reference this against published CVE databases.",
                _version_fix_advice(tech),
                f"{tech} {version} (from {loc})"))
    else:
        results.append(finding("PASS", "No Version Numbers Disclosed",
            "No specific version strings found in headers or HTML source."))

    return results


def _version_fix_advice(tech):
    """Return targeted remediation advice for a given technology."""
    advice = {
        "nginx":    "In nginx.conf set: server_tokens off;",
        "Apache":   "In httpd.conf or .htaccess set: ServerTokens Prod  and  ServerSignature Off",
        "IIS":      "Remove the X-Powered-By header in IIS Manager → HTTP Response Headers.",
        "PHP":      "In php.ini set: expose_php = Off",
        "Express.js": "In your app: app.disable('x-powered-by')  or use the helmet middleware.",
        "ASP.NET":  "In web.config remove the X-AspNet-Version header: "
                    "<httpRuntime enableVersionHeader='false'/>",
        "WordPress": "Remove the generator meta tag via: remove_action('wp_head', 'wp_generator');",
        "Drupal":   "Disable version disclosure in Drupal's performance settings.",
        "Angular":  "Build with --configuration=production which strips ng-version attributes.",
        "jQuery":   "Ensure you are on the latest version; consider removing the version comment "
                    "from the bundle with a minifier.",
        "Bootstrap": "No server-side change needed; ensure you are on the latest version.",
        "OpenSSL":  "Recompile nginx/Apache with -DOPENSSL_NO_HEARTBEATS or upgrade OpenSSL.",
    }
    return advice.get(tech,
        f"Remove or suppress the {tech} version string from response headers and HTML.")


# ─────────────────────────────────────────────
# JAVASCRIPT SECRET SCANNING  (passive)
# ─────────────────────────────────────────────

def check_js_secrets(session, base_url, stealth=False):
    """Fetch JS files linked from the page and scan for hardcoded secrets."""
    results = []
    r = safe_get(session, base_url, stealth=stealth)
    if not r:
        results.append(finding("INFO", "JS Secret Scan: Page Unreachable",
            "Could not load the page to locate JavaScript files."))
        return results

    # Collect JS file URLs from the page
    js_urls = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', r.text, re.I)
    js_urls = list(set(js_urls))[:15]  # cap at 15 to avoid hammering the server

    absolute_js = []
    for js in js_urls:
        if js.startswith("http"):
            absolute_js.append(js)
        elif js.startswith("//"):
            absolute_js.append("https:" + js)
        else:
            absolute_js.append(urllib.parse.urljoin(base_url, js))

    # Also check inline scripts
    inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', r.text, re.S | re.I)
    inline_combined = "\n".join(inline_scripts)

    secrets_found = []

    # Scan inline scripts
    for pattern, label in JS_SECRET_PATTERNS:
        matches = re.findall(pattern, inline_combined)
        for match in matches[:3]:
            val = match if isinstance(match, str) else match[0]
            # Skip obvious template placeholders
            if re.search(r'(YOUR|EXAMPLE|PLACEHOLDER|INSERT|REPLACE|xxx)', val, re.I):
                continue
            secrets_found.append((label, val[:60] + "..." if len(val) > 60 else val, "inline script"))

    # Fetch and scan each JS file
    for js_url in absolute_js[:8]:
        js_r = safe_get(session, js_url, stealth=stealth)
        if not js_r or js_r.status_code != 200:
            continue
        # Skip minified files over 500KB — too slow and too many false positives
        if len(js_r.content) > 500_000:
            continue
        for pattern, label in JS_SECRET_PATTERNS:
            matches = re.findall(pattern, js_r.text)
            for match in matches[:2]:
                val = match if isinstance(match, str) else match[0]
                if re.search(r'(YOUR|EXAMPLE|PLACEHOLDER|INSERT|REPLACE|xxx)', val, re.I):
                    continue
                secrets_found.append((label, val[:60] + "..." if len(val) > 60 else val, js_url))

    if secrets_found:
        seen = set()
        for label, val, source in secrets_found:
            key = (label, val[:30])
            if key in seen:
                continue
            seen.add(key)
            short_source = source.split("/")[-1] if "/" in source else source
            results.append(finding("CRITICAL", f"Possible Hardcoded Secret in JS: {label}",
                f"Found in {short_source}",
                "Remove all secrets from client-side code. Use environment variables server-side. "
                "Rotate any exposed credentials immediately.",
                val))
    else:
        results.append(finding("PASS", "No Obvious Secrets in JavaScript",
            f"Scanned {len(absolute_js)} JS file(s) and inline scripts — no credential patterns matched."))

    return results


# ─────────────────────────────────────────────
# DATABASE KEY PROBING
# ─────────────────────────────────────────────

def _collect_js_text(session, base_url, stealth=False, size_limit=500_000):
    """Return a single string of all JS content (inline + external files).

    For Next.js sites the initial HTML often contains very few <script src> tags —
    the real bundles live under /_next/static/chunks/.  We probe those paths
    explicitly so framework-bundled secrets are not missed.
    """
    r = safe_get(session, base_url, stealth=stealth)
    if not r:
        return ""
    parts = re.findall(r'<script[^>]*>(.*?)</script>', r.text, re.S | re.I)

    # Collect all <script src> URLs from the page
    js_urls = list(set(re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', r.text, re.I)))

    # Next.js: also probe common chunk paths that may not appear in the initial HTML
    parsed = urllib.parse.urlparse(base_url)
    next_root = f"{parsed.scheme}://{parsed.netloc}"
    # The buildId is embedded in __NEXT_DATA__ — extract it if present
    build_id_m = re.search(r'"buildId"\s*:\s*"([^"]+)"', r.text)
    if build_id_m:
        build_id = build_id_m.group(1)
        js_urls += [
            f"/_next/static/{build_id}/_buildManifest.js",
            f"/_next/static/chunks/pages/_app.js",
            f"/_next/static/chunks/pages/index.js",
        ]
    # Probe the chunks directory listing heuristic (common filenames)
    js_urls += [
        "/_next/static/chunks/main.js",
        "/_next/static/chunks/webpack.js",
        "/_next/static/chunks/framework.js",
        "/_next/static/chunks/pages/_app.js",
    ]

    seen = set()
    for js in js_urls[:20]:
        if js.startswith("http"):
            abs_url = js
        elif js.startswith("//"):
            abs_url = "https:" + js
        else:
            abs_url = urllib.parse.urljoin(base_url, js)
        if abs_url in seen:
            continue
        seen.add(abs_url)
        jr = safe_get(session, abs_url, stealth=stealth)
        if not jr or jr.status_code != 200:
            continue
        # For large files, still search — but only keep if they contain a Supabase/Firebase signal
        if len(jr.content) > size_limit:
            if re.search(r'supabase\.co|firebaseio\.com|firebaseapp\.com', jr.text):
                parts.append(jr.text)
        else:
            parts.append(jr.text)
    return "\n".join(parts)


def check_db_keys(session, base_url, stealth=False, detected_tech=None):
    """Extract Supabase/Firebase keys from client JS and probe whether they grant live DB access."""
    detected_tech = detected_tech or set()
    supabase_expected = "Supabase" in detected_tech
    firebase_expected = "Firebase" in detected_tech

    results = []
    all_js = _collect_js_text(session, base_url, stealth=stealth)
    if not all_js:
        results.append(finding("INFO", "DB Key Probe: Page Unreachable",
            "Could not load page JS to scan for database keys."))
        return results

    probed = []

    # ── Supabase ──
    # Pass 1: createClient("https://xxx.supabase.co", "eyJ...") — intact source
    supabase_pairs = re.findall(
        r'createClient\s*\(\s*["\']?(https://[a-z0-9]+\.supabase\.co)["\']?\s*,\s*["\']?(eyJ[A-Za-z0-9_\-\.]{20,})["\']?',
        all_js, re.I
    )
    # Pass 2: named variable assignments (common in env-var patterns)
    if not supabase_pairs:
        url_m = re.search(r'["\']?(https://[a-z0-9]+\.supabase\.co)["\']?', all_js)
        key_m = re.search(
            r'(?:supabase[_\-]?anon[_\-]?key|anon[_\-]?key|supabaseKey)\s*[=:]\s*["\']?(eyJ[A-Za-z0-9_\-\.]{20,})["\']?',
            all_js, re.I)
        if url_m and key_m:
            supabase_pairs = [(url_m.group(1), key_m.group(1))]
    # Pass 3: co-occurrence — any JWT within 300 chars of a supabase.co URL (handles minified bundles)
    if not supabase_pairs:
        for m in re.finditer(r'https://([a-z0-9]+)\.supabase\.co', all_js, re.I):
            window = all_js[max(0, m.start() - 300): m.end() + 300]
            jwt_m = re.search(r'eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{10,}', window)
            if jwt_m:
                supabase_pairs = [(m.group(0), jwt_m.group(0))]
                break

    for supabase_url, anon_key in supabase_pairs[:2]:
        try:
            headers = {"apikey": anon_key, "Authorization": f"Bearer {anon_key}"}
            # Hit the PostgREST root — returns OpenAPI spec listing all exposed tables
            root_resp = session.get(
                supabase_url.rstrip("/") + "/rest/v1/",
                headers=headers, timeout=TIMEOUT, verify=False)

            if root_resp.status_code == 401:
                probed.append(("PASS", "Supabase Anon Key Rejected",
                    "Anon key found in client JS was rejected (401) by the database API.",
                    None, f"Project: {supabase_url}"))
                continue

            if root_resp.status_code != 200:
                continue

            try:
                spec = root_resp.json()
            except Exception:
                continue

            table_paths = [p.lstrip("/") for p in spec.get("paths", {}) if p not in ("/", "")]
            if not table_paths:
                probed.append(("PASS", "Supabase Anon Key: No Tables Exposed",
                    "Anon key accepted but no readable tables found in API spec.",
                    None, f"Project: {supabase_url}"))
                continue

            # Try to read one row from the first listed table
            table = table_paths[0]
            row_resp = session.get(
                f"{supabase_url.rstrip('/')}/rest/v1/{table}?select=*&limit=1",
                headers=headers, timeout=TIMEOUT, verify=False)

            if row_resp.status_code == 200:
                try:
                    data = row_resp.json()
                except Exception:
                    data = None
                if isinstance(data, list):
                    probed.append(("CRITICAL", "Supabase Anon Key Grants Database Read Access",
                        f"Anon key from client JS successfully read table '{table}' ({len(data)} row(s) returned). "
                        "Row Level Security (RLS) is disabled or overly permissive.",
                        "Enable RLS on all Supabase tables. Anon keys are intentionally public — "
                        "RLS is the only thing preventing public data access.",
                        f"Table: {table} | Rows returned: {len(data)} | Key: {anon_key[:24]}..."))
                else:
                    probed.append(("HIGH", "Supabase Anon Key Accepted (Unexpected Response)",
                        f"Anon key authenticated against {supabase_url} but table read returned unexpected format.",
                        "Manually verify RLS is enabled on all tables.",
                        f"Key: {anon_key[:24]}..."))
            elif row_resp.status_code == 401:
                probed.append(("PASS", "Supabase RLS Active",
                    f"Anon key accepted by API but table '{table}' read returned 401 — RLS is enforced.",
                    None, f"Project: {supabase_url}"))
        except Exception:
            pass

    # ── Firebase Realtime Database ──
    firebase_db_urls = re.findall(
        r'databaseURL\s*[=:]\s*["\']?(https://[a-z0-9\-]+\.firebaseio\.com)["\']?',
        all_js, re.I)

    for db_url in firebase_db_urls[:2]:
        try:
            resp = session.get(db_url.rstrip("/") + "/.json", timeout=TIMEOUT, verify=False)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                except Exception:
                    data = None
                if data is not None:
                    probed.append(("CRITICAL", "Firebase Realtime Database Publicly Readable",
                        f"Unauthenticated GET to {db_url}/.json returned data — security rules allow public read.",
                        'Set Firebase rules to require auth: { "rules": { ".read": "auth != null", ".write": "auth != null" } }',
                        str(data)[:120]))
                else:
                    probed.append(("PASS", "Firebase Realtime Database Returns Null",
                        "Unauthenticated read returned null — database is empty or rules restrict access.",
                        None, db_url))
            elif resp.status_code in (401, 403):
                probed.append(("PASS", "Firebase Realtime Database Correctly Restricted",
                    f"Unauthenticated read to {db_url}/.json returned {resp.status_code} — rules require auth.",
                    None, db_url))
        except Exception:
            pass

    # ── Firestore ──
    project_ids = re.findall(r'projectId\s*[=:]\s*["\']([a-z0-9\-]+)["\']', all_js, re.I)

    for project_id in project_ids[:2]:
        try:
            fs_url = f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents"
            resp = session.get(fs_url, timeout=TIMEOUT, verify=False)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    docs = data.get("documents", [])
                except Exception:
                    docs = []
                if docs:
                    probed.append(("CRITICAL", "Firestore Database Publicly Readable",
                        f"Unauthenticated GET to Firestore project '{project_id}' returned {len(docs)} document(s). "
                        "Security rules allow public read.",
                        "Set Firestore security rules to require authentication on all collections.",
                        f"Project: {project_id} | Documents at root: {len(docs)}"))
                else:
                    probed.append(("PASS", "Firestore: No Documents at Root",
                        "Unauthenticated Firestore read returned no documents at root — rules may still be open on subcollections.",
                        "Verify Firestore rules explicitly deny unauthenticated reads on all collections.",
                        f"Project: {project_id}"))
            elif resp.status_code in (401, 403):
                probed.append(("PASS", "Firestore Correctly Restricted",
                    f"Unauthenticated Firestore read returned {resp.status_code} — rules require auth.",
                    None, f"Project: {project_id}"))
        except Exception:
            pass

    if not supabase_pairs and not firebase_db_urls and not project_ids:
        if supabase_expected:
            results.append(finding("MEDIUM", "Supabase Detected but Anon Key Not Found in JS",
                "Supabase was identified via fingerprinting but no anon key could be extracted from "
                "client-side JS. The key may be in a large bundle that was not fully scanned, loaded "
                "via a service worker, or injected at runtime.",
                "Manually verify RLS is enabled on all tables. Check network requests in DevTools "
                "for the Authorization header to confirm the anon key in use."))
        elif firebase_expected:
            results.append(finding("MEDIUM", "Firebase Detected but Config Not Found in JS",
                "Firebase was identified via fingerprinting but no API key or project config could "
                "be extracted from client-side JS.",
                "Manually verify Firebase security rules require authentication."))
        else:
            results.append(finding("PASS", "No Database Keys Detected",
                "No Supabase or Firebase database configuration found in client-side JS."))
        return results

    if not probed:
        results.append(finding("INFO", "Database Keys Found but Probes Inconclusive",
            "Database configuration was detected in JS but live probes failed or timed out."))
        return results

    for severity, title, detail, rec, evidence in probed:
        results.append(finding(severity, title, detail, rec, evidence))

    return results


# ─────────────────────────────────────────────
# DNS RECONNAISSANCE  (bypasses WAF entirely)
# ─────────────────────────────────────────────

def check_dns_recon(hostname):
    """DNS-based recon: SPF, DMARC, MX, subdomain enumeration."""
    results = []

    if not HAS_DNSPYTHON:
        results.append(finding("INFO", "DNS Recon Skipped",
            "Install dnspython for DNS recon: pip install dnspython"))
        return results

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 5

    # ── SPF ──
    try:
        answers = resolver.resolve(hostname, "TXT")
        spf_records = [r.to_text() for r in answers if "v=spf1" in r.to_text()]
        if not spf_records:
            results.append(finding("MEDIUM", "No SPF Record Found",
                "Without SPF, attackers can spoof emails from your domain.",
                "Add a TXT record: v=spf1 include:... ~all"))
        else:
            spf = spf_records[0]
            if spf.endswith("+all\"") or spf.endswith("+all"):
                results.append(finding("HIGH", "SPF Record Uses +all (Permissive)",
                    "'+all' allows anyone to send email as your domain.",
                    "Replace +all with ~all (soft fail) or -all (hard fail).", spf))
            elif spf.endswith("-all\"") or spf.endswith("-all"):
                results.append(finding("PASS", "SPF Record Configured (Strict)",
                    "SPF uses -all which rejects unauthorised senders.", evidence=spf))
            else:
                results.append(finding("LOW", "SPF Record Uses ~all (Soft Fail)",
                    "Soft fail still allows spoofed emails to be delivered.",
                    "Consider upgrading to -all for stricter enforcement.", spf))
    except Exception:
        results.append(finding("INFO", "SPF Record Lookup Failed",
            "Could not retrieve TXT records for SPF check."))

    # ── DMARC ──
    try:
        dmarc_host = f"_dmarc.{hostname}"
        answers = resolver.resolve(dmarc_host, "TXT")
        dmarc_records = [r.to_text() for r in answers if "v=DMARC1" in r.to_text()]
        if not dmarc_records:
            results.append(finding("MEDIUM", "No DMARC Record Found",
                "Without DMARC, spoofed emails from your domain may not be reported or blocked.",
                "Add: _dmarc TXT \"v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com\""))
        else:
            dmarc = dmarc_records[0]
            if "p=none" in dmarc:
                results.append(finding("LOW", "DMARC Policy is 'none' (Monitor Only)",
                    "p=none means spoofed emails are reported but not blocked.",
                    "Upgrade to p=quarantine or p=reject once you have reviewed reports.", dmarc))
            elif "p=reject" in dmarc:
                results.append(finding("PASS", "DMARC Policy is 'reject' (Strict)",
                    "Spoofed emails are rejected outright.", evidence=dmarc))
            else:
                results.append(finding("PASS", "DMARC Record Present",
                    "DMARC configured with quarantine policy.", evidence=dmarc))
    except dns.exception.DNSException:
        results.append(finding("MEDIUM", "No DMARC Record Found",
            "Could not resolve _dmarc record — DMARC is likely not configured.",
            "Add a DMARC TXT record to your DNS."))
    except Exception:
        pass

    # ── MX Records ──
    try:
        mx_records = resolver.resolve(hostname, "MX")
        mx_list = sorted([(r.preference, str(r.exchange)) for r in mx_records])
        results.append(finding("INFO", "MX Records",
            f"{len(mx_list)} mail server(s): " + ", ".join(f"{p} {h}" for p, h in mx_list[:5]),
            evidence=str(mx_list[:5])))
    except Exception:
        pass

    # ── Subdomain Enumeration (DNS brute-force, bypasses WAF) ──
    live_subs = []
    for sub in COMMON_SUBDOMAINS:
        fqdn = f"{sub}.{hostname}"
        try:
            addrs = socket.getaddrinfo(fqdn, None)
            ips = list(set(a[4][0] for a in addrs))
            live_subs.append((fqdn, ips))
        except socket.gaierror:
            pass

    if live_subs:
        sub_list = ", ".join(f"{fqdn} ({', '.join(ips)})" for fqdn, ips in live_subs[:10])
        results.append(finding("INFO", f"Live Subdomains Found ({len(live_subs)})",
            f"Resolving subdomains: {sub_list}",
            "Ensure all subdomains are intentional and secured. "
            "Dangling subdomains can be hijacked if their DNS record points to a decommissioned service.",
            sub_list))

        # Flag dev/staging subdomains specifically
        risky_subs = [(s, ips) for s, ips in live_subs
                      if any(kw in s for kw in ["dev.", "staging.", "test.", "beta.", "preview."])]
        if risky_subs:
            for fqdn, ips in risky_subs:
                results.append(finding("MEDIUM", f"Dev/Staging Subdomain Exposed: {fqdn}",
                    f"Resolves to {', '.join(ips)} — dev environments often have weaker security.",
                    "Restrict access to staging/dev subdomains via IP allowlist or basic auth."))
    else:
        results.append(finding("INFO", "No Common Subdomains Resolved",
            f"Checked {len(COMMON_SUBDOMAINS)} common subdomains — none resolved."))

    return results


# ─────────────────────────────────────────────
# HTTP METHOD ENUMERATION  (passive)
# ─────────────────────────────────────────────

def check_http_methods(session, url, stealth=False):
    """Check which HTTP methods the server allows — dangerous ones like PUT/DELETE are a risk."""
    results = []
    try:
        r = session.options(url, timeout=TIMEOUT, verify=False,
                            headers={"User-Agent": random.choice(ROTATING_USER_AGENTS)})
        stealth_delay(stealth)
        allow = r.headers.get("Allow", r.headers.get("Access-Control-Allow-Methods", ""))

        if not allow:
            results.append(finding("INFO", "No Allow Header in OPTIONS Response",
                "Server did not return an Allow header — method enumeration inconclusive."))
            return results

        methods = [m.strip().upper() for m in allow.split(",")]
        dangerous = [m for m in methods if m in ("PUT", "DELETE", "PATCH", "CONNECT", "TRACE")]

        results.append(finding("INFO", "HTTP Methods Allowed",
            f"Server advertises: {', '.join(methods)}", evidence=allow))

        if "TRACE" in methods:
            results.append(finding("MEDIUM", "HTTP TRACE Method Enabled",
                "TRACE can be used in Cross-Site Tracing (XST) attacks to steal cookies.",
                "Disable TRACE in your web server configuration."))
        if dangerous:
            results.append(finding("LOW", f"Potentially Dangerous Methods Allowed: {', '.join(dangerous)}",
                "Write methods exposed at the root path may allow unintended modifications.",
                "Restrict PUT/DELETE/PATCH to authenticated API endpoints only."))
        else:
            results.append(finding("PASS", "No Dangerous HTTP Methods at Root",
                "TRACE, PUT, DELETE not advertised by OPTIONS response."))

    except Exception as e:
        results.append(finding("INFO", "HTTP Method Enumeration Failed", str(e)))

    return results


# ─────────────────────────────────────────────
# ACTIVE INJECTION CHECKS  (opt-in via --active)
# ─────────────────────────────────────────────

# SQL error signatures that indicate a backend is reflecting raw error output
SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning.*mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"pg_query\(\).*error",
    r"supplied argument is not a valid (mysql|postgresql|oracle)",
    r"sqlite_\w+\(\)",
    r"odbc_exec\(\)",
    r"microsoft ole db provider for sql server",
    r"ora-\d{4,}",
    r"syntax error.*sql",
    r"sqlstate\[",
    r"db2 sql error",
    r"jdbc\.SQLException",
]

# SQL detection payloads — chosen to trigger errors, not to exploit
SQL_PAYLOADS = ["'", '"', "' OR '1'='1' --", "1; --", "\\",
                "' OR 1=1 --", "\" OR \"\"=\"", "1' ORDER BY 1--",
                "1' ORDER BY 2--", "' UNION SELECT NULL--"]

# Blind SQLi: time-based payloads per dialect — server should pause if vulnerable
BLIND_SQLI_PAYLOADS = [
    ("MySQL",      f"' OR SLEEP({BLIND_SQLI_DELAY}) --"),
    ("MySQL",      f"1 AND SLEEP({BLIND_SQLI_DELAY})"),
    ("PostgreSQL", f"'; SELECT pg_sleep({BLIND_SQLI_DELAY}); --"),
    ("MSSQL",      f"'; WAITFOR DELAY '0:0:{BLIND_SQLI_DELAY}'; --"),
    ("SQLite",     f"' OR randomblob(500000000) --"),  # CPU stall, not time-based
]

# Open redirect sinks to test
REDIRECT_PARAMS = ["redirect", "redirect_to", "redirect_url", "url", "next",
                   "return", "returnTo", "return_url", "goto", "target", "to",
                   "destination", "redir", "forward", "location", "ref"]

# XSS: inject a unique tag and check if it comes back unescaped
def _xss_token():
    uid = uuid.uuid4().hex[:8]
    return f"<xss-probe-{uid}>", f"xss-probe-{uid}"

# Template / expression injection: look for evaluated output (7*7=49)
TEMPLATE_PAYLOADS = ["{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>"]


def check_blind_sqli(session, base_url, stealth=False):
    """Time-based blind SQL injection — detects vulnerabilities hidden behind error suppression."""
    results = []
    inputs = _discover_inputs_raw(session, base_url)

    if not inputs:
        results.append(finding("INFO", "Blind SQLi: No Inputs Found",
            "No parameters found to test for blind SQL injection."))
        return results

    vulnerable = []
    for (kind, action, param, method) in inputs[:6]:  # cap to avoid hammering
        for dialect, payload in BLIND_SQLI_PAYLOADS[:3]:  # 3 dialects per param
            try:
                start = time.time()
                if method == "GET":
                    parsed = urllib.parse.urlparse(action)
                    qs = urllib.parse.parse_qs(parsed.query)
                    qs[param] = [payload]
                    test_url = urllib.parse.urlunparse(
                        parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)))
                    r = session.get(test_url, timeout=BLIND_SQLI_DELAY + 6,
                                    verify=False,
                                    headers={"User-Agent": random.choice(ROTATING_USER_AGENTS)})
                else:
                    r = session.post(action, data={param: payload},
                                     timeout=BLIND_SQLI_DELAY + 6, verify=False,
                                     headers={"User-Agent": random.choice(ROTATING_USER_AGENTS)})
                elapsed = time.time() - start
                stealth_delay(stealth)

                if elapsed >= BLIND_SQLI_DELAY - 0.5:
                    vulnerable.append((param, dialect, payload, round(elapsed, 2)))
                    break  # one confirmed hit per param is enough
            except requests.exceptions.Timeout:
                elapsed = time.time() - start
                if elapsed >= BLIND_SQLI_DELAY - 0.5:
                    vulnerable.append((param, dialect, payload + " (timeout)", round(elapsed, 2)))
                    break
            except Exception:
                pass

    if vulnerable:
        for param, dialect, payload, elapsed in vulnerable:
            results.append(finding("CRITICAL",
                f"Blind SQL Injection — Parameter: '{param}' ({dialect})",
                f"Response took {elapsed}s after sleep payload — server likely executed the SQL.",
                "Use parameterised queries / prepared statements for all database interactions.",
                f"param={param}, dialect={dialect}, delay={elapsed}s"))
    else:
        results.append(finding("PASS", "No Blind SQL Injection Detected",
            "Time-based payloads did not produce measurable delays."))

    return results


def check_open_redirect(session, base_url, stealth=False):
    """Test common redirect parameters for open redirect vulnerabilities."""
    results = []
    canary = "https://evil-canary-test.example.com"
    vulnerable = []

    r = safe_get(session, base_url, stealth=stealth)
    if not r:
        results.append(finding("INFO", "Open Redirect: Page Unreachable",
            "Could not load the page to test redirect parameters."))
        return results

    # Also test redirect params embedded in the current URL
    parsed = urllib.parse.urlparse(base_url)
    qs_params = list(urllib.parse.parse_qs(parsed.query).keys())
    params_to_test = list(set(REDIRECT_PARAMS + qs_params))

    for param in params_to_test:
        test_parsed = urllib.parse.urlparse(base_url)
        qs = urllib.parse.parse_qs(test_parsed.query)
        qs[param] = [canary]
        test_url = urllib.parse.urlunparse(
            test_parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)))

        try:
            r2 = session.get(test_url, timeout=TIMEOUT, verify=False,
                             allow_redirects=False,
                             headers={"User-Agent": random.choice(ROTATING_USER_AGENTS)})
            stealth_delay(stealth)
            location = r2.headers.get("Location", "")
            if canary in location:
                vulnerable.append((param, location))
        except Exception:
            pass

    if vulnerable:
        for param, location in vulnerable:
            results.append(finding("HIGH", f"Open Redirect — Parameter: '{param}'",
                f"Server redirected to injected URL: {location}",
                "Validate redirect destinations against a whitelist of allowed URLs. "
                "Never reflect user-supplied URLs directly into Location headers.",
                f"param={param}, location={location}"))
    else:
        results.append(finding("PASS", "No Open Redirects Detected",
            f"Tested {len(params_to_test)} redirect parameter(s) — none redirected to injected URL."))

    return results


def _discover_inputs_raw(session, base_url):
    """Internal: return discovered inputs without printing."""
    inputs = []
    r = safe_get(session, base_url)
    if not r:
        return inputs
    parsed = urllib.parse.urlparse(base_url)
    for param in urllib.parse.parse_qs(parsed.query):
        inputs.append(("url_param", base_url, param, "GET"))
    form_blocks = re.findall(r'<form[^>]*>(.*?)</form>', r.text, re.S | re.I)
    for form_html in form_blocks:
        action_m = re.search(r'<form[^>]+action=["\']([^"\']*)["\']', form_html, re.I)
        method_m = re.search(r'<form[^>]+method=["\']([^"\']*)["\']', form_html, re.I)
        action = action_m.group(1) if action_m else base_url
        method = method_m.group(1).upper() if method_m else "GET"
        if not action.startswith("http"):
            action = urllib.parse.urljoin(base_url, action)
        for name in re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', form_html, re.I):
            inputs.append(("form_field", action, name, method))
        for name in re.findall(r'<textarea[^>]+name=["\']([^"\']+)["\']', form_html, re.I):
            inputs.append(("form_field", action, name, method))
    return inputs


def _discover_inputs(session, base_url):
    """
    Return a list of (test_url, param_name, method) tuples representing
    injectable points found on the page — URL params and HTML form fields.
    """
    inputs = []
    r = safe_get(session, base_url)
    if not r:
        return inputs

    # ── URL parameters already in the URL ──
    parsed = urllib.parse.urlparse(base_url)
    qs = urllib.parse.parse_qs(parsed.query)
    for param in qs:
        inputs.append(("url_param", base_url, param, "GET"))

    # ── HTML form fields ──
    form_blocks = re.findall(r'<form[^>]*>(.*?)</form>', r.text, re.S | re.I)
    for form_html in form_blocks:
        action_m = re.search(r'<form[^>]+action=["\']([^"\']*)["\']', form_html, re.I)
        method_m = re.search(r'<form[^>]+method=["\']([^"\']*)["\']', form_html, re.I)
        action = action_m.group(1) if action_m else base_url
        method = method_m.group(1).upper() if method_m else "GET"

        if not action.startswith("http"):
            action = urllib.parse.urljoin(base_url, action)

        field_names = re.findall(
            r'<input[^>]+name=["\']([^"\']+)["\']', form_html, re.I)
        textarea_names = re.findall(
            r'<textarea[^>]+name=["\']([^"\']+)["\']', form_html, re.I)

        for name in field_names + textarea_names:
            inputs.append(("form_field", action, name, method))

    return inputs


def check_injection(session, base_url):
    results = []
    inputs = _discover_inputs(session, base_url)

    if not inputs:
        results.append(finding("INFO", "No Injectable Inputs Found",
            "No URL parameters or form fields were discovered for injection testing.",
            "If your site has dynamic pages, try passing a URL that includes query parameters."))
        return results

    print(f"      Found {len(inputs)} input(s) to test for injection...")

    sqli_vulnerable = []
    xss_vulnerable = []
    tpl_vulnerable = []
    tested_params = set()

    for (kind, action, param, method) in inputs:
        key = (action, param)
        if key in tested_params:
            continue
        tested_params.add(key)

        # ── SQL Injection ──
        for payload in SQL_PAYLOADS:
            try:
                if method == "GET":
                    test_url = action
                    parsed = urllib.parse.urlparse(action)
                    qs = urllib.parse.parse_qs(parsed.query)
                    qs[param] = [payload]
                    new_qs = urllib.parse.urlencode(qs, doseq=True)
                    test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                    r = safe_get(session, test_url)
                else:
                    r = session.post(action, data={param: payload},
                                     timeout=TIMEOUT, verify=False,
                                     headers={"User-Agent": USER_AGENT})

                if r and r.status_code == 200:
                    body = r.text.lower()
                    for pattern in SQL_ERROR_PATTERNS:
                        if re.search(pattern, body, re.I):
                            sqli_vulnerable.append((param, payload, pattern))
                            break
            except Exception:
                pass

        # ── Reflected XSS ──
        xss_tag, xss_marker = _xss_token()
        try:
            if method == "GET":
                parsed = urllib.parse.urlparse(action)
                qs = urllib.parse.parse_qs(parsed.query)
                qs[param] = [xss_tag]
                new_qs = urllib.parse.urlencode(qs, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                r = safe_get(session, test_url)
            else:
                r = session.post(action, data={param: xss_tag},
                                 timeout=TIMEOUT, verify=False,
                                 headers={"User-Agent": USER_AGENT})

            if r and r.status_code == 200:
                # Unescaped reflection: marker appears as a literal tag
                if xss_marker in r.text and xss_tag in r.text:
                    xss_vulnerable.append((param, xss_tag))
        except Exception:
            pass

        # ── Template / Expression Injection ──
        for tpl_payload in TEMPLATE_PAYLOADS:
            try:
                if method == "GET":
                    parsed = urllib.parse.urlparse(action)
                    qs = urllib.parse.parse_qs(parsed.query)
                    qs[param] = [tpl_payload]
                    new_qs = urllib.parse.urlencode(qs, doseq=True)
                    test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                    r = safe_get(session, test_url)
                else:
                    r = session.post(action, data={param: tpl_payload},
                                     timeout=TIMEOUT, verify=False,
                                     headers={"User-Agent": USER_AGENT})

                if r and r.status_code == 200 and "49" in r.text:
                    # Sanity-check: baseline page shouldn't already contain "49"
                    baseline = safe_get(session, base_url)
                    if baseline and "49" not in baseline.text:
                        tpl_vulnerable.append((param, tpl_payload))
                        break
            except Exception:
                pass

    # ── Compile results ──
    if sqli_vulnerable:
        for param, payload, pattern in sqli_vulnerable:
            results.append(finding(
                "CRITICAL", f"Possible SQL Injection — Parameter: '{param}'",
                f"Payload '{payload}' triggered a SQL error pattern: '{pattern}'.",
                "Use parameterised queries / prepared statements. Never concatenate user input into SQL.",
                f"param={param}, payload={payload}"))
    else:
        results.append(finding("PASS", "No SQL Injection Errors Detected",
            f"Tested {len(tested_params)} input(s) with common SQL payloads — no error signatures found."))

    if xss_vulnerable:
        for param, payload in xss_vulnerable:
            results.append(finding(
                "HIGH", f"Possible Reflected XSS — Parameter: '{param}'",
                f"Injected tag was reflected in the response without HTML encoding.",
                "HTML-encode all user-controlled output. Use a Content-Security-Policy to reduce impact.",
                f"param={param}, reflected payload={payload}"))
    else:
        results.append(finding("PASS", "No Reflected XSS Detected",
            f"Tested {len(tested_params)} input(s) — injected tags were not reflected unescaped."))

    if tpl_vulnerable:
        for param, payload in tpl_vulnerable:
            results.append(finding(
                "CRITICAL", f"Possible Template Injection — Parameter: '{param}'",
                f"Payload '{payload}' evaluated to 49, suggesting server-side template execution.",
                "Never pass user input directly into template engines. Sanitise and sandbox all template rendering.",
                f"param={param}, payload={payload}"))
    else:
        results.append(finding("PASS", "No Template Injection Detected",
            f"Tested {len(tested_params)} input(s) — no expression evaluation detected."))

    return results


# ─────────────────────────────────────────────
# PLAYWRIGHT — HEADLESS BROWSER SCANNING
# ─────────────────────────────────────────────

# JavaScript run inside the browser to extract the fully-rendered page state
_JS_EXTRACT_PAGE = """() => {
    const forms = [];
    document.querySelectorAll('form').forEach(form => {
        const inputs = [];
        form.querySelectorAll('input, textarea, select').forEach(el => {
            const t = (el.type || '').toLowerCase();
            if (!['hidden','submit','button','image','reset','file'].includes(t)) {
                inputs.push({
                    name: el.name || el.id || el.getAttribute('placeholder') || 'field',
                    type: t || el.tagName.toLowerCase(),
                    id: el.id || '',
                    placeholder: el.getAttribute('placeholder') || ''
                });
            }
        });
        if (inputs.length > 0) {
            forms.push({ action: form.action || '', method: (form.method || 'GET').toUpperCase(), inputs });
        }
    });

    // Standalone inputs outside any <form> (common in React)
    const inForm = new Set(Array.from(document.querySelectorAll('form input, form textarea, form select')));
    const standalone = [];
    document.querySelectorAll('input, textarea').forEach(el => {
        const t = (el.type || '').toLowerCase();
        if (!inForm.has(el) && !['hidden','submit','button','image','reset','file'].includes(t)) {
            standalone.push({
                name: el.name || el.id || el.getAttribute('placeholder') || 'field',
                type: t || el.tagName.toLowerCase(),
                id: el.id || '',
                placeholder: el.getAttribute('placeholder') || ''
            });
        }
    });

    // Sensitive globals on window
    const sensitiveGlobals = [];
    const sensKeys = ['token','key','secret','password','auth','api','credential','jwt','bearer'];
    // Browser-standard properties that match sensitive keywords but are not secrets
    const browserBuiltins = new Set([
        'credentialless', 'credentials', 'localStorage', 'sessionStorage',
        'crypto', 'CryptoKey', 'AuthenticatorResponse', 'AuthenticatorAttestationResponse',
        'AuthenticatorAssertionResponse', 'PublicKeyCredential',
        'PasswordCredential', 'FederatedCredential', 'CredentialsContainer',
        'KeyboardEvent', 'KeyframeEffect', 'KeyboardLayoutMap',
        'tokenList', 'apiBaseUrl',
    ]);
    Object.keys(window).forEach(k => {
        if (browserBuiltins.has(k)) return;
        if (sensKeys.some(p => k.toLowerCase().includes(p))) {
            try {
                const v = JSON.stringify(window[k]);
                if (v && v.length > 4 && v !== 'null' && v !== 'undefined'
                    && v !== '{}' && v !== '[]' && v !== 'false' && v !== 'true') {
                    sensitiveGlobals.push({ key: k, value: v.substring(0, 120) });
                }
            } catch(e) {}
        }
    });

    // localStorage contents
    const localStorageItems = {};
    try {
        for (let i = 0; i < localStorage.length; i++) {
            const k = localStorage.key(i);
            localStorageItems[k] = localStorage.getItem(k);
        }
    } catch(e) {}

    // sessionStorage contents
    const sessionStorageItems = {};
    try {
        for (let i = 0; i < sessionStorage.length; i++) {
            const k = sessionStorage.key(i);
            sessionStorageItems[k] = sessionStorage.getItem(k);
        }
    } catch(e) {}

    // Inline comments in HTML that might contain secrets
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_COMMENT);
    const comments = [];
    let node;
    while ((node = walker.nextNode())) {
        const txt = node.nodeValue.trim();
        if (txt.length > 5) comments.push(txt.substring(0, 200));
    }

    return { forms, standalone, sensitiveGlobals, localStorageItems, sessionStorageItems, comments };
}"""

_JS_CONSOLE_ERRORS = """() => window.__pwConsoleErrors || []"""


def _pw_launch(stealth=False):
    """Launch a stealth-configured headless Chromium instance."""
    p = sync_playwright().start()
    browser = p.chromium.launch(
        headless=True,
        args=[
            "--no-sandbox", "--disable-setuid-sandbox",
            "--disable-blink-features=AutomationControlled",
            "--disable-infobars", "--disable-dev-shm-usage",
        ]
    )
    context = browser.new_context(
        user_agent=random.choice(ROTATING_USER_AGENTS),
        ignore_https_errors=True,
        viewport={"width": 1280, "height": 800},
        locale="en-GB",
        extra_http_headers={
            "Accept-Language": "en-GB,en;q=0.9",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
    )
    # Mask automation signals
    context.add_init_script("""
        Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
        window.__pwConsoleErrors = [];
        const origError = console.error.bind(console);
        console.error = (...args) => { window.__pwConsoleErrors.push(args.join(' ')); origError(...args); };
    """)
    return p, browser, context


def check_playwright(url, active=False, stealth=False):
    """Full headless browser scan: renders the page, discovers React forms,
    checks storage/globals for secrets, and optionally tests injection."""
    results = []

    if not HAS_PLAYWRIGHT:
        results.append(finding("INFO", "Playwright Not Installed",
            "Headless browser scanning requires Playwright.",
            "Run: pip install playwright && playwright install chromium"))
        return results

    print("      Launching headless Chromium...")
    pw = browser = context = page = None
    try:
        pw, browser, context = _pw_launch(stealth=stealth)
        page = context.new_page()

        # Navigate — try networkidle first (waits for React to finish), fall back to domcontentloaded
        try:
            page.goto(url, wait_until="networkidle", timeout=30000)
        except PlaywrightTimeout:
            try:
                page.goto(url, wait_until="domcontentloaded", timeout=15000)
                page.wait_for_timeout(3000)  # give JS a moment to run
            except Exception:
                results.append(finding("INFO", "Playwright: Page Load Timed Out",
                    f"Could not fully load {url} in 30s.", "Check if the URL is accessible."))
                return results

        if stealth:
            page.wait_for_timeout(int(random.uniform(800, 2000)))

        # ── Extract full page state ──
        try:
            state = page.evaluate(_JS_EXTRACT_PAGE)
        except Exception as e:
            results.append(finding("INFO", "Playwright: Page Extraction Failed", str(e)))
            return results

        forms = state.get("forms", [])
        standalone = state.get("standalone", [])
        sensitive_globals = state.get("sensitiveGlobals", [])
        local_storage = state.get("localStorageItems", {})
        session_storage = state.get("sessionStorageItems", {})
        html_comments = state.get("comments", [])

        # ── Report: forms discovered ──
        total_inputs = sum(len(f["inputs"]) for f in forms) + len(standalone)
        if forms or standalone:
            form_summary = []
            for i, f in enumerate(forms):
                names = ", ".join(inp["name"] for inp in f["inputs"][:5])
                form_summary.append(f"Form {i+1} [{f['method']}→{f['action'] or 'same page'}]: {names}")
            if standalone:
                names = ", ".join(inp["name"] for inp in standalone[:5])
                form_summary.append(f"Standalone inputs (React): {names}")

            results.append(finding("INFO",
                f"Playwright: {len(forms)} Form(s), {len(standalone)} Standalone Input(s) Found",
                f"{total_inputs} total input field(s) discovered after JavaScript render.",
                "Use --active to test these inputs for SQL injection, XSS, and template injection.",
                "\n".join(form_summary)))
        else:
            results.append(finding("INFO", "Playwright: No Forms Found After Render",
                "No input fields detected even after JavaScript execution. "
                "The page may require user interaction to reveal forms."))

        # ── Report: sensitive window globals ──
        if sensitive_globals:
            for item in sensitive_globals[:5]:
                results.append(finding("HIGH",
                    f"Sensitive Global Variable Exposed: window.{item['key']}",
                    "A window-level JavaScript variable has a name suggesting it contains credentials or tokens.",
                    "Move secrets to server-side environment variables. Never store tokens in global scope.",
                    item["value"]))
        else:
            results.append(finding("PASS", "No Sensitive Globals in window.*",
                "No credential-like names found in the page's global JavaScript scope."))

        # ── Report: localStorage ──
        sensitive_storage = {k: v for k, v in local_storage.items()
                             if any(p in k.lower() for p in
                                    ["token","key","secret","password","auth","jwt","user","session"])}
        if sensitive_storage:
            for k, v in list(sensitive_storage.items())[:5]:
                val_preview = (v or "")[:80]
                results.append(finding("MEDIUM",
                    f"Sensitive Data in localStorage: '{k}'",
                    "Tokens or credentials stored in localStorage are accessible to any JavaScript on the page, "
                    "including injected scripts (XSS).",
                    "Store auth tokens in HttpOnly cookies instead of localStorage where possible.",
                    val_preview))
        elif local_storage:
            results.append(finding("INFO", f"localStorage Contains {len(local_storage)} Key(s)",
                "No obviously sensitive keys detected.",
                evidence=", ".join(list(local_storage.keys())[:8])))
        else:
            results.append(finding("PASS", "localStorage is Empty",
                "No data found in localStorage."))

        # ── Report: sessionStorage ──
        sens_session = {k: v for k, v in session_storage.items()
                        if any(p in k.lower() for p in ["token","secret","password","auth","jwt"])}
        if sens_session:
            for k, v in list(sens_session.items())[:3]:
                results.append(finding("MEDIUM",
                    f"Sensitive Data in sessionStorage: '{k}'",
                    "Sensitive data in sessionStorage is accessible to JavaScript.",
                    "Prefer HttpOnly cookies for session tokens.",
                    (v or "")[:80]))

        # ── Report: HTML comments ──
        secret_comments = [c for c in html_comments
                           if any(p in c.lower() for p in
                                  ["password","secret","key","token","todo","fixme","hack","debug","api"])]
        if secret_comments:
            for c in secret_comments[:3]:
                results.append(finding("LOW", "Suspicious HTML Comment Found",
                    "HTML comments are visible to anyone who views page source.",
                    "Remove comments containing sensitive information or internal notes from production HTML.",
                    c[:150]))

        # ── Console errors ──
        try:
            console_errors = page.evaluate(_JS_CONSOLE_ERRORS)
            stack_traces = [e for e in console_errors
                            if any(p in e.lower() for p in ["error","exception","failed","undefined","null"])]
            if stack_traces:
                results.append(finding("LOW", f"JavaScript Console Errors Detected ({len(stack_traces)})",
                    "Console errors can leak stack traces, internal paths, or framework version info.",
                    "Fix JavaScript errors before deploying to production.",
                    stack_traces[0][:200]))
        except Exception:
            pass

        # ── Active injection via Playwright ──
        if active and (forms or standalone):
            print("      Testing discovered inputs for injection...")
            injection_results = _pw_test_injection(page, context, url, forms, standalone, stealth)
            results.extend(injection_results)

    except Exception as e:
        results.append(finding("INFO", "Playwright Scan Error", str(e)))
    finally:
        try:
            if page: page.close()
            if context: context.close()
            if browser: browser.close()
            if pw: pw.stop()
        except Exception:
            pass

    return results


def _pw_test_injection(page, context, base_url, forms, standalone, stealth=False):
    """Test each discovered input for SQL injection, XSS, and template injection."""
    results = []
    sqli_found = []
    xss_found = []
    tpl_found = []

    # Build a flat list of (field_name, field_id, form_index_or_None)
    targets = []
    for i, form in enumerate(forms):
        for inp in form["inputs"]:
            targets.append((inp["name"], inp["id"], i))
    for inp in standalone:
        targets.append((inp["name"], inp["id"], None))

    tested = set()
    for field_name, field_id, form_idx in targets[:8]:  # cap at 8 fields
        key = field_name or field_id
        if key in tested:
            continue
        tested.add(key)

        selector = f'[name="{field_name}"]' if field_name else f'#{field_id}'

        # ── SQL Injection (error-based via network interception) ──
        for payload in SQL_PAYLOADS[:5]:
            try:
                new_page = context.new_page()
                sql_errors_found = []

                def on_response(resp):
                    try:
                        if resp.status == 200 and "json" in resp.headers.get("content-type",""):
                            body = resp.text()
                            for pat in SQL_ERROR_PATTERNS:
                                if re.search(pat, body, re.I):
                                    sql_errors_found.append(pat)
                    except Exception:
                        pass

                new_page.on("response", on_response)
                new_page.goto(base_url, wait_until="domcontentloaded", timeout=20000)
                new_page.wait_for_timeout(2000)

                el = new_page.query_selector(selector)
                if el:
                    el.fill(payload)
                    el.press("Enter")
                    new_page.wait_for_timeout(2000)

                    # Also check rendered page text for SQL errors
                    page_text = new_page.content().lower()
                    for pat in SQL_ERROR_PATTERNS:
                        if re.search(pat, page_text, re.I):
                            sql_errors_found.append(pat)

                if sql_errors_found:
                    sqli_found.append((key, payload, sql_errors_found[0]))

                new_page.close()
                if stealth:
                    time.sleep(random.uniform(0.8, 1.5))
                if sqli_found:
                    break
            except Exception:
                try: new_page.close()
                except Exception: pass

        # ── Reflected XSS ──
        xss_tag, xss_marker = _xss_token()
        try:
            new_page = context.new_page()
            new_page.goto(base_url, wait_until="domcontentloaded", timeout=20000)
            new_page.wait_for_timeout(2000)
            el = new_page.query_selector(selector)
            if el:
                el.fill(xss_tag)
                el.press("Enter")
                new_page.wait_for_timeout(1500)
                if xss_marker in new_page.content() and xss_tag in new_page.content():
                    xss_found.append((key, xss_tag))
            new_page.close()
        except Exception:
            try: new_page.close()
            except Exception: pass

        # ── Template Injection ──
        for tpl_payload in TEMPLATE_PAYLOADS:
            try:
                new_page = context.new_page()
                new_page.goto(base_url, wait_until="domcontentloaded", timeout=20000)
                new_page.wait_for_timeout(2000)
                el = new_page.query_selector(selector)
                if el:
                    el.fill(tpl_payload)
                    el.press("Enter")
                    new_page.wait_for_timeout(1500)
                    if "49" in new_page.content():
                        # Baseline check
                        baseline = new_page.goto(base_url, wait_until="domcontentloaded", timeout=10000)
                        if "49" not in new_page.content():
                            tpl_found.append((key, tpl_payload))
                new_page.close()
                if tpl_found:
                    break
            except Exception:
                try: new_page.close()
                except Exception: pass

    # ── Compile ──
    if sqli_found:
        for field, payload, pat in sqli_found:
            results.append(finding("CRITICAL",
                f"Playwright: SQL Injection — Field '{field}'",
                f"Payload '{payload}' triggered SQL error pattern in rendered response.",
                "Use parameterised queries / prepared statements.",
                f"field={field}, pattern={pat}"))
    else:
        results.append(finding("PASS", "Playwright: No SQL Injection Detected",
            f"Tested {len(tested)} rendered input(s) — no SQL error signatures triggered."))

    if xss_found:
        for field, payload in xss_found:
            results.append(finding("HIGH",
                f"Playwright: Reflected XSS — Field '{field}'",
                "Injected tag appeared unescaped in the rendered DOM.",
                "HTML-encode all user output. Implement a Content-Security-Policy.",
                f"field={field}"))
    else:
        results.append(finding("PASS", "Playwright: No Reflected XSS Detected",
            f"Tested {len(tested)} rendered input(s) — no unescaped reflection found."))

    if tpl_found:
        for field, payload in tpl_found:
            results.append(finding("CRITICAL",
                f"Playwright: Template Injection — Field '{field}'",
                f"Payload '{payload}' was evaluated server-side.",
                "Never pass user input directly into template engines.",
                f"field={field}, payload={payload}"))
    else:
        results.append(finding("PASS", "Playwright: No Template Injection Detected",
            f"Tested {len(tested)} rendered input(s) — no expression evaluation detected."))

    return results


# ─────────────────────────────────────────────
# SCAN ORCHESTRATOR
# ─────────────────────────────────────────────

def scan_url(url, active=False, stealth=False, use_playwright=False):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    print(f"  → Scanning: {url}")
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    session = get_session()
    results_by_category = {}

    passive_total = 12 + (1 if use_playwright else 0)
    total = passive_total + (4 if active else 0)

    # 1. SSL/TLS
    print(f"    [ 1/{total}] SSL/TLS checks...")
    results_by_category["SSL/TLS"] = check_ssl_tls(hostname, port if parsed.scheme == "https" else 443)

    # 2. HTTPS redirect
    print(f"    [ 2/{total}] HTTPS redirect...")
    results_by_category["HTTPS Redirect"] = check_https_redirect(session, url)

    # 3. Security headers + fingerprinting + version disclosure (share the same request)
    print(f"    [ 3/{total}] Security headers, fingerprinting & version disclosure...")
    r = safe_get(session, url, stealth=stealth)
    if r:
        results_by_category["Security Headers"] = check_security_headers(r)
        fp_results, detected_tech = check_fingerprint(r, r.headers)
        results_by_category["Technology Fingerprint"] = fp_results
        results_by_category["Version Disclosure"] = check_version_disclosure(r)
    else:
        results_by_category["Security Headers"] = [finding("INFO", "Could Not Connect",
            "Unable to retrieve the page for header analysis.")]
        detected_tech = set()

    # 4. HTTP method enumeration
    print(f"    [ 4/{total}] HTTP method enumeration...")
    results_by_category["HTTP Methods"] = check_http_methods(session, url, stealth=stealth)

    # 5. DNS reconnaissance (bypasses WAF — pure DNS)
    print(f"    [ 5/{total}] DNS reconnaissance...")
    results_by_category["DNS Recon"] = check_dns_recon(hostname)

    # 6. JavaScript secret scanning
    print(f"    [ 6/{total}] JavaScript secret scanning...")
    results_by_category["JavaScript Secrets"] = check_js_secrets(session, url, stealth=stealth)

    # 7. Database key probing (Supabase anon key, Firebase)
    print(f"    [ 7/{total}] Database key probing...")
    results_by_category["Database Keys"] = check_db_keys(session, url, stealth=stealth, detected_tech=detected_tech)

    # SPA catch-all detection (avoids false positives on path probes)
    spa_baseline = detect_spa_baseline(session, url)
    if spa_baseline[0] is not None:
        print(f"    [info] SPA catch-all detected — will validate path probe results")

    # 8. Sensitive files
    print(f"    [ 8/{total}] Sensitive file exposure...")
    results_by_category["Sensitive Files"] = check_sensitive_files(session, url, spa_baseline=spa_baseline)

    # 9. Admin panels
    print(f"    [ 9/{total}] Admin panel discovery...")
    results_by_category["Admin Panels"] = check_admin_panels(session, url, spa_baseline=spa_baseline)

    # 10. API security
    print(f"    [10/{total}] API endpoint checks...")
    results_by_category["API Security"] = check_api_endpoints(session, url, spa_baseline=spa_baseline)

    # 11. Authentication
    print(f"    [11/{total}] Authentication checks...")
    results_by_category["Authentication"] = check_authentication(session, url)

    # 12. Mixed content
    print(f"    [12/{total}] Mixed content...")
    mc = check_mixed_content(session, url)
    if mc:
        results_by_category["Mixed Content"] = mc

    # ── Active checks (opt-in) ──
    if active:
        print(f"    [13/{total}] Injection checks (SQL error-based, XSS, template)...")
        results_by_category["Injection Testing"] = check_injection(session, url)

        print(f"    [14/{total}] Blind time-based SQL injection...")
        results_by_category["Blind SQL Injection"] = check_blind_sqli(session, url, stealth=stealth)

        print(f"    [15/{total}] Open redirect testing...")
        results_by_category["Open Redirect"] = check_open_redirect(session, url, stealth=stealth)

        print(f"    [16/{total}] Brute force / account lockout testing...")
        results_by_category["Brute Force Protection"] = check_brute_force(session, url, stealth=stealth)

    # ── Playwright headless browser scan (opt-in) ──
    if use_playwright:
        step = total - (0 if not active else 0)
        print(f"    [{step}/{total}] Playwright headless browser scan...")
        results_by_category["Playwright (Headless Browser)"] = check_playwright(
            url, active=active, stealth=stealth)

    return {"url": url, "categories": results_by_category, "scanned_at": datetime.datetime.utcnow().isoformat()}


# ─────────────────────────────────────────────
# SCORING
# ─────────────────────────────────────────────

def compute_score(categories):
    penalty = 0
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for findings in categories.values():
        for f in findings:
            sev = f["severity"]
            if sev == "CRITICAL":
                penalty += 25
                counts["CRITICAL"] += 1
            elif sev == "HIGH":
                penalty += 15
                counts["HIGH"] += 1
            elif sev == "MEDIUM":
                penalty += 7
                counts["MEDIUM"] += 1
            elif sev == "LOW":
                penalty += 3
                counts["LOW"] += 1
    score = max(0, 100 - penalty)
    if score >= 80:
        grade = "A"
    elif score >= 65:
        grade = "B"
    elif score >= 50:
        grade = "C"
    elif score >= 35:
        grade = "D"
    else:
        grade = "F"
    return score, grade, counts


# ─────────────────────────────────────────────
# HTML REPORT GENERATION
# ─────────────────────────────────────────────

SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#d97706",
    "LOW": "#2563eb",
    "INFO": "#6b7280",
    "PASS": "#16a34a",
}

SEVERITY_BADGE_COLORS = {
    "CRITICAL": "background:#fee2e2;color:#991b1b;border:1px solid #fca5a5",
    "HIGH": "background:#ffedd5;color:#9a3412;border:1px solid #fdba74",
    "MEDIUM": "background:#fef3c7;color:#92400e;border:1px solid #fcd34d",
    "LOW": "background:#dbeafe;color:#1e40af;border:1px solid #93c5fd",
    "INFO": "background:#f3f4f6;color:#374151;border:1px solid #d1d5db",
    "PASS": "background:#dcfce7;color:#166534;border:1px solid #86efac",
}


def generate_html_report(scan_results, output_path):
    report_time = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    sites_data = []

    for result in scan_results:
        score, grade, counts = compute_score(result["categories"])
        sites_data.append({**result, "score": score, "grade": grade, "counts": counts})

    # Build findings JSON for JS
    findings_json = json.dumps(sites_data, indent=2)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Web Security Audit Report</title>
<style>
  :root {{
    --bg: #0f172a; --surface: #1e293b; --surface2: #334155;
    --border: #475569; --text: #e2e8f0; --text2: #94a3b8;
    --accent: #38bdf8; --radius: 8px;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: var(--bg); color: var(--text); min-height: 100vh; }}
  header {{ background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 100%);
    border-bottom: 1px solid var(--border); padding: 24px 32px; display: flex;
    align-items: center; justify-content: space-between; }}
  header h1 {{ font-size: 1.5rem; font-weight: 700; color: var(--accent); }}
  header .meta {{ font-size: 0.8rem; color: var(--text2); }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 24px 16px; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 16px; margin-bottom: 32px; }}
  .summary-card {{ background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius); padding: 20px; text-align: center; }}
  .summary-card .score {{ font-size: 3rem; font-weight: 800; }}
  .summary-card .label {{ font-size: 0.8rem; color: var(--text2); margin-top: 4px; }}
  .summary-card .url {{ font-size: 0.75rem; color: var(--accent); margin-top: 6px;
    word-break: break-all; }}
  .grade-A {{ color: #22c55e; }} .grade-B {{ color: #84cc16; }}
  .grade-C {{ color: #eab308; }} .grade-D {{ color: #f97316; }} .grade-F {{ color: #ef4444; }}
  .site-section {{ background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius); margin-bottom: 24px; overflow: hidden; }}
  .site-header {{ padding: 16px 20px; background: var(--surface2); display: flex;
    align-items: center; justify-content: space-between; cursor: pointer;
    user-select: none; }}
  .site-header:hover {{ background: #3d5068; }}
  .site-header h2 {{ font-size: 1rem; font-weight: 600; }}
  .site-header .badges {{ display: flex; gap: 8px; flex-wrap: wrap; }}
  .badge {{ padding: 2px 10px; border-radius: 999px; font-size: 0.7rem; font-weight: 700; }}
  .site-body {{ padding: 16px 20px; display: none; }}
  .site-body.open {{ display: block; }}
  .category-title {{ font-size: 0.85rem; font-weight: 700; color: var(--accent);
    text-transform: uppercase; letter-spacing: 0.05em; margin: 16px 0 8px; }}
  .finding {{ background: var(--bg); border: 1px solid var(--border);
    border-radius: 6px; padding: 12px 16px; margin-bottom: 8px;
    border-left: 4px solid #475569; }}
  .finding-header {{ display: flex; align-items: flex-start; gap: 10px; }}
  .sev-badge {{ padding: 1px 8px; border-radius: 4px; font-size: 0.65rem;
    font-weight: 800; white-space: nowrap; margin-top: 2px; }}
  .finding-title {{ font-size: 0.9rem; font-weight: 600; }}
  .finding-detail {{ font-size: 0.8rem; color: var(--text2); margin-top: 6px; }}
  .finding-rec {{ font-size: 0.78rem; margin-top: 6px;
    background: #1a2c1a; border: 1px solid #2d5a2d; border-radius: 4px;
    padding: 6px 10px; color: #86efac; }}
  .finding-rec::before {{ content: "✓ Fix: "; font-weight: 700; }}
  .finding-evidence {{ font-size: 0.72rem; color: #64748b; margin-top: 4px;
    font-family: monospace; word-break: break-all; }}
  .filters {{ display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 20px;
    align-items: center; }}
  .filter-btn {{ padding: 5px 14px; border-radius: 6px; border: 1px solid var(--border);
    background: var(--surface); color: var(--text); cursor: pointer; font-size: 0.8rem;
    transition: all 0.15s; }}
  .filter-btn:hover, .filter-btn.active {{ background: var(--accent); color: #0f172a;
    border-color: var(--accent); font-weight: 700; }}
  .stats-row {{ display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 24px; }}
  .stat {{ display: flex; align-items: center; gap: 6px; font-size: 0.8rem; }}
  .stat-dot {{ width: 10px; height: 10px; border-radius: 50%; }}
  footer {{ text-align: center; padding: 24px; color: var(--text2); font-size: 0.75rem;
    border-top: 1px solid var(--border); margin-top: 32px; }}
  .expand-icon {{ font-size: 1.2rem; color: var(--text2); transition: transform 0.2s; }}
  .expand-icon.rotated {{ transform: rotate(180deg); }}
  @media print {{
    body {{ background: white; color: black; }}
    .site-body {{ display: block !important; }}
  }}
</style>
</head>
<body>
<header>
  <div>
    <h1>🛡 Web Security Audit Report</h1>
    <div class="meta">Generated: {report_time} &nbsp;|&nbsp; {len(scan_results)} site(s) scanned</div>
  </div>
  <div class="meta" style="text-align:right">
    Security Agent v{__version__}
  </div>
</header>

<div class="container">
  <div class="summary-grid" id="summaryGrid"></div>
  <div class="filters" id="filters">
    <span style="font-size:0.8rem;color:var(--text2)">Filter:</span>
    <button class="filter-btn active" onclick="filterFindings('ALL')">All</button>
    <button class="filter-btn" onclick="filterFindings('CRITICAL')" style="border-color:#dc2626">Critical</button>
    <button class="filter-btn" onclick="filterFindings('HIGH')" style="border-color:#ea580c">High</button>
    <button class="filter-btn" onclick="filterFindings('MEDIUM')" style="border-color:#d97706">Medium</button>
    <button class="filter-btn" onclick="filterFindings('LOW')" style="border-color:#2563eb">Low</button>
    <button class="filter-btn" onclick="filterFindings('PASS')" style="border-color:#16a34a">Passed</button>
  </div>
  <div id="siteSections"></div>
</div>

<footer>Web Security Agent &mdash; Passive/non-invasive scan only. Always obtain proper authorization before scanning.</footer>

<script>
const DATA = {findings_json};

const SEV_COLORS = {json.dumps(SEVERITY_COLORS)};
const SEV_BADGE = {json.dumps(SEVERITY_BADGE_COLORS)};
const SEV_ORDER = {json.dumps(SEVERITY_ORDER)};

let currentFilter = 'ALL';

function renderSummary() {{
  const grid = document.getElementById('summaryGrid');
  DATA.forEach(site => {{
    const gradeClass = 'grade-' + site.grade;
    const card = document.createElement('div');
    card.className = 'summary-card';
    card.innerHTML = `
      <div class="score ${{gradeClass}}">${{site.grade}}</div>
      <div class="score" style="font-size:1.4rem;color:var(--text)">${{site.score}}/100</div>
      <div class="label">Security Score</div>
      <div class="url">${{site.url}}</div>
      <div style="display:flex;gap:6px;justify-content:center;margin-top:10px;flex-wrap:wrap">
        ${{site.counts.CRITICAL ? `<span class="badge" style="background:#fee2e2;color:#991b1b">${{site.counts.CRITICAL}} Critical</span>` : ''}}
        ${{site.counts.HIGH ? `<span class="badge" style="background:#ffedd5;color:#9a3412">${{site.counts.HIGH}} High</span>` : ''}}
        ${{site.counts.MEDIUM ? `<span class="badge" style="background:#fef3c7;color:#92400e">${{site.counts.MEDIUM}} Medium</span>` : ''}}
        ${{site.counts.LOW ? `<span class="badge" style="background:#dbeafe;color:#1e40af">${{site.counts.LOW}} Low</span>` : ''}}
      </div>`;
    grid.appendChild(card);
  }});
}}

function renderSite(site, idx) {{
  const container = document.getElementById('siteSections');
  const sec = document.createElement('div');
  sec.className = 'site-section';
  sec.id = 'site-' + idx;

  const gradeClass = 'grade-' + site.grade;
  const header = document.createElement('div');
  header.className = 'site-header';
  header.innerHTML = `
    <div>
      <h2>${{site.url}}</h2>
      <div style="font-size:0.75rem;color:var(--text2);margin-top:2px">Scanned: ${{site.scanned_at}} UTC</div>
    </div>
    <div style="display:flex;align-items:center;gap:12px">
      <span style="font-size:1.5rem;font-weight:800" class="${{gradeClass}}">${{site.grade}} (${{site.score}})</span>
      <span class="expand-icon" id="icon-${{idx}}">▼</span>
    </div>`;

  const body = document.createElement('div');
  body.className = 'site-body open';
  body.id = 'body-' + idx;

  Object.entries(site.categories).forEach(([cat, findings]) => {{
    const catDiv = document.createElement('div');
    catDiv.innerHTML = `<div class="category-title">${{cat}}</div>`;
    const sorted = [...findings].sort((a,b) => (SEV_ORDER[a.severity]||99) - (SEV_ORDER[b.severity]||99));
    sorted.forEach(f => {{
      const fd = document.createElement('div');
      fd.className = 'finding';
      fd.dataset.severity = f.severity;
      fd.style.borderLeftColor = SEV_COLORS[f.severity] || '#475569';
      fd.innerHTML = `
        <div class="finding-header">
          <span class="sev-badge" style="${{SEV_BADGE[f.severity] || ''}}">${{f.severity}}</span>
          <span class="finding-title">${{f.title}}</span>
        </div>
        ${{f.detail ? `<div class="finding-detail">${{f.detail}}</div>` : ''}}
        ${{f.recommendation ? `<div class="finding-rec">${{f.recommendation}}</div>` : ''}}
        ${{f.evidence ? `<div class="finding-evidence">Evidence: ${{f.evidence}}</div>` : ''}}`;
      catDiv.appendChild(fd);
    }});
    body.appendChild(catDiv);
  }});

  header.addEventListener('click', () => {{
    const b = document.getElementById('body-' + idx);
    const icon = document.getElementById('icon-' + idx);
    b.classList.toggle('open');
    icon.classList.toggle('rotated');
  }});

  sec.appendChild(header);
  sec.appendChild(body);
  container.appendChild(sec);
}}

function filterFindings(sev) {{
  currentFilter = sev;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');

  document.querySelectorAll('.finding').forEach(f => {{
    if (sev === 'ALL' || f.dataset.severity === sev) {{
      f.style.display = '';
    }} else {{
      f.style.display = 'none';
    }}
  }});
}}

renderSummary();
DATA.forEach((site, idx) => renderSite(site, idx));
</script>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    print(f"\n  ✅ Report saved: {output_path}")


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Web Security Agent — passive and optional active scanning",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python3 security_agent.py https://mysite.com
  python3 security_agent.py https://site1.com https://site2.com
  python3 security_agent.py --active https://mysite.com
  python3 security_agent.py --active https://site1.com https://site2.com
        """
    )
    parser.add_argument("urls", nargs="+", help="One or more URLs to scan")
    parser.add_argument(
        "--active", action="store_true",
        help="Enable active injection testing (SQL error-based, blind SQLi, XSS, template, open redirect). "
             "Only use on sites you own or have explicit permission to test."
    )
    parser.add_argument(
        "--stealth", action="store_true",
        help="Add randomised delays (1.5-4s) between requests to reduce WAF and rate-limit triggers. "
             "Makes scans slower but less detectable."
    )
    parser.add_argument(
        "--playwright", action="store_true",
        help="Launch a headless Chromium browser to scan JavaScript-rendered pages (React, Vue, etc.). "
             "Discovers forms invisible to plain HTTP requests, checks localStorage/sessionStorage, "
             "window globals, and HTML comments for secrets. Combine with --active to test found inputs."
    )
    parser.add_argument(
        "--skip", metavar="FINDING", action="append", default=[],
        help="Suppress a finding by a keyword match against its title (case-insensitive). "
             "Can be repeated: --skip csrf --skip 2fa --skip 'rate limit'"
    )
    args = parser.parse_args()

    urls = args.urls
    active = args.active
    stealth = args.stealth
    use_playwright = args.playwright
    skip_keywords = [k.lower() for k in args.skip]

    print(f"\n🛡  Web Security Agent")
    if active:
        print(f"   ⚡ Active injection testing ENABLED")
    if stealth:
        print(f"   🕵  Stealth mode ENABLED (slower, quieter)")
    if use_playwright:
        print(f"   🌐 Playwright headless browser ENABLED")
    if skip_keywords:
        print(f"   ⏭  Skipping findings matching: {', '.join(skip_keywords)}")
    print(f"   Scanning {len(urls)} site(s)...\n")

    scan_results = []
    for url in urls:
        try:
            result = scan_url(url, active=active, stealth=stealth, use_playwright=use_playwright)
            if skip_keywords:
                for cat in result["categories"]:
                    result["categories"][cat] = [
                        f for f in result["categories"][cat]
                        if not any(kw in f["title"].lower() for kw in skip_keywords)
                    ]
            score, grade, counts = compute_score(result["categories"])
            scan_results.append(result)
            print(f"     Score: {score}/100  Grade: {grade}  "
                  f"Critical:{counts['CRITICAL']} High:{counts['HIGH']} "
                  f"Medium:{counts['MEDIUM']} Low:{counts['LOW']}\n")
        except Exception as e:
            print(f"  ✗ Error scanning {url}: {e}\n")

    if not scan_results:
        print("No results to report.")
        sys.exit(1)

    date_str = datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S")
    # Build a slug from the scanned hostnames
    def host_slug(url):
        host = urllib.parse.urlparse(url).hostname or url
        return re.sub(r"[^\w.-]", "_", host)

    site_part = "_".join(host_slug(r["url"]) for r in scan_results)
    output_dir = Path(__file__).parent
    output_path = output_dir / f"security_report_{site_part}_{date_str}.html"

    print("  Generating HTML report...")
    generate_html_report(scan_results, output_path)
    print(f"\n  Open: {output_path}")
    return str(output_path)


if __name__ == "__main__":
    main()
