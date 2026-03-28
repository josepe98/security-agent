# Security Agent

A Python-based web security scanner that performs passive and optional active checks against web applications, then generates a self-contained interactive HTML report. Built for developers and security practitioners who need a quick, actionable picture of a site's security posture without standing up a full enterprise scanning platform.

**Current version: 1.7.0**

---

## What it checks

### Passive (run on every scan)

| Category | What it looks for |
|---|---|
| SSL/TLS | Certificate validity, expiry, weak protocols (TLS 1.0/1.1), weak ciphers |
| Security Headers | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| HTTPS Redirect | HTTP → HTTPS enforcement, HSTS preload |
| CSRF Protection | Token presence in forms, SameSite cookie attributes |
| Rate Limiting | Rate-limit headers on auth endpoints; probes backend API hosts extracted from CSP |
| JavaScript Secrets | API keys, tokens, and credentials in JS bundles and inline scripts |
| JS Template / SSTI | Template engine fingerprinting (EJS, Pug, Nunjucks, Handlebars, Mustache); flags unsafe `.render()` / `.compile()` calls with non-literal arguments |
| Database Keys | Supabase anon keys, Firebase config, Hasura, Xata, Turso credentials in JS |
| Sensitive Files | `.env`, `config.json`, backup files, `.git/config`, `robots.txt` exposure |
| Admin Panels | Common admin paths (`/admin`, `/wp-admin`, `/dashboard`, etc.) |
| API Endpoints | Unauthenticated API routes, verbose error responses |
| Authentication | Login form analysis, cookie flags (Secure, HttpOnly, SameSite), 2FA signals |
| Mixed Content | HTTP resources loaded on HTTPS pages |
| Tech Fingerprinting | Framework and CMS detection (Next.js, WordPress, Drupal, etc.) |
| Version Disclosure | Server/framework version leakage in headers and HTML |
| DNS Recon | Subdomain enumeration, SPF/DMARC/DKIM records, zone transfer attempts |
| HTTP Methods | Dangerous methods enabled (PUT, DELETE, TRACE, CONNECT) |

### Active (opt-in via `--active`)

Only use active scanning on sites you own or have explicit written permission to test.

| Category | What it tests |
|---|---|
| SQL Injection | Error-based detection across form inputs and URL parameters |
| Blind SQL Injection | Time-based detection (deliberate delays) |
| XSS | Reflected and stored XSS via form inputs and URL parameters |
| Template Injection (SSTI) | Engine-specific payloads for Jinja2, Nunjucks/Twig, EJS, Smarty, Thymeleaf, EL/Velocity |
| Open Redirect | Redirect parameter manipulation |
| Brute Force / Lockout | Account lockout enforcement on login endpoints |

### Playwright mode (opt-in via `--playwright`)

Launches a headless Chromium browser to handle JavaScript-rendered pages (React, Vue, Angular SPAs). Discovers forms and inputs that don't exist in the raw HTML response, and checks `localStorage`, `sessionStorage`, window globals, and HTML comments for exposed secrets. Combine with `--active` to test found inputs for injection.

---

## Installation

```bash
# Clone the repo
git clone https://github.com/josepe98/security-agent.git
cd security-agent

# Install dependencies
pip install requests urllib3 dnspython

# Playwright support (optional)
pip install playwright
playwright install chromium
```

---

## Usage

```bash
# Passive scan (safe, read-only)
python3 security_agent.py https://example.com

# Scan multiple targets
python3 security_agent.py https://site1.com https://site2.com

# Full active scan with browser rendering
python3 security_agent.py --active --playwright https://example.com

# Stealth mode — randomised delays to reduce WAF/rate-limit triggers
python3 security_agent.py --stealth https://example.com

# Suppress specific findings
python3 security_agent.py --skip csrf --skip '2fa' https://example.com
```

### Flags

| Flag | Description |
|---|---|
| `--active` | Enable injection testing (SQLi, XSS, SSTI, open redirect, brute force). Requires permission. |
| `--playwright` | Use headless Chromium for JS-rendered pages. Required for React/Vue/Angular SPAs. |
| `--stealth` | Add 1.5–4s randomised delays between requests. Slower but less detectable. |
| `--skip KEYWORD` | Suppress findings whose title contains KEYWORD (case-insensitive). Repeatable. |

---

## Output

The scanner writes a self-contained HTML report to the current directory:

```
security_report_example.com_2026-03-28_120000.html
```

The report is filterable by severity (CRITICAL, HIGH, MEDIUM, LOW, INFO, PASS) and includes remediation guidance for every finding. No external dependencies — open it in any browser.

---

## Severity levels

| Level | Meaning |
|---|---|
| CRITICAL | Direct exploitability confirmed (e.g. SSTI with evaluated payload, exposed secret) |
| HIGH | Strong indicator of a serious vulnerability |
| MEDIUM | Potential vulnerability or missing defence-in-depth control |
| LOW | Minor issue or informational finding worth addressing |
| INFO | Contextual data (tech fingerprint, detected engine, recon results) |
| PASS | Check completed with no issues found |

---

## DAST vs SAST

This tool is a **DAST** (Dynamic Application Security Testing) scanner — it tests the running application from the outside with real HTTP requests. It can confirm exploitability but cannot see server-side code that isn't reachable via the network.

For full coverage, pair it with a **SAST** tool like [Aikido](https://aikido.dev) that analyses your source code statically. The two approaches are complementary: DAST finds runtime and configuration issues; SAST finds dangerous coding patterns in paths that may not be reachable by a scanner.

---

## Authorization

Active scanning sends potentially disruptive payloads to a target. Only run `--active` against:

- Applications you own
- Applications you have explicit written permission to test
- Local or staging environments

Unauthorised active scanning may be illegal.
