# Feedback: SPA Catch-All False Positive Detection

## Problem

The scanner correctly suppresses most SPA false positives, but still flags some paths
(e.g. `/.backup`) as MEDIUM findings when the app uses a catch-all rewrite rule
(Vercel `rewrites`, Netlify `_redirects`, Nginx `try_files`, etc.).

**Example from practice-profiles.vercel.app scan (2026-03-26_224447):**
- `/.backup` flagged as MEDIUM "Sensitive file or directory exposed"
- Actual response: HTTP 200, 577 bytes, `Content-Type: text/html`, body = `index.html` (SPA shell)
- The scanner suppressed 29 other paths as SPA false positives but missed this one

## Recommended Fix: Canary Probe + Fingerprint Matching

### Step 1 — Probe a canary path before scanning

Before checking any sensitive paths, request a random UUID path that cannot possibly exist:

```
GET /a7f3c9d2-4b1e-4f8a-9c3d-000000000000
```

Record the "catch-all fingerprint":
- `body_hash` — SHA1 or MD5 of the response body
- `content_length` — byte size
- `content_type` — e.g. `text/html; charset=utf-8`

If this returns 404, the app has no catch-all — scan normally.
If it returns 200, record the fingerprint and use it as the suppression baseline.

### Step 2 — Suppress fingerprint matches

For every sensitive-file probe, compare against the canary fingerprint:

```python
if response.body_hash == canary.body_hash:
    suppress("SPA catch-all — identical to canary response")
elif response.content_length == canary.content_length and response.content_type == canary.content_type:
    suppress("Probable SPA catch-all — size and type match canary")
```

### Step 3 — Content-Type sanity check (secondary signal)

Even without a canary match, flag as probable false positive if:
- The path has a binary/config extension (`.backup`, `.sql`, `.tar.gz`, `.zip`, `.bak`, `.env`)
- But the response `Content-Type` is `text/html`

A real backup file would never return `text/html`.

### Step 4 — Body content check (tertiary signal)

If response body contains SPA markers, suppress regardless of status:
- `<div id="root">`
- `<script type="module"`
- `<!DOCTYPE html>` + `<title>` + no server-rendered content

## Why This Approach

- **Framework-agnostic**: Works for Vercel, Netlify, Nginx, Apache, Express — any catch-all pattern
- **No hardcoded paths**: Doesn't rely on knowing what the SPA index.html looks like
- **Cheap**: One extra HTTP request (the canary probe) per scan target
- **Eliminates the whole class of false positives**: Not just the ones the scanner already knows about

## Priority

High. False positives on MEDIUM findings erode trust in the scanner's output. A developer
seeing `/.backup` flagged as exposed will investigate, find it's the SPA shell, and start
ignoring scanner output — including real findings.
