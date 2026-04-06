"""
step1_homepage.py

GET https://f75s.com — grab CF cookies, detect CF challenge page.

If this fails = Cloudflare is blocking your VPS IP.
Fix: use residential IP or different VPS provider.
"""

import time
from helpers import BASE_URL, http_get, get_http_client


def run(sid):
    """
    Step 1: GET homepage.
    Returns dict with: status, body, cf detection, timing.
    """
    t0 = time.time()
    client_type = get_http_client()[1]
    status, body, headers = http_get(BASE_URL, timeout=15)
    ms = int((time.time() - t0) * 1000)

    result = {
        "step": "1-homepage",
        "url": BASE_URL,
        "httpStatus": status,
        "timeMs": ms,
        "clientType": client_type,
    }

    # Check response headers
    if headers:
        cf_ray = headers.get("cf-ray", "")
        cf_mitigated = headers.get("cf-mitigated", "")
        server = headers.get("server", "")
        result["headers"] = {
            "server": server,
            "cf-ray": cf_ray,
            "cf-mitigated": cf_mitigated,
            "set-cookie": headers.get("set-cookie", "")[:200],
        }

    # Detect Cloudflare challenge/block
    if isinstance(body, str):
        cf_challenge_keywords = [
            "challenge-platform",
            "cf-browser-verification",
            "Just a moment",
            "Checking your browser",
        ]
        if any(kw in body for kw in cf_challenge_keywords):
            result["cfChallenge"] = True
            result["cfType"] = "JS Challenge"
            result["bodyPreview"] = body[:800]
            return result

        if "cloudflare" in body.lower() and status in (403, 503):
            result["cfBlocked"] = True
            result["cfType"] = "Block (HTTP %d)" % status
            result["bodyPreview"] = body[:800]
            return result

        # Looks like normal page
        result["cfChallenge"] = False
        result["cfType"] = "None (passed)"
        result["bodyPreview"] = body[:400]
    else:
        result["bodyPreview"] = str(body)[:400]

    return result
