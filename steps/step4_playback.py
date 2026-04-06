"""
step4_playback.py

POST /api/videos/{code}/embed/playback — get encrypted payload.

If this fails:
  - 401 = invalid/expired token (step 3 failed)
  - 403 = embedding blocked or CF block
  - 404 = wrong video code
  - No key_parts = API response format changed

Required: X-Embed-Parent header must be set.
"""

import time
from helpers import (
    BASE_URL, http_post, get_session
)


def run(sid, code):
    """
    Step 4: POST playback → get encrypted data.
    Returns dict with encrypted payload info, timing.
    """
    sess = get_session(sid)
    t0 = time.time()
    url = BASE_URL + "/api/videos/%s/embed/playback" % code

    # Validate prerequisites
    if not sess.get("token"):
        return {
            "step": "4-playback",
            "error": "No token. Run step 3 first.",
            "fix": "Click step 3 button first",
        }
    if not code:
        return {
            "step": "4-playback",
            "error": "No code provided.",
            "fix": "Enter embed code in the input box",
        }

    sess["code"] = code

    # Build playback request
    playback_body = {"token": sess["token"]}
    extra_headers = {"X-Embed-Parent": BASE_URL}

    status, body, headers = http_post(
        url, body=playback_body, extra_headers=extra_headers
    )
    ms = int((time.time() - t0) * 1000)

    result = {
        "step": "4-playback",
        "url": url,
        "httpStatus": status,
        "timeMs": ms,
        "code": code,
        "responseBody": body,
    }

    # Store for step 5
    sess["playback_body"] = body

    # Analyze response structure
    if isinstance(body, dict):
        result["responseKeys"] = list(body.keys())
        enc = body.get("playback", body)
        result["encryptedKeys"] = list(enc.keys()) if isinstance(enc, dict) else "N/A"
        result["hasKeyParts"] = bool(enc.get("key_parts")) if isinstance(enc, dict) else False
        result["hasIv"] = bool(enc.get("iv")) if isinstance(enc, dict) else False
        result["hasPayload"] = bool(enc.get("payload")) if isinstance(enc, dict) else False
        result["canDecrypt"] = result["hasKeyParts"] and result["hasIv"] and result["hasPayload"]
    else:
        result["isJson"] = False
        result["bodyType"] = type(body).__name__

    return result
