"""
step4_playback.py

POST /api/videos/{code}/embed/playback — get encrypted payload.

Real browser sends:
{
  "fingerprint": {
    "token": "eyJ...",
    "viewer_id": "...",
    "device_id": "...",
    "confidence": 0.93
  }
}

Required cookies: byse_viewer_id + byse_device_id
Required header: X-Embed-Parent
"""

import time
from helpers import (
    BASE_URL, http_post, set_cookies, get_session
)


def run(sid, code):
    """
    Step 4: POST playback -> get encrypted data.
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

    # Use server-returned IDs (from step 3 attest response), fall back to local
    viewer_id = sess.get("server_viewer_id") or sess["viewer_id"]
    device_id = sess.get("server_device_id") or sess["device_id"]
    confidence = sess.get("confidence", 0.6)

    # Set cookies that the browser sends
    set_cookies({
        "byse_viewer_id": viewer_id,
        "byse_device_id": device_id,
    })

    # Build the EXACT body structure the server expects
    playback_body = {
        "fingerprint": {
            "token": sess["token"],
            "viewer_id": viewer_id,
            "device_id": device_id,
            "confidence": confidence,
        }
    }

    # X-Embed-Parent header (the embed parent domain)
    extra_headers = {
        "X-Embed-Parent": "https://bysesayeveum.com/e/%s/875828" % code,
    }

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
        "sentBody": playback_body,
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
        result["hasDecryptKeys"] = bool(enc.get("decrypt_keys")) if isinstance(enc, dict) else False
        result["hasIv2"] = bool(enc.get("iv2")) if isinstance(enc, dict) else False
        result["hasPayload2"] = bool(enc.get("payload2")) if isinstance(enc, dict) else False
        result["canDecrypt"] = result["hasKeyParts"] and result["hasIv"] and result["hasPayload"]
    else:
        result["isJson"] = False
        result["bodyType"] = type(body).__name__

    return result
