"""
step3_attest.py

POST /api/videos/access/attest — sign nonce, send fingerprint, get token.

If this fails:
  - 400 = bad request body format
  - 401 = signature verification failed
  - 403 = CF blocking or invalid fingerprint
  - 422 = validation error (field names wrong)

This tries TWO key formats:
  1. Raw X.962 (uncompressed point) — what browser WebCrypto produces
  2. SPKI (DER SubjectPublicKeyInfo) — alternative format
"""

import time
from helpers import (
    BASE_URL, http_post, sign_nonce, FINGERPRINT, get_session
)


def run(sid):
    """
    Step 3: Sign nonce + POST attest → get token.
    Returns dict with token, signature, timing.
    """
    sess = get_session(sid)
    t0 = time.time()
    url = BASE_URL + "/api/videos/access/attest"

    # Validate prerequisites
    if not sess.get("nonce"):
        return {
            "step": "3-attest",
            "error": "No nonce. Run step 2 first.",
            "fix": "Click step 2 button first",
        }
    if not sess.get("private_key"):
        return {
            "step": "3-attest",
            "error": "No keypair. Run step 2 first.",
            "fix": "Click step 2 button first",
        }

    nonce = sess["nonce"]

    # Sign the nonce
    try:
        signature = sign_nonce(sess["private_key"], nonce)
    except ImportError:
        return {
            "step": "3-attest",
            "error": "cryptography not installed",
            "fix": "pip install cryptography",
        }
    except Exception as e:
        return {
            "step": "3-attest",
            "error": "Signing failed: %s" % e,
        }

    # Get challenge_id from step 2
    challenge_id = sess.get("challenge_id", "")

    # Build attestation request body
    # IMPORTANT: server uses snake_case field names!
    attest_body = {
        "challenge_id": challenge_id,
        "nonce": nonce,
        "signature": signature,
        "public_key": sess["pub_raw"],
        "fingerprint": FINGERPRINT,
    }

    result = {
        "step": "3-attest",
        "url": url,
        "timeMs": 0,
        "requestBody": {
            "challenge_id": challenge_id,
            "nonce": nonce[:30] + "...",
            "signature": signature[:30] + "...",
            "public_key": sess["pub_raw"][:30] + "...",
            "fingerprintKeys": list(FINGERPRINT.keys()),
        },
    }

    # Try 1: Raw X.962 key format
    status, body, _ = http_post(url, body=attest_body)
    ms = int((time.time() - t0) * 1000)
    result["httpStatus"] = status
    result["timeMs"] = ms
    result["attempt1"] = {"status": status, "body": body}

    # If failed, try 2: SPKI key format
    if status != 200 and sess.get("pub_spki"):
        attest_body["public_key"] = sess["pub_spki"]
        status2, body2, _ = http_post(url, body=attest_body)
        ms2 = int((time.time() - t0) * 1000)
        result["attempt2"] = {"status": status2, "body": body2, "timeMs": ms2}
        result["httpStatus"] = status2
        result["timeMs"] = ms2
        if status2 == 200:
            status = 200
            body = body2

    result["responseBody"] = body

    # Check for token
    if isinstance(body, dict) and body.get("token"):
        sess["token"] = body["token"]
        result["token"] = body["token"]
        result["tokenPreview"] = body["token"][:30] + "..."
    else:
        result["tokenFound"] = False
        if isinstance(body, dict):
            result["responseKeys"] = list(body.keys())

    return result
