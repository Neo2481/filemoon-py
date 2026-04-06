"""
step3_attest.py

POST /api/videos/access/attest — sign nonce, send fingerprint, get token.

Exact payload structure (captured from real browser):
{
  "viewer_id": "uuid",
  "device_id": "uuid",
  "challenge_id": "from step 2",
  "nonce": "from step 2",
  "signature": "base64url ECDSA P-256 SHA-256",
  "public_key": {
    "crv": "P-256",
    "ext": true,
    "key_ops": ["verify"],
    "kty": "EC",
    "x": "base64url",
    "y": "base64url"
  },
  "client": { ... browser fingerprint ... },
  "storage": { ... },
  "attributes": { ... }
}
"""

import json
import time
from helpers import (
    BASE_URL, http_post, sign_nonce,
    make_client_fingerprint, make_storage, make_attributes,
    get_session,
)


def run(sid):
    sess = get_session(sid)
    t0 = time.time()
    url = BASE_URL + "/api/videos/access/attest"

    # Prerequisites
    if not sess.get("nonce"):
        return {"step": "3-attest", "error": "No nonce. Run step 2 first."}
    if not sess.get("private_key"):
        return {"step": "3-attest", "error": "No keypair. Run step 2 first."}
    if not sess.get("challenge_id"):
        return {"step": "3-attest", "error": "No challenge_id. Run step 2 first."}
    if not sess.get("pub_jwk"):
        return {"step": "3-attest", "error": "No JWK public key. Run step 2 first."}

    nonce = sess["nonce"]
    challenge_id = sess["challenge_id"]
    viewer_id = sess["viewer_id"]
    device_id = sess["device_id"]

    # Sign the nonce with ECDSA P-256 SHA-256
    try:
        signature = sign_nonce(sess["private_key"], nonce)
    except Exception as e:
        return {"step": "3-attest", "error": "Signing failed: %s" % e}

    # Build the EXACT payload structure the server expects
    body = {
        "viewer_id": viewer_id,
        "device_id": device_id,
        "challenge_id": challenge_id,
        "nonce": nonce,
        "signature": signature,
        "public_key": sess["pub_jwk"],
        "client": make_client_fingerprint(),
        "storage": make_storage(viewer_id, device_id),
        "attributes": make_attributes(),
    }

    # Show what we're sending (for debugging)
    sent_preview = json.dumps(body, indent=2)
    if len(sent_preview) > 3000:
        sent_preview = sent_preview[:1500] + "\n  ... (truncated)\n" + sent_preview[-1500:]

    status, resp_body, resp_headers = http_post(url, body=body)
    ms = int((time.time() - t0) * 1000)

    result = {
        "step": "3-attest",
        "url": url,
        "httpStatus": status,
        "timeMs": ms,
        "sentBodyPreview": sent_preview,
        "responseBody": resp_body,
    }

    if status == 200:
        result["tokenFound"] = False
        if isinstance(resp_body, dict):
            result["responseKeys"] = list(resp_body.keys())
            token = resp_body.get("token")
            if token:
                sess["token"] = token
                result["token"] = token
                result["tokenPreview"] = token[:40] + "..." if len(token) > 40 else token
                result["tokenFound"] = True

            # Save server-returned IDs for step 4 (playback needs these)
            if resp_body.get("viewer_id"):
                sess["server_viewer_id"] = resp_body["viewer_id"]
            if resp_body.get("device_id"):
                sess["server_device_id"] = resp_body["device_id"]
            if "confidence" in resp_body:
                sess["confidence"] = resp_body["confidence"]
    else:
        result["hint"] = (
            "Status %d — check sentBodyPreview vs real browser payload. "
            "Common issues: missing fields, wrong types, wrong field names."
            % status
        )

    return result
