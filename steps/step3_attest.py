"""
step3_attest.py

POST /api/videos/access/attest — sign nonce, send fingerprint, get token.

The exact request format is unknown (hidden in index-DD6OUyti.js).
This file tries MULTIPLE formats and dumps every attempt.

Errors:
  - "challenge id required" → missing challenge_id
  - "public key required"   → missing public_key field
  - "invalid payload"       → body format/structure is wrong
"""

import json
import time
from helpers import (
    BASE_URL, http_post, sign_nonce, FINGERPRINT, get_session
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

    nonce = sess["nonce"]
    challenge_id = sess.get("challenge_id", "")

    # Sign
    try:
        signature = sign_nonce(sess["private_key"], nonce)
    except Exception as e:
        return {"step": "3-attest", "error": "Signing failed: %s" % e}

    sig_full = signature
    pk_raw = sess["pub_raw"]
    pk_spki = sess["pub_spki"]

    result = {"step": "3-attest", "url": url, "attempts": []}

    # ── Try multiple body formats ──

    formats = [
        {
            "name": "A: flat snake_case (challenge_id, nonce, signature, public_key, fingerprint)",
            "body": {
                "challenge_id": challenge_id,
                "nonce": nonce,
                "signature": signature,
                "public_key": pk_raw,
                "fingerprint": FINGERPRINT,
            },
        },
        {
            "name": "B: nested under 'attestation'",
            "body": {
                "attestation": {
                    "challenge_id": challenge_id,
                    "nonce": nonce,
                    "signature": signature,
                    "public_key": pk_raw,
                    "fingerprint": FINGERPRINT,
                },
            },
        },
        {
            "name": "C: 'data' wrapper with public_key as array",
            "body": {
                "challenge_id": challenge_id,
                "data": {
                    "nonce": nonce,
                    "signature": signature,
                    "public_key": pk_raw,
                    "fingerprint": FINGERPRINT,
                },
            },
        },
        {
            "name": "D: camelCase keys",
            "body": {
                "challengeId": challenge_id,
                "nonce": nonce,
                "signature": signature,
                "publicKey": pk_raw,
                "fingerprint": FINGERPRINT,
            },
        },
        {
            "name": "E: no fingerprint field",
            "body": {
                "challenge_id": challenge_id,
                "nonce": nonce,
                "signature": signature,
                "public_key": pk_raw,
            },
        },
        {
            "name": "F: with SPKI key",
            "body": {
                "challenge_id": challenge_id,
                "nonce": nonce,
                "signature": signature,
                "public_key": pk_spki,
                "fingerprint": FINGERPRINT,
            },
        },
        {
            "name": "G: signature as array [r, s]",
            "body": {
                "challenge_id": challenge_id,
                "nonce": nonce,
                "signature": [signature],  # try as array
                "public_key": pk_raw,
                "fingerprint": FINGERPRINT,
            },
        },
        {
            "name": "H: minimal - just challenge_id + nonce + signature + public_key",
            "body": {
                "challenge_id": challenge_id,
                "nonce": nonce,
                "signature": signature,
                "public_key": pk_raw,
            },
        },
    ]

    for fmt in formats:
        body_to_send = fmt["body"]
        # Show full JSON being sent
        raw_json = json.dumps(body_to_send, separators=(",", ":"))
        if len(raw_json) > 500:
            raw_json_show = raw_json[:250] + "..." + raw_json[-250:]
        else:
            raw_json_show = raw_json

        status, resp_body, _ = http_post(url, body=body_to_send)
        ms = int((time.time() - t0) * 1000)

        attempt = {
            "name": fmt["name"],
            "status": status,
            "response": resp_body,
            "sentJsonPreview": raw_json_show,
            "sentFieldCount": len(body_to_send),
            "sentTopKeys": list(body_to_send.keys()),
        }

        # Check nested keys
        for k, v in body_to_send.items():
            if isinstance(v, dict):
                attempt["nestedKeys_%s" % k] = list(v.keys())

        result["attempts"].append(attempt)

        if status == 200:
            result["httpStatus"] = 200
            result["timeMs"] = ms
            result["winner"] = fmt["name"]
            result["responseBody"] = resp_body
            if isinstance(resp_body, dict) and resp_body.get("token"):
                sess["token"] = resp_body["token"]
                result["token"] = resp_body["token"]
                result["tokenFound"] = True
            return result

    # All attempts failed
    result["httpStatus"] = 400
    result["timeMs"] = int((time.time() - t0) * 1000)
    result["tokenFound"] = False
    result["hint"] = "All formats failed. Share this output - we need to see which format the server accepts."

    return result
