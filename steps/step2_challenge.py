"""
step2_challenge.py

POST /api/videos/access/challenge — get nonce to sign.

Response contains: nonce, challenge_id
We also generate an ECDSA P-256 keypair and save JWK to session.
"""

import time
from helpers import (
    BASE_URL, http_post, generate_keypair, get_session
)


def run(sid):
    """
    Step 2: POST challenge -> get nonce + generate ECDSA keypair.
    Returns dict with nonce, public key, timing.
    """
    sess = get_session(sid)
    t0 = time.time()
    url = BASE_URL + "/api/videos/access/challenge"

    status, body, headers = http_post(url, body={})
    ms = int((time.time() - t0) * 1000)

    result = {
        "step": "2-challenge",
        "url": url,
        "httpStatus": status,
        "timeMs": ms,
        "responseBody": body,
    }

    # Check if we got a nonce and challenge_id
    if isinstance(body, dict) and body.get("nonce"):
        nonce = body["nonce"]
        sess["nonce"] = nonce
        result["nonce"] = nonce
        result["noncePreview"] = nonce[:30] + "..."

        # Save challenge_id for step 3
        challenge_id = body.get("challenge_id", "")
        sess["challenge_id"] = challenge_id
        result["challenge_id"] = challenge_id

        # Generate ECDSA P-256 keypair for step 3
        try:
            pk, jwk, raw, spki = generate_keypair()
            sess["private_key"] = pk
            sess["pub_jwk"] = jwk
            sess["pub_raw"] = raw
            sess["pub_spki"] = spki
            result["keyGenerated"] = True
            result["jwkPreview"] = {
                "kty": jwk["kty"],
                "crv": jwk["crv"],
                "x": jwk["x"][:20] + "...",
                "y": jwk["y"][:20] + "...",
            }
        except ImportError:
            result["keyError"] = "cryptography not installed"
        except Exception as e:
            result["keyError"] = str(e)
    else:
        result["nonceFound"] = False
        if isinstance(body, dict):
            result["responseKeys"] = list(body.keys())

    return result
