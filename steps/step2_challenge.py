"""
step2_challenge.py

POST /api/videos/access/challenge — get nonce to sign.

If this fails:
  - 403 = CF challenge not passed (step 1 failed)
  - 404 = wrong API endpoint
  - No nonce in response = API changed format
"""

import time
from helpers import (
    BASE_URL, http_post, generate_keypair, get_session
)


def run(sid):
    """
    Step 2: POST challenge → get nonce + generate ECDSA keypair.
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

    # Check if we got a nonce
    if isinstance(body, dict) and body.get("nonce"):
        nonce = body["nonce"]
        sess["nonce"] = nonce
        result["nonce"] = nonce
        result["noncePreview"] = nonce[:30] + "..."

        # Generate ECDSA P-256 keypair for step 3
        try:
            pk, raw, spki = generate_keypair()
            sess["private_key"] = pk
            sess["pub_raw"] = raw
            sess["pub_spki"] = spki
            result["keyGenerated"] = True
            result["publicKeyPreview"] = raw[:30] + "..."
        except ImportError:
            result["keyError"] = "cryptography not installed — run: pip install cryptography"
        except Exception as e:
            result["keyError"] = str(e)

    else:
        result["nonceFound"] = False
        if isinstance(body, dict):
            result["responseKeys"] = list(body.keys())

    return result
