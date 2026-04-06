#!/usr/bin/env python3
"""
════════════════════════════════════════════════════════════════════════════════
  VPS Video Decryptor v3 — Pure HTTP (No Browser)
════════════════════════════════════════════════════════════════════════════════

  Completely different approach from Puppeteer:
  - NO browser, NO headless Chrome, NO DOM
  - Uses curl_cffi to impersonate Chrome's TLS fingerprint (JA3/JA4)
  - Direct HTTP API calls: challenge → attest → playback → decrypt
  - Much faster, much lighter, harder for Cloudflare to detect

  WHY this works when Puppeteer fails:
  - Puppeteer launches a REAL browser → Cloudflare can detect it via
    navigator.webdriver, CDP detection, headless indicators, etc.
  - curl_cffi patches libcurl to produce the EXACT same TLS ClientHello
    as Chrome → Cloudflare sees a normal Chrome TLS handshake

  Deploy:
    sudo apt update && sudo apt install -y python3 python3-pip python3-venv
    python3 -m venv venv && source venv/bin/activate
    pip install -r requirements.txt
    python3 server.py

  Or without venv:
    sudo pip3 install -r requirements.txt
    python3 server.py

  If curl_cffi fails to install (needs C compiler):
    sudo apt install -y build-essential python3-dev libcurl4-openssl-dev
    pip install -r requirements.txt

════════════════════════════════════════════════════════════════════════════════
"""

import os
import sys
import json
import time
import base64
import hashlib
import traceback
from datetime import datetime, timezone
from flask import Flask, jsonify, request as flask_req

# ─── Imports: crypto ─────────────────────────────────────────────────────────
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ─── Imports: HTTP client ────────────────────────────────────────────────────
try:
    from curl_cffi.requests import Session as CffiSession
    HAS_CURL_CFFI = True
    print("[init] curl_cffi loaded ✓ (Chrome TLS impersonation available)")
except ImportError:
    HAS_CURL_CFFI = False
    print("[init] curl_cffi NOT available — install with: pip install curl_cffi")
    print("[init] Falling back to plain requests (may not bypass Cloudflare)")

# ═════════════════════════════════════════════════════════════════════════════
#  CONFIG
# ═════════════════════════════════════════════════════════════════════════════

BASE_URL = "https://f75s.com"
PORT = int(os.environ.get("PORT", 3000))

# Realistic Windows 10 + Chrome 131 fingerprint
UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)

# Realistic browser fingerprint data (what JS would collect)
FINGERPRINT = {
    "canvas": hashlib.md5(b"win10_chrome131_canvas_render").hexdigest(),
    "webglVendor": "Google Inc. (NVIDIA)",
    "webglRenderer": (
        "ANGLE (NVIDIA, NVIDIA GeForce GTX 1660 Ti "
        "Direct3D11 vs_5_0 ps_5_0, D3D11)"
    ),
    "audioHash": hashlib.md5(b"win10_chrome131_audioctx").hexdigest(),
    "screenWidth": 1920,
    "screenHeight": 1080,
    "colorDepth": 24,
    "pixelRatio": 1.0,
    "timezone": "America/New_York",
    "timezoneOffset": -300,
    "language": "en-US",
    "languages": ["en-US", "en"],
    "platform": "Win32",
    "deviceMemory": 8,
    "hardwareConcurrency": 12,
    "maxTouchPoints": 0,
    "touchSupport": False,
    "pdfViewerEnabled": True,
    "webglVersion": "WebGL 2.0",
    "webglShadingLanguageVersion": "WebGL GLSL ES 3.00",
    "cookiesEnabled": True,
    "doNotTrack": None,
    "plugins": (
        "PDF Viewer,Chrome PDF Viewer,Chromium PDF Viewer,"
        "Microsoft Edge PDF Viewer,WebKit built-in PDF"
    ),
    "storageEstimate": 1073741824,  # ~1GB
    "connectionType": "4g",
    "connectionDownlink": 10,
    "connectionRtt": 50,
    "connectionSaveData": False,
}

# Headers that mimic a real browser's XHR/fetch request
API_HEADERS = {
    "User-Agent": UA,
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Content-Type": "application/json",
    "Origin": BASE_URL,
    "Referer": f"{BASE_URL}/",
    "Sec-Ch-Ua": '"Chromium";v="131", "Not_A Brand";v="24", "Google Chrome";v="131"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
}

app = Flask(__name__)

# ═════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═════════════════════════════════════════════════════════════════════════════

def b64url_decode(s: str) -> bytes:
    """Base64url decode (add padding if needed)."""
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def b64url_encode(data: bytes) -> str:
    """Base64url encode (strip padding)."""
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def generate_keypair():
    """
    Generate an ECDSA P-256 key pair.
    Returns (private_key, public_key_b64url, public_key_jwk).
    """
    private_key = ec.generate_private_key(ec.SECP256R1())

    # Raw public key (65 bytes: 0x04 + 32 + 32)
    pub_raw = private_key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )

    # SPKI public key (DER encoded)
    pub_spki = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return private_key, b64url_encode(pub_raw), b64url_encode(pub_spki)


def sign_nonce(private_key, nonce: str) -> str:
    """
    Sign nonce with ECDSA P-256 SHA-256.
    Returns base64url-encoded raw signature (r || s, 64 bytes).
    This matches what Web Crypto API produces in the browser.
    """
    nonce_bytes = nonce.encode("utf-8") if isinstance(nonce, str) else nonce

    # Python's cryptography lib produces DER-encoded signature
    der_sig = private_key.sign(nonce_bytes, ec.ECDSA(hashes.SHA256()))

    # Convert DER → raw (r || s) format (each 32 bytes for P-256)
    r, s = decode_dss_signature(der_sig)
    raw_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")

    return b64url_encode(raw_sig)


def decrypt_payload(encrypted: dict) -> dict:
    """
    Decrypt AES-256-GCM encrypted payload.
    Key = concat(base64url_decode(part) for each key_parts[])
    Tag = last 16 bytes of the payload ciphertext.
    """
    key_parts = encrypted.get("key_parts", [])
    iv_b64 = encrypted.get("iv", "")
    payload_b64 = encrypted.get("payload", "")

    if not key_parts or not iv_b64 or not payload_b64:
        raise ValueError(
            f"Missing fields — key_parts: {len(key_parts)}, "
            f"iv: {bool(iv_b64)}, payload: {bool(payload_b64)}"
        )

    # Concatenate all key parts → 32-byte AES key
    key = b""
    for part in key_parts:
        key += b64url_decode(part)

    if len(key) != 32:
        raise ValueError(f"Key length is {len(key)} bytes, expected 32")

    iv = b64url_decode(iv_b64)
    ciphertext_with_tag = b64url_decode(payload_b64)

    if len(ciphertext_with_tag) <= 16:
        raise ValueError(
            f"Ciphertext too short: {len(ciphertext_with_tag)} bytes"
        )

    # AESGCM in Python's cryptography lib expects ciphertext || tag
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(iv, ciphertext_with_tag, None)

    return json.loads(plaintext.decode("utf-8"))


# ═════════════════════════════════════════════════════════════════════════════
#  HTTP SESSION
# ═════════════════════════════════════════════════════════════════════════════

_session = None


def get_session():
    """
    Get HTTP session with Chrome TLS impersonation (curl_cffi)
    or plain requests as fallback.
    """
    global _session
    if _session is not None:
        return _session

    if HAS_CURL_CFFI:
        # curl_cffi impersonates Chrome's JA3/JA4 TLS fingerprint
        # This is the #1 reason Cloudflare blocks server requests
        _session = CffiSession(impersonate="chrome")
        print("[session] Created curl_cffi session (Chrome TLS impersonation)")
    else:
        import requests as _requests
        _session = _requests.Session()
        _session.headers.update(API_HEADERS)
        print("[session] Created plain requests session (NO TLS impersonation)")

    return _session


def http_post(session, url, json_body=None, extra_headers=None, timeout=20):
    """
    Make a POST request. Handles both curl_cffi and plain requests.
    Returns (status_code, response_json_or_text, response_headers).
    """
    headers = {**API_HEADERS}
    if extra_headers:
        headers.update(extra_headers)

    kwargs = {
        "headers": headers,
        "timeout": timeout,
    }
    if json_body is not None:
        kwargs["json"] = json_body

    try:
        resp = session.post(url, **kwargs)
        ct = resp.headers.get("content-type", "")
        if "json" in ct:
            body = resp.json()
        else:
            body = resp.text[:5000]  # Truncate large HTML responses
        return resp.status_code, body, dict(resp.headers)
    except Exception as e:
        return None, str(e), {}


def http_get(session, url, timeout=20):
    """Make a GET request. Returns (status_code, text, headers)."""
    try:
        resp = session.get(url, headers=API_HEADERS, timeout=timeout)
        return resp.status_code, resp.text[:10000], dict(resp.headers)
    except Exception as e:
        return None, str(e), {}


# ═════════════════════════════════════════════════════════════════════════════
#  MAIN FLOW: Challenge → Attest → Playback → Decrypt
# ═════════════════════════════════════════════════════════════════════════════

def fetch_and_decrypt(code: str, debug: bool = False):
    """
    Complete flow:
    1. Warm up: GET homepage to get CF cookies
    2. Challenge: POST /api/videos/access/challenge → get nonce
    3. Sign: ECDSA P-256 sign the nonce
    4. Attest: POST /api/videos/access/attest → get token
    5. Playback: POST /api/videos/{code}/embed/playback → get encrypted data
    6. Decrypt: AES-256-GCM → return JSON

    Returns dict with 'success', 'data'/'error', and optionally 'debug'.
    """
    log = []
    t0 = time.time()
    debug_info = {
        "code": code,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hasCurlCffi": HAS_CURL_CFFI,
    }

    def step(msg):
        elapsed = int((time.time() - t0) * 1000)
        line = f"[{elapsed}ms] {msg}"
        log.append(line)
        print(line)

    session = get_session()

    try:
        # ── Step 0: Warm up — visit homepage to get CF cookies ──────────
        step("Warming up: GET homepage for CF cookies...")
        status, body, headers = http_get(session, BASE_URL, timeout=15)

        if status is None:
            raise Exception(f"Homepage request failed: {body}")

        step(f"Homepage: HTTP {status}")

        # Check if we got a Cloudflare challenge page
        if isinstance(body, str) and (
            "challenge-platform" in body
            or "cf-browser-verification" in body
            or "Just a moment" in body
            or "Checking your browser" in body
        ):
            step("⚠ Cloudflare challenge page detected on homepage!")
            step("curl_cffi TLS impersonation alone is NOT enough.")
            step("This site uses JS challenges that need browser execution.")
            debug_info["cf_challenge"] = True
            debug_info["homepage_status"] = status
            debug_info["homepage_body_preview"] = body[:500] if isinstance(body, str) else "non-text"

            # Check for cf_clearance cookie
            cookies = getattr(session, "cookies", {})
            if hasattr(cookies, "get_dict"):
                cookie_dict = cookies.get_dict()
            elif isinstance(cookies, dict):
                cookie_dict = cookies
            else:
                cookie_dict = {}

            if "cf_clearance" in cookie_dict:
                step(f"✓ Got cf_clearance: {cookie_dict['cf_clearance'][:20]}...")
                debug_info["cf_clearance"] = True
            else:
                step("✗ No cf_clearance cookie — CF challenge not solved")
                debug_info["cf_clearance"] = False
                raise Exception(
                    "Cloudflare JS challenge detected. curl_cffi cannot solve JS challenges.\n"
                    "Options:\n"
                    "1. Use a VPS with residential IP (datacenter IPs may be flagged)\n"
                    "2. Try Playwright approach (see alternative below)\n"
                    "3. Use a Cloudflare-solving proxy service\n"
                    "Share this debug output for further analysis."
                )

        elif isinstance(body, str) and "cloudflare" in body.lower() and status in (403, 503):
            step(f"⚠ Cloudflare block page (HTTP {status})")
            debug_info["cf_blocked"] = True
            debug_info["homepage_status"] = status
            debug_info["homepage_body_preview"] = body[:500]
            raise Exception(
                f"Cloudflare blocked the request (HTTP {status}). "
                "Your VPS IP may be flagged. Try a different VPS/IP."
            )

        elif status == 200:
            step("✓ Homepage loaded (no CF challenge)")
            debug_info["cf_challenge"] = False

        # Small delay to look natural
        time.sleep(0.5)

        # ── Step 1: Challenge ────────────────────────────────────────────
        step("POST /api/videos/access/challenge")
        status, body, _ = http_post(
            session,
            f"{BASE_URL}/api/videos/access/challenge",
            json_body={},
        )

        if status is None:
            raise Exception(f"Challenge request failed: {body}")

        step(f"Challenge response: HTTP {status}")

        if status != 200:
            err_detail = ""
            if isinstance(body, str):
                err_detail = body[:200]
            elif isinstance(body, dict):
                err_detail = json.dumps(body, indent=2)[:200]
            raise Exception(
                f"Challenge endpoint returned HTTP {status}. {err_detail}"
            )

        if not isinstance(body, dict):
            raise Exception(
                f"Challenge response is not JSON: {str(body)[:100]}"
            )

        challenge_data = body
        nonce = challenge_data.get("nonce", "")
        debug_info["challenge"] = {
            "status": status,
            "keys": list(body.keys()),
            "nonce_preview": nonce[:30] + "..." if nonce else "(empty)",
        }

        if not nonce:
            raise Exception(
                f"No nonce in challenge response. Keys: {list(body.keys())}"
            )

        step(f"Got nonce: {nonce[:20]}...")

        # ── Step 2: Sign nonce ───────────────────────────────────────────
        step("Signing nonce with ECDSA P-256...")
        private_key, pub_key_raw, pub_key_spki = generate_keypair()
        signature = sign_nonce(private_key, nonce)
        step(f"Signature: {signature[:20]}... ({len(base64.b64decode(signature + '=='))} bytes)")

        debug_info["signing"] = {
            "pubkey_raw_preview": pub_key_raw[:30] + "...",
            "pubkey_spki_preview": pub_key_spki[:30] + "...",
            "sig_preview": signature[:30] + "...",
        }

        # ── Step 3: Attest ───────────────────────────────────────────────
        step("POST /api/videos/access/attest")

        # Build attestation body — format based on what the JS sends
        attest_body = {
            "nonce": nonce,
            "signature": signature,
            "publicKey": pub_key_raw,   # Try raw X.962 format first
            "fingerprint": FINGERPRINT,
        }

        status, body, _ = http_post(
            session,
            f"{BASE_URL}/api/videos/access/attest",
            json_body=attest_body,
        )

        step(f"Attest response: HTTP {status}")
        debug_info["attest"] = {
            "status": status,
            "request_body_keys": list(attest_body.keys()),
        }

        if status != 200:
            err_detail = ""
            if isinstance(body, str):
                err_detail = body[:300]
            elif isinstance(body, dict):
                err_detail = json.dumps(body, indent=2)[:300]
                debug_info["attest"]["response_body"] = body

            # If attest fails with raw key, try SPKI format
            if status in (400, 401, 403, 422) and "publicKey" in err_detail:
                step("⚠ Attest failed — trying SPKI public key format...")
                attest_body["publicKey"] = pub_key_spki
                status2, body2, _ = http_post(
                    session,
                    f"{BASE_URL}/api/videos/access/attest",
                    json_body=attest_body,
                )
                step(f"Attest retry: HTTP {status2}")
                if status2 == 200:
                    status = status2
                    body = body2
                else:
                    debug_info["attest"]["spki_retry_status"] = status2
                    debug_info["attest"]["spki_retry_body"] = (
                        body2 if isinstance(body2, dict) else str(body2)[:300]
                    )

            if status != 200:
                raise Exception(
                    f"Attest endpoint returned HTTP {status}. {err_detail}"
                )

        if not isinstance(body, dict):
            raise Exception(
                f"Attest response is not JSON: {str(body)[:100]}"
            )

        token = body.get("token", "")
        debug_info["attest"]["response_keys"] = list(body.keys())
        debug_info["attest"]["token_preview"] = (
            token[:40] + "..." if token else "(empty)"
        )

        if not token:
            raise Exception(
                f"No token in attest response. Keys: {list(body.keys())}. "
                f"Full response: {json.dumps(body, indent=2)[:500]}"
            )

        step(f"Got token: {token[:30]}...")

        # ── Step 4: Playback ─────────────────────────────────────────────
        step(f"POST /api/videos/{code}/embed/playback")

        playback_headers = {
            "X-Embed-Parent": BASE_URL,
        }

        # The playback body format — try with token directly
        playback_body_v1 = {"token": token}

        status, body, resp_headers = http_post(
            session,
            f"{BASE_URL}/api/videos/{code}/embed/playback",
            json_body=playback_body_v1,
            extra_headers=playback_headers,
        )

        step(f"Playback response: HTTP {status}")
        debug_info["playback"] = {
            "status": status,
            "response_keys": list(body.keys()) if isinstance(body, dict) else "non-json",
        }

        if status != 200:
            err_detail = ""
            if isinstance(body, str):
                err_detail = body[:300]
            elif isinstance(body, dict):
                err_detail = json.dumps(body, indent=2)[:300]
                debug_info["playback"]["response_body"] = body
            raise Exception(
                f"Playback endpoint returned HTTP {status}. {err_detail}"
            )

        if not isinstance(body, dict):
            raise Exception(
                f"Playback response is not JSON: {str(body)[:100]}"
            )

        # The encrypted payload might be at top level or nested under 'playback'
        encrypted = body.get("playback", body)
        debug_info["playback"]["encrypted_keys"] = list(encrypted.keys())

        if not encrypted.get("key_parts") or not encrypted.get("iv") or not encrypted.get("payload"):
            # Maybe the response has a different structure
            debug_info["playback"]["full_response"] = {
                k: (str(v)[:100] if not isinstance(v, (dict, list)) else f"({type(v).__name__})")
                for k, v in body.items()
            }
            raise Exception(
                f"No encrypted payload found. "
                f"Response keys: {list(body.keys())}. "
                f"Nested 'playback' keys: {list(encrypted.keys())}. "
                f"Share debug output for analysis."
            )

        debug_info["raw_encrypted"] = {
            "key_parts_count": len(encrypted.get("key_parts", [])),
            "iv_preview": str(encrypted.get("iv", ""))[:30],
            "payload_length": len(str(encrypted.get("payload", ""))),
        }

        # ── Step 5: Decrypt ──────────────────────────────────────────────
        step("Decrypting AES-256-GCM...")
        decrypted = decrypt_payload(encrypted)

        sources = decrypted.get("sources", [])
        subtitles = decrypted.get("subtitles", [])
        step(f"✓ Decrypted! {len(sources)} source(s), {len(subtitles)} subtitle(s)")

        # Log source URLs (for debug)
        for i, src in enumerate(sources):
            url = src.get("url", "(no url)")
            quality = src.get("quality") or src.get("label") or src.get("height", "")
            mime = src.get("mimeType", "")
            step(f"  Source {i}: {quality} | {mime} | {url[:80]}...")

        total_ms = int((time.time() - t0) * 1000)
        step(f"Total: {total_ms}ms")
        debug_info["totalTimeMs"] = total_ms
        debug_info["success"] = True

        return {
            "success": True,
            "data": decrypted,
            "debug": debug_info if debug else None,
        }

    except Exception as e:
        total_ms = int((time.time() - t0) * 1000)
        step(f"✗ ERROR: {str(e)}")
        debug_info["totalTimeMs"] = total_ms
        debug_info["success"] = False
        debug_info["error"] = str(e)
        debug_info["error_type"] = type(e).__name__
        debug_info["traceback"] = traceback.format_exc()

        return {
            "success": False,
            "error": str(e),
            "debug": debug_info if debug else None,
        }


# ═════════════════════════════════════════════════════════════════════════════
#  ROUTES
# ═════════════════════════════════════════════════════════════════════════════

@app.route("/e/<code>")
def endpoint_decrypt(code):
    """Decrypt video and return sources JSON."""
    print(f"\n[GET /e/{code}]")
    result = fetch_and_decrypt(code, debug=False)
    if result["success"]:
        return jsonify(result["data"])
    else:
        return jsonify({"error": result["error"]}), 502


@app.route("/d/<code>")
def endpoint_decrypt_d(code):
    """Alias for /e/{code}."""
    print(f"\n[GET /d/{code}]")
    result = fetch_and_decrypt(code, debug=False)
    if result["success"]:
        return jsonify(result["data"])
    else:
        return jsonify({"error": result["error"]}), 502


@app.route("/debug/<code>")
def endpoint_debug(code):
    """Full debug mode — returns everything including logs and raw data."""
    print(f"\n[GET /debug/{code}]")
    result = fetch_and_decrypt(code, debug=True)
    status_code = 200 if result["success"] else 502
    resp = {
        "success": result["success"],
        "debug": result.get("debug", {}),
    }
    if result["success"]:
        resp["decrypted"] = result["data"]
    if not result["success"]:
        resp["error"] = result["error"]
        resp["note"] = "Share this FULL response for analysis"
    return jsonify(resp), status_code


@app.route("/raw/<code>")
def endpoint_raw(code):
    """Return the raw encrypted response (before decryption)."""
    print(f"\n[GET /raw/{code}]")
    session = get_session()

    # Do the full flow but return the encrypted payload
    log = []
    t0 = time.time()

    try:
        private_key, pub_key, _ = generate_keypair()

        # Challenge
        status, body, _ = http_post(
            session,
            f"{BASE_URL}/api/videos/access/challenge",
            json_body={},
        )
        if status != 200:
            return jsonify({"error": f"Challenge failed: HTTP {status}", "body": str(body)[:500]}), 502

        nonce = body.get("nonce", "")
        signature = sign_nonce(private_key, nonce)

        # Attest
        status, body, _ = http_post(
            session,
            f"{BASE_URL}/api/videos/access/attest",
            json_body={
                "nonce": nonce,
                "signature": signature,
                "publicKey": pub_key,
                "fingerprint": FINGERPRINT,
            },
        )
        if status != 200:
            return jsonify({"error": f"Attest failed: HTTP {status}", "body": str(body)[:500]}), 502

        token = body.get("token", "")

        # Playback
        status, body, _ = http_post(
            session,
            f"{BASE_URL}/api/videos/{code}/embed/playback",
            json_body={"token": token},
            extra_headers={"X-Embed-Parent": BASE_URL},
        )
        if status != 200:
            return jsonify({"error": f"Playback failed: HTTP {status}", "body": str(body)[:500]}), 502

        return jsonify({
            "success": True,
            "raw_encrypted": body,
            "note": "This is the raw server response before decryption",
        })

    except Exception as e:
        return jsonify({"error": str(e), "traceback": traceback.format_exc()}), 502


@app.route("/decrypt", methods=["POST"])
def endpoint_manual_decrypt():
    """Decrypt a manually provided encrypted payload (POST JSON body)."""
    try:
        data = flask_req.get_json(force=True)
        if not data:
            return jsonify({"error": "No JSON body provided"}), 400

        encrypted = data.get("playback", data)
        if not encrypted.get("key_parts") or not encrypted.get("iv") or not encrypted.get("payload"):
            return jsonify({
                "error": "Missing required fields: key_parts, iv, payload",
                "received_keys": list(encrypted.keys()),
            }), 400

        result = decrypt_payload(encrypted)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Decrypt failed: {str(e)}"}), 400


@app.route("/proxy")
def endpoint_proxy():
    """Proxy .ts segments with correct Referer header."""
    from urllib.parse import urlparse
    import urllib.request

    target_url = flask_req.args.get("url")
    if not target_url:
        return jsonify({"error": "Missing ?url= parameter"}), 400

    parsed = urlparse(target_url)
    if parsed.scheme not in ("http", "https"):
        return jsonify({"error": "Only http/https URLs allowed"}), 400

    proxy_req = urllib.request.Request(
        target_url,
        headers={
            "User-Agent": UA,
            "Accept": "*/*, video/mp4, application/vnd.apple.mpegurl",
            "Referer": f"{BASE_URL}/",
            "Origin": BASE_URL,
        },
    )

    try:
        resp = urllib.request.urlopen(proxy_req, timeout=15)
        headers = dict(resp.headers)
        response = app.response_class(
            resp.read(),
            status=resp.status,
            headers={
                k: v for k, v in headers.items()
                if k.lower() not in ("transfer-encoding", "connection")
            },
        )
        response.headers["Access-Control-Allow-Origin"] = "*"
        return response
    except Exception as e:
        return jsonify({"error": f"Proxy failed: {str(e)}"}), 502


@app.route("/rewrite")
def endpoint_rewrite():
    """Rewrite m3u8 playlist: replace segment URLs with /proxy URLs."""
    from urllib.parse import urlparse
    import urllib.request

    m3u8_url = flask_req.args.get("url")
    if not m3u8_url:
        return jsonify({"error": "Missing ?url= parameter"}), 400

    base = flask_req.scheme + "://" + flask_req.host

    try:
        req = urllib.request.Request(
            m3u8_url,
            headers={"User-Agent": UA, "Referer": f"{BASE_URL}/"},
        )
        resp = urllib.request.urlopen(req, timeout=15)
        body = resp.read().decode("utf-8", errors="replace")

        base_url = m3u8_url[: m3u8_url.rfind("/") + 1]

        lines = body.split("\n")
        rewritten = []
        for line in lines:
            trimmed = line.strip()
            if not trimmed or trimmed.startswith("#"):
                rewritten.append(line)
            else:
                full = trimmed if trimmed.startswith("http") else base_url + trimmed
                rewritten.append(base + "/proxy?url=" + urllib.parse.quote(full, safe=""))

        resp_body = "\n".join(rewritten)
        response = app.response_class(
            resp_body,
            content_type="application/vnd.apple.mpegurl",
        )
        response.headers["Access-Control-Allow-Origin"] = "*"
        return response
    except Exception as e:
        return jsonify({"error": f"Rewrite failed: {str(e)}"}), 502


@app.route("/health")
def endpoint_health():
    """Server health check."""
    return jsonify({
        "status": "ok",
        "version": "v3-python",
        "method": "curl_cffi" if HAS_CURL_CFFI else "requests (no TLS impersonation)",
        "uptime": time.time(),
        "hasCurlCffi": HAS_CURL_CFFI,
    })


# ═════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print()
    print("═════════════════════════════════════════════════════════════")
    print("  VPS Video Decryptor v3 — Pure HTTP (No Browser)")
    print("═════════════════════════════════════════════════════════════")
    print(f"  curl_cffi: {'✓ Chrome TLS impersonation' if HAS_CURL_CFFI else '✗ NOT INSTALLED (pip install curl_cffi)'}")
    print(f"  Port:      {PORT}")
    print()
    print("  Routes:")
    print("  /e/{code}       → decrypt, return JSON")
    print("  /d/{code}       → decrypt, return JSON (alias)")
    print("  /debug/{code}   → full debug with logs + raw data")
    print("  /raw/{code}     → raw encrypted response (no decrypt)")
    print("  /decrypt        → POST raw payload to decrypt")
    print("  /proxy?url=     → proxy .ts segments")
    print("  /rewrite?url=   → rewrite m3u8 with /proxy URLs")
    print("  /health         → server status")
    print()
    print("  ⚠ If curl_cffi is NOT installed:")
    print("    pip install curl_cffi")
    print("    (may need: sudo apt install -y build-essential libcurl4-openssl-dev)")
    print()
    if not HAS_CURL_CFFI:
        print("  ⚠⚠⚠ WARNING: Without curl_cffi, Cloudflare WILL block requests!")
        print("  Install it BEFORE deploying: pip install curl_cffi")
        print()
    print("═════════════════════════════════════════════════════════════")

    app.run(host="0.0.0.0", port=PORT, debug=False)
