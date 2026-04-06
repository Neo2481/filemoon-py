#!/usr/bin/env python3
"""
VPS Video Decryptor v3.1 - Crash-proof, auto-fallback

All heavy imports (cryptography, curl_cffi) are lazy-loaded
so the server ALWAYS starts even if they're missing.
"""

import os
import sys
import json
import time
import base64
import hashlib
import traceback
from datetime import datetime, timezone

# ═══════════════════════════════════════════════════════════════════
#  LAZY IMPORTS - never crash on startup
# ═══════════════════════════════════════════════════════════════════

_flask_app = None
_has_curl_cffi = None
_has_cryptography = None
_curl_cffi_session = None
_requests_session = None


def _check_curl_cffi():
    global _has_curl_cffi
    if _has_curl_cffi is not None:
        return _has_curl_cffi
    try:
        from curl_cffi.requests import Session
        _has_curl_cffi = True
        print("[init] curl_cffi OK - Chrome TLS impersonation available")
    except ImportError:
        _has_curl_cffi = False
        print("[init] curl_cffi NOT available - will use fallback HTTP")
    return _has_curl_cffi


def _check_cryptography():
    global _has_cryptography
    if _has_cryptography is not None:
        return _has_cryptography
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        _has_cryptography = True
        print("[init] cryptography OK - AES-256-GCM decryption available")
    except ImportError:
        _has_cryptography = False
        print("[init] cryptography NOT available - decryption will fail!")
    return _has_cryptography


def _get_flask():
    global _flask_app
    if _flask_app is not None:
        return _flask_app
    from flask import Flask, jsonify, request as flask_req
    _flask_app = Flask(__name__)
    return _flask_app, jsonify, flask_req


# ═══════════════════════════════════════════════════════════════════
#  CONFIG
# ═══════════════════════════════════════════════════════════════════

BASE_URL = "https://f75s.com"
PORT = int(os.environ.get("PORT", 3000))

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)

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
    "storageEstimate": 1073741824,
    "connectionType": "4g",
    "connectionDownlink": 10,
    "connectionRtt": 50,
    "connectionSaveData": False,
}

API_HEADERS = {
    "User-Agent": UA,
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Content-Type": "application/json",
    "Origin": BASE_URL,
    "Referer": BASE_URL + "/",
    "Sec-Ch-Ua": '"Chromium";v="131", "Not_A Brand";v="24", "Google Chrome";v="131"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
}


# ═══════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════

def b64url_decode(s):
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def b64url_encode(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def generate_keypair():
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    private_key = ec.generate_private_key(ec.SECP256R1())
    pub_raw = private_key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    pub_spki = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, b64url_encode(pub_raw), b64url_encode(pub_spki)


def sign_nonce(private_key, nonce):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    nonce_bytes = nonce.encode("utf-8") if isinstance(nonce, str) else nonce
    der_sig = private_key.sign(nonce_bytes, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    raw_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return b64url_encode(raw_sig)


def decrypt_payload(encrypted):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key_parts = encrypted.get("key_parts", [])
    iv_b64 = encrypted.get("iv", "")
    payload_b64 = encrypted.get("payload", "")
    if not key_parts or not iv_b64 or not payload_b64:
        raise ValueError("Missing key_parts, iv, or payload")
    key = b""
    for part in key_parts:
        key += b64url_decode(part)
    if len(key) != 32:
        raise ValueError("Key is %d bytes, expected 32" % len(key))
    iv = b64url_decode(iv_b64)
    ct = b64url_decode(payload_b64)
    if len(ct) <= 16:
        raise ValueError("Ciphertext too short: %d bytes" % len(ct))
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(iv, ct, None)
    return json.loads(plaintext.decode("utf-8"))


# ═══════════════════════════════════════════════════════════════════
#  HTTP CLIENT
# ═══════════════════════════════════════════════════════════════════

def get_session():
    global _curl_cffi_session, _requests_session
    if _curl_cffi_session:
        return _curl_cffi_session, "curl_cffi"
    if _requests_session:
        return _requests_session, "requests"

    if _check_curl_cffi():
        try:
            from curl_cffi.requests import Session
            _curl_cffi_session = Session(impersonate="chrome")
            return _curl_cffi_session, "curl_cffi"
        except Exception as e:
            print("[session] curl_cffi failed to create session: %s" % e)

    import requests
    _requests_session = requests.Session()
    _requests_session.headers.update(API_HEADERS)
    print("[session] Using fallback: requests (no TLS impersonation)")
    return _requests_session, "requests"


def http_post(session, url, json_body=None, extra_headers=None, timeout=20):
    headers = dict(API_HEADERS)
    if extra_headers:
        headers.update(extra_headers)
    kwargs = {"headers": headers, "timeout": timeout}
    if json_body is not None:
        kwargs["json"] = json_body
    try:
        resp = session.post(url, **kwargs)
        ct = resp.headers.get("content-type", "")
        if "json" in ct:
            body = resp.json()
        else:
            body = resp.text[:5000]
        return resp.status_code, body, dict(resp.headers)
    except Exception as e:
        return None, str(e), {}


def http_get(session, url, timeout=20):
    try:
        resp = session.get(url, headers=API_HEADERS, timeout=timeout)
        return resp.status_code, resp.text[:10000], dict(resp.headers)
    except Exception as e:
        return None, str(e), {}


# ═══════════════════════════════════════════════════════════════════
#  MAIN FLOW
# ═══════════════════════════════════════════════════════════════════

def fetch_and_decrypt(code, debug=False):
    t0 = time.time()
    log = []
    dbg = {"code": code, "timestamp": datetime.now(timezone.utc).isoformat()}

    def step(msg):
        elapsed = int((time.time() - t0) * 1000)
        line = "[%dms] %s" % (elapsed, msg)
        log.append(line)
        print(line)

    try:
        session, client_type = get_session()
        dbg["client"] = client_type
        _check_cryptography()

        # Step 0: Warm up homepage
        step("GET homepage for cookies...")
        status, body, _ = http_get(session, BASE_URL, timeout=15)
        if status is None:
            raise Exception("Homepage request failed: %s" % body)
        step("Homepage: HTTP %d" % status)

        # Check CF challenge
        if isinstance(body, str):
            cf_signals = ["challenge-platform", "cf-browser-verification",
                          "Just a moment", "Checking your browser"]
            if any(s in body for s in cf_signals):
                step("Cloudflare JS challenge detected!")
                dbg["cf_challenge"] = True
                dbg["homepage_status"] = status
                raise Exception(
                    "Cloudflare JS challenge detected.\n"
                    "curl_cffi alone cannot solve JS challenges.\n"
                    "Your VPS IP may need: residential IP or Cloudflare solver.\n"
                    "Hit /debug/%s for full diagnosis." % code
                )
            if "cloudflare" in body.lower() and status in (403, 503):
                step("Cloudflare block page (HTTP %d)" % status)
                dbg["cf_blocked"] = True
                raise Exception(
                    "Cloudflare blocked request (HTTP %d). "
                    "Try different VPS IP or residential proxy." % status
                )

        time.sleep(0.3)

        # Step 1: Challenge
        step("POST /api/videos/access/challenge")
        status, body, _ = http_post(
            session, BASE_URL + "/api/videos/access/challenge", json_body={})
        if status is None:
            raise Exception("Challenge failed: %s" % body)
        step("Challenge: HTTP %d" % status)
        if status != 200:
            raise Exception("Challenge returned HTTP %d: %s" % (
                status, json.dumps(body, indent=2)[:300] if isinstance(body, dict) else str(body)[:300]))
        if not isinstance(body, dict):
            raise Exception("Challenge not JSON: %s" % str(body)[:100])

        nonce = body.get("nonce", "")
        dbg["challenge"] = {"status": status, "keys": list(body.keys())}
        if not nonce:
            raise Exception("No nonce in challenge. Keys: %s" % list(body.keys()))
        step("Nonce: %s..." % nonce[:20])

        # Step 2: Sign
        step("Signing nonce ECDSA P-256...")
        private_key, pub_raw, pub_spki = generate_keypair()
        signature = sign_nonce(private_key, nonce)
        step("Signature OK")

        # Step 3: Attest
        step("POST /api/videos/access/attest")
        attest_body = {
            "nonce": nonce,
            "signature": signature,
            "publicKey": pub_raw,
            "fingerprint": FINGERPRINT,
        }
        status, body, _ = http_post(
            session, BASE_URL + "/api/videos/access/attest",
            json_body=attest_body)
        step("Attest: HTTP %d" % status)
        dbg["attest"] = {"status": status}

        if status != 200:
            err = str(body)[:300]
            # Try SPKI format if raw failed
            if isinstance(body, dict):
                dbg["attest"]["response"] = body
                err = json.dumps(body, indent=2)[:300]
            if status in (400, 401, 403, 422):
                step("Retrying with SPKI key format...")
                attest_body["publicKey"] = pub_spki
                s2, b2, _ = http_post(
                    session, BASE_URL + "/api/videos/access/attest",
                    json_body=attest_body)
                step("Attest retry: HTTP %d" % s2)
                if s2 == 200:
                    status, body = s2, b2
                else:
                    dbg["attest"]["retry_status"] = s2
                    dbg["attest"]["retry_body"] = b2
            if status != 200:
                raise Exception("Attest returned HTTP %d: %s" % (status, err))

        if not isinstance(body, dict):
            raise Exception("Attest not JSON: %s" % str(body)[:100])

        token = body.get("token", "")
        dbg["attest"]["keys"] = list(body.keys())
        dbg["attest"]["token_preview"] = (token[:30] + "...") if token else "(empty)"
        if not token:
            raise Exception("No token in attest. Keys: %s. Body: %s" % (
                list(body.keys()), json.dumps(body, indent=2)[:500]))
        step("Token: %s..." % token[:25])

        # Step 4: Playback
        step("POST /api/videos/%s/embed/playback" % code)
        status, body, _ = http_post(
            session, BASE_URL + "/api/videos/%s/embed/playback" % code,
            json_body={"token": token},
            extra_headers={"X-Embed-Parent": BASE_URL})
        step("Playback: HTTP %d" % status)
        dbg["playback"] = {"status": status}

        if status != 200:
            err = json.dumps(body, indent=2)[:300] if isinstance(body, dict) else str(body)[:300]
            if isinstance(body, dict):
                dbg["playback"]["response"] = body
            raise Exception("Playback returned HTTP %d: %s" % (status, err))

        if not isinstance(body, dict):
            raise Exception("Playback not JSON: %s" % str(body)[:100])

        encrypted = body.get("playback", body)
        dbg["playback"]["encrypted_keys"] = list(encrypted.keys())

        if not encrypted.get("key_parts") or not encrypted.get("iv") or not encrypted.get("payload"):
            dbg["playback"]["full_response_keys"] = list(body.keys())
            dbg["playback"]["full_response_preview"] = {k: str(v)[:80] for k, v in body.items() if k != "payload"}
            raise Exception(
                "No encrypted payload. Body keys: %s. Nested keys: %s. "
                "Share debug output." % (list(body.keys()), list(encrypted.keys())))

        # Step 5: Decrypt
        step("Decrypting AES-256-GCM...")
        decrypted = decrypt_payload(encrypted)
        sources = decrypted.get("sources", [])
        step("OK! %d source(s)" % len(sources))
        for i, src in enumerate(sources):
            q = src.get("quality") or src.get("label") or src.get("height", "")
            step("  [%d] %s | %s" % (i, q, src.get("url", "")[:70]))

        ms = int((time.time() - t0) * 1000)
        step("Total: %dms" % ms)
        dbg["totalTimeMs"] = ms
        dbg["success"] = True
        return {"success": True, "data": decrypted, "debug": dbg if debug else None}

    except Exception as e:
        ms = int((time.time() - t0) * 1000)
        step("ERROR: %s" % e)
        dbg["totalTimeMs"] = ms
        dbg["success"] = False
        dbg["error"] = str(e)
        dbg["error_type"] = type(e).__name__
        dbg["traceback"] = traceback.format_exc()
        return {"success": False, "error": str(e), "debug": dbg if debug else None}


# ═══════════════════════════════════════════════════════════════════
#  FLASK APP - created here so server ALWAYS starts
# ═══════════════════════════════════════════════════════════════════

app, jsonify, flask_req = _get_flask()


@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "version": "v3.1",
        "curl_cffi": _check_curl_cffi(),
        "cryptography": _check_cryptography(),
        "pid": os.getpid(),
        "time": datetime.now(timezone.utc).isoformat(),
    })


@app.route("/e/<code>")
def ep_decrypt(code):
    print("\n[GET /e/%s]" % code)
    r = fetch_and_decrypt(code, False)
    return jsonify(r["data"]) if r["success"] else jsonify({"error": r["error"]}), 502


@app.route("/d/<code>")
def ep_decrypt_d(code):
    print("\n[GET /d/%s]" % code)
    r = fetch_and_decrypt(code, False)
    return jsonify(r["data"]) if r["success"] else jsonify({"error": r["error"]}), 502


@app.route("/debug/<code>")
def ep_debug(code):
    print("\n[GET /debug/%s]" % code)
    r = fetch_and_decrypt(code, True)
    out = {"success": r["success"], "debug": r.get("debug", {})}
    if r["success"]:
        out["decrypted"] = r["data"]
    if not r["success"]:
        out["error"] = r["error"]
        out["note"] = "Share this FULL response for analysis"
    return jsonify(out), 200 if r["success"] else 502


@app.route("/decrypt", methods=["POST"])
def ep_manual():
    try:
        data = flask_req.get_json(force=True)
        encrypted = data.get("playback", data) if data else None
        if not encrypted or not encrypted.get("key_parts"):
            return jsonify({"error": "Need JSON with key_parts, iv, payload"}), 400
        return jsonify(decrypt_payload(encrypted))
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/proxy")
def ep_proxy():
    from urllib.parse import urlparse
    import urllib.request
    target = flask_req.args.get("url")
    if not target:
        return jsonify({"error": "Missing ?url="}), 400
    p = urlparse(target)
    if p.scheme not in ("http", "https"):
        return jsonify({"error": "Only http/https"}), 400
    try:
        req = urllib.request.Request(target, headers={
            "User-Agent": UA,
            "Accept": "*/*, video/mp4",
            "Referer": BASE_URL + "/",
            "Origin": BASE_URL,
        })
        resp = urllib.request.urlopen(req, timeout=15)
        out = app.response_class(resp.read(), status=resp.status)
        out.headers["Access-Control-Allow-Origin"] = "*"
        ct = resp.headers.get("content-type")
        if ct:
            out.headers["Content-Type"] = ct
        return out
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@app.route("/rewrite")
def ep_rewrite():
    import urllib.request
    from urllib.parse import urlparse, quote
    url = flask_req.args.get("url")
    if not url:
        return jsonify({"error": "Missing ?url="}), 400
    base = flask_req.scheme + "://" + flask_req.host
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Referer": BASE_URL + "/"})
        resp = urllib.request.urlopen(req, timeout=15)
        text = resp.read().decode("utf-8", errors="replace")
        base_url = url[:url.rfind("/") + 1]
        lines = []
        for line in text.split("\n"):
            t = line.strip()
            if not t or t.startswith("#"):
                lines.append(line)
            else:
                full = t if t.startswith("http") else base_url + t
                lines.append(base + "/proxy?url=" + quote(full, safe=""))
        out = app.response_class("\n".join(lines), content_type="application/vnd.apple.mpegurl")
        out.headers["Access-Control-Allow-Origin"] = "*"
        return out
    except Exception as e:
        return jsonify({"error": str(e)}), 502


# ═══════════════════════════════════════════════════════════════════
#  START
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print()
    print("=" * 55)
    print("  VPS Video Decryptor v3.1 - Crash-proof")
    print("=" * 55)
    print("  curl_cffi:   %s" % ("YES" if _check_curl_cffi() else "NO (fallback mode)"))
    print("  cryptography: %s" % ("YES" if _check_cryptography() else "NO (decrypt will fail)"))
    print("  Port:        %d" % PORT)
    print()
    print("  Routes:")
    print("    /e/{code}     decrypt -> JSON")
    print("    /d/{code}     decrypt -> JSON (alias)")
    print("    /debug/{code} full debug output")
    print("    /decrypt      POST raw payload")
    print("    /proxy?url=   proxy .ts segments")
    print("    /rewrite?url= rewrite m3u8")
    print("    /health       server status")
    print()
    if not _check_curl_cffi():
        print("  WARNING: curl_cffi not installed!")
        print("  Cloudflare will likely block requests.")
        print("  Fix: pip install curl_cffi")
        print()
    print("=" * 55)
    sys.stdout.flush()

    app.run(host="0.0.0.0", port=PORT, debug=False, use_reloader=False)
