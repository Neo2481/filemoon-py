"""
helpers.py — Shared config, crypto, and HTTP client.

If this file fails to import, NOTHING works.
Check: pip install cryptography requests curl_cffi
"""

import os, json, base64, hashlib, time

# ═══════════════════════════════════════════
#  CONFIG
# ═══════════════════════════════════════════

BASE_URL = "https://f75s.com"
UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)

API_HEADERS = {
    "User-Agent": UA,
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
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

FINGERPRINT = {
    "canvas": hashlib.md5(b"win10_chrome131").hexdigest(),
    "webglVendor": "Google Inc. (NVIDIA)",
    "webglRenderer": (
        "ANGLE (NVIDIA, NVIDIA GeForce GTX 1660 Ti "
        "Direct3D11 vs_5_0 ps_5_0, D3D11)"
    ),
    "audioHash": hashlib.md5(b"audioctx").hexdigest(),
    "screenWidth": 1920, "screenHeight": 1080, "colorDepth": 24,
    "pixelRatio": 1.0,
    "timezone": "America/New_York", "timezoneOffset": -300,
    "language": "en-US", "languages": ["en-US", "en"],
    "platform": "Win32", "deviceMemory": 8, "hardwareConcurrency": 12,
    "maxTouchPoints": 0, "touchSupport": False, "pdfViewerEnabled": True,
    "webglVersion": "WebGL 2.0",
    "webglShadingLanguageVersion": "WebGL GLSL ES 3.00",
    "cookiesEnabled": True, "doNotTrack": None,
    "plugins": (
        "PDF Viewer,Chrome PDF Viewer,Chromium PDF Viewer,"
        "Microsoft Edge PDF Viewer,WebKit built-in PDF"
    ),
    "storageEstimate": 1073741824,
    "connectionType": "4g", "connectionDownlink": 10,
    "connectionRtt": 50, "connectionSaveData": False,
}


# ═══════════════════════════════════════════
#  SESSION STORE
# ═══════════════════════════════════════════

_sessions = {}


def get_session(sid):
    """Get or create user session dict."""
    if sid not in _sessions:
        _sessions[sid] = {
            "id": sid,
            "nonce": None,
            "token": None,
            "code": None,
            "private_key": None,
            "pub_raw": None,
            "pub_spki": None,
            "playback_body": None,
        }
    return _sessions[sid]


# ═══════════════════════════════════════════
#  HTTP CLIENT
# ═══════════════════════════════════════════

_http_session = None
_http_type = None


def get_http_client():
    """Get HTTP session. Returns (session, type_string)."""
    global _http_session, _http_type
    if _http_session is not None:
        return _http_session, _http_type

    # Try curl_cffi first (Chrome TLS fingerprint)
    try:
        from curl_cffi.requests import Session
        _http_session = Session(impersonate="chrome")
        _http_type = "curl_cffi"
        print("[http] Using curl_cffi (Chrome TLS impersonation)")
        return _http_session, _http_type
    except ImportError:
        print("[http] curl_cffi not available, trying requests...")
    except Exception as e:
        print("[http] curl_cffi error: %s" % e)

    # Fallback: plain requests
    try:
        import requests
        _http_session = requests.Session()
        _http_session.headers.update(API_HEADERS)
        _http_type = "requests"
        print("[http] Using requests (NO TLS impersonation)")
        return _http_session, _http_type
    except ImportError:
        print("[http] requests not available either!")
        return None, "none"


def http_get(url, timeout=20):
    """GET request. Returns (status_code, text, headers_dict)."""
    sess, _ = get_http_client()
    if sess is None:
        return None, "No HTTP client available", {}
    try:
        r = sess.get(url, headers=API_HEADERS, timeout=timeout)
        return r.status_code, r.text[:10000], dict(r.headers)
    except Exception as e:
        return None, str(e), {}


def http_post(url, body=None, extra_headers=None, timeout=20):
    """POST request. Returns (status_code, body, headers_dict)."""
    sess, _ = get_http_client()
    if sess is None:
        return None, "No HTTP client available", {}
    h = dict(API_HEADERS)
    if extra_headers:
        h.update(extra_headers)
    kw = {"headers": h, "timeout": timeout}
    if body is not None:
        kw["json"] = body
    try:
        r = sess.post(url, **kw)
        ct = r.headers.get("content-type", "")
        if "json" in ct:
            return r.status_code, r.json(), dict(r.headers)
        return r.status_code, r.text[:5000], dict(r.headers)
    except Exception as e:
        return None, str(e), {}


# ═══════════════════════════════════════════
#  CRYPTO HELPERS
# ═══════════════════════════════════════════

def b64url_decode(s):
    """Base64url decode."""
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def b64url_encode(data):
    """Base64url encode."""
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def generate_keypair():
    """
    Generate ECDSA P-256 key pair.
    Returns (private_key, pub_raw_b64url, pub_spki_b64url).
    Needs: pip install cryptography
    """
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    pk = ec.generate_private_key(ec.SECP256R1())
    raw = pk.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    spki = pk.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pk, b64url_encode(raw), b64url_encode(spki)


def sign_nonce(private_key, nonce):
    """
    Sign nonce with ECDSA P-256 SHA-256.
    Returns base64url raw signature (r || s, 64 bytes).
    Needs: pip install cryptography
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    nb = nonce.encode("utf-8") if isinstance(nonce, str) else nonce
    der_sig = private_key.sign(nb, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return b64url_encode(raw)


def decrypt_payload(encrypted):
    """
    Decrypt AES-256-GCM payload.
    Key = concat(base64url_decode(part) for each key_parts[]).
    Needs: pip install cryptography
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    parts = encrypted.get("key_parts", [])
    iv_b64 = encrypted.get("iv", "")
    payload_b64 = encrypted.get("payload", "")
    if not parts or not iv_b64 or not payload_b64:
        raise ValueError("Missing key_parts, iv, or payload")
    key = b"".join(b64url_decode(p) for p in parts)
    if len(key) != 32:
        raise ValueError("Key is %d bytes, expected 32" % len(key))
    iv = b64url_decode(iv_b64)
    ct = b64url_decode(payload_b64)
    if len(ct) <= 16:
        raise ValueError("Ciphertext too short: %d bytes" % len(ct))
    plaintext = AESGCM(key).decrypt(iv, ct, None)
    return json.loads(plaintext.decode("utf-8"))
