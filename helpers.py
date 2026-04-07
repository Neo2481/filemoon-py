"""
helpers.py — Shared config, crypto, and HTTP client with proxy support.

If this file fails to import, NOTHING works.
Check: pip install cryptography requests curl_cffi
"""

import os, json, base64, hashlib, time, uuid

# ═══════════════════════════════════════════
#  CONFIG
# ═══════════════════════════════════════════

BASE_URL = "https://f75s.com"
UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)

# ═══════════════════════════════════════════
#  PROXY CONFIG — Webshare rotating residential proxy
# ═══════════════════════════════════════════

PROXY_ENABLED = True
PROXY_HOST = "p.webshare.io"
PROXY_PORT = 80
PROXY_USER = "qijlkvsz-rotate"
PROXY_PASS = "viryx2zv5njj"

# Sticky session: same IP for ALL requests in this server session
# Webshare format: replace "-rotate" with "_session-<id>"
# Wrong: qijlkvsz-rotate_session-abc (auth fails with 407)
# Right: qijlkvsz_session-abc (keeps same exit IP for ~10 min)
_proxy_session = uuid.uuid4().hex[:8]
PROXY_USER_STICKY = "qijlkvsz_session-%s" % _proxy_session
PROXY_URL = "http://%s:%s@%s:%d" % (PROXY_USER_STICKY, PROXY_PASS, PROXY_HOST, PROXY_PORT)
PROXIES = {
    "http": PROXY_URL,
    "https": PROXY_URL,
}
print("[proxy] Sticky session user: %s" % PROXY_USER_STICKY)
print("[proxy] Same exit IP will be used for all requests")

# ═══════════════════════════════════════════
#  HEADERS
# ═══════════════════════════════════════════

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


# ═══════════════════════════════════════════
#  BROWSER CLIENT FINGERPRINT
# ═══════════════════════════════════════════

def make_client_fingerprint():
    """
    Build the 'client' object matching what the real browser sends
    to /api/videos/access/attest.
    """
    return {
        "user_agent": UA,
        "architecture": "x86",
        "bitness": "64",
        "platform": "Windows",
        "platform_version": "10.0.0",
        "model": "",
        "ua_full_version": "131.0.0.0",
        "brand_full_versions": [
            {"brand": "Chromium", "version": "131.0.0.0"},
            {"brand": "Not-A.Brand", "version": "24.0.0.0"},
            {"brand": "Google Chrome", "version": "131.0.0.0"},
        ],
        "pixel_ratio": 1,
        "screen_width": 1920,
        "screen_height": 1080,
        "color_depth": 32,
        "languages": ["en-US", "en"],
        "timezone": "Asia/Calcutta",
        "hardware_concurrency": 8,
        "device_memory": 8,
        "touch_points": 0,
        "webgl_vendor": "Google Inc. (AMD)",
        "webgl_renderer": (
            "ANGLE (AMD, AMD Radeon(TM) Vega 8 Graphics (0x000015D8) "
            "Direct3D11 vs_5_0 ps_5_0, D3D11)"
        ),
        "canvas_hash": hashlib.sha256(b"canvas_fp_v1").hexdigest(),
        "audio_hash": hashlib.sha256(b"audio_fp_v1").hexdigest(),
        "pointer_type": "fine,hover",
        "extra": {
            "vendor": "Google Inc.",
            "appVersion": UA,
        },
    }


def make_storage(viewer_id, device_id):
    """Build the 'storage' object."""
    return {
        "cookie": viewer_id,
        "local_storage": viewer_id,
        "indexed_db": "%s:%s" % (viewer_id, device_id),
        "cache_storage": "%s:%s" % (viewer_id, device_id),
    }


def make_attributes():
    """Build the 'attributes' object."""
    return {
        "entropy": "high",
    }


# ═══════════════════════════════════════════
#  SESSION STORE
# ═══════════════════════════════════════════

_sessions = {}


def get_session(sid):
    """Get or create user session dict."""
    if sid not in _sessions:
        vid = uuid.uuid4().hex
        did = uuid.uuid4().hex
        _sessions[sid] = {
            "id": sid,
            "viewer_id": vid,
            "device_id": did,
            "challenge_id": None,
            "nonce": None,
            "token": None,
            "code": None,
            "private_key": None,
            "pub_jwk": None,
            "pub_raw": None,
            "pub_spki": None,
            "playback_body": None,
            "server_viewer_id": None,
            "server_device_id": None,
            "confidence": None,
        }
    return _sessions[sid]


# ═══════════════════════════════════════════
#  HTTP CLIENT (with proxy)
# ═══════════════════════════════════════════

_http_session = None
_http_type = None


def get_http_client():
    """Get HTTP session with proxy. Returns (session, type_string)."""
    global _http_session, _http_type
    if _http_session is not None:
        return _http_session, _http_type

    proxy_kw = {"proxies": PROXIES} if PROXY_ENABLED else {}

    # Try curl_cffi first (Chrome TLS fingerprint)
    try:
        from curl_cffi.requests import Session
        _http_session = Session(impersonate="chrome", **proxy_kw)
        _http_type = "curl_cffi"
        if PROXY_ENABLED:
            print("[http] curl_cffi + Webshare proxy (%s)" % PROXY_HOST)
        else:
            print("[http] Using curl_cffi (NO proxy)")
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
        if PROXY_ENABLED:
            _http_session.proxies.update(PROXIES)
            print("[http] requests + Webshare proxy (%s)" % PROXY_HOST)
        else:
            print("[http] Using requests (NO proxy, NO TLS impersonation)")
        _http_type = "requests"
        return _http_session, _http_type
    except ImportError:
        print("[http] requests not available either!")
        return None, "none"


def check_my_ip():
    """Check what IP the proxy is using. Returns IP string or error."""
    sess, _ = get_http_client()
    if sess is None:
        return "no client"
    try:
        r = sess.get("https://api.ipify.org?format=json", timeout=10)
        if r.status_code == 200:
            return r.json().get("ip", "unknown")
        return "status %d" % r.status_code
    except Exception as e:
        return str(e)


def http_get(url, timeout=30):
    """GET request. Returns (status_code, text, headers_dict)."""
    sess, _ = get_http_client()
    if sess is None:
        return None, "No HTTP client available", {}
    try:
        r = sess.get(url, headers=API_HEADERS, timeout=timeout)
        return r.status_code, r.text[:10000], dict(r.headers)
    except Exception as e:
        return None, str(e), {}


def set_cookies(cookie_dict):
    """Set cookies on the shared HTTP session."""
    sess, _ = get_http_client()
    if sess is None:
        return
    for k, v in cookie_dict.items():
        sess.cookies.set(k, v, domain="f75s.com")
    print("[http] Cookies set: %s" % list(cookie_dict.keys()))


def http_post(url, body=None, extra_headers=None, timeout=30):
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
    Returns (private_key, pub_jwk_dict, pub_raw_b64url, pub_spki_b64url).
    """
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization

    pk = ec.generate_private_key(ec.SECP256R1())

    # Uncompressed point: 04 || x(32) || y(32)
    raw = pk.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    x_bytes = raw[1:33]   # skip 0x04 prefix
    y_bytes = raw[33:65]

    # JWK
    jwk = {
        "crv": "P-256",
        "ext": True,
        "key_ops": ["verify"],
        "kty": "EC",
        "x": b64url_encode(x_bytes),
        "y": b64url_encode(y_bytes),
    }

    # SPKI DER (for reference)
    spki = pk.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return pk, jwk, b64url_encode(raw), b64url_encode(spki)


def sign_nonce(private_key, nonce):
    """
    Sign nonce with ECDSA P-256 SHA-256.
    Returns base64url raw signature (r || s, 64 bytes).
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
