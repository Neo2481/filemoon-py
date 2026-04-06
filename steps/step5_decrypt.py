"""
step5_decrypt.py

Decrypt AES-256-GCM encrypted payload -> JSON with video sources.

The playback response has:
  playback.key_parts  -> concat to form AES-256 key (32 bytes)
  playback.iv         -> nonce for AES-GCM
  playback.payload    -> ciphertext (first decryption)
  playback.decrypt_keys -> {edge_1, edge_2, legacy_fallback} (extra keys)
  playback.iv2        -> nonce for second payload
  playback.payload2   -> second ciphertext

Needs: pip install cryptography
"""

import time
from helpers import b64url_decode, b64url_encode, decrypt_payload, get_session


def try_decrypt(enc, label=""):
    """Try to decrypt with standard key_parts. Returns (ok, result_or_error)."""
    try:
        decrypted = decrypt_payload(enc)
        return True, decrypted
    except Exception as e:
        return False, "%s decryption failed: %s" % (label, e)


def run(sid):
    """
    Step 5: Decrypt the encrypted payload from step 4.
    Returns dict with sources, subtitles, timing.
    """
    sess = get_session(sid)
    t0 = time.time()

    # Validate prerequisites
    body = sess.get("playback_body")
    if not body:
        return {
            "step": "5-decrypt",
            "error": "No playback data. Run step 4 first.",
            "fix": "Click step 4 button first",
        }
    if not isinstance(body, dict):
        return {
            "step": "5-decrypt",
            "error": "Playback response was not JSON",
            "rawType": type(body).__name__,
            "rawPreview": str(body)[:200],
        }

    result = {"step": "5-decrypt"}

    # Get the encrypted payload (nested under "playback")
    enc = body.get("playback", body)
    result["encryptedKeys"] = list(enc.keys()) if isinstance(enc, dict) else "N/A"

    # Show what we have
    if isinstance(enc, dict):
        result["hasKeyParts"] = bool(enc.get("key_parts"))
        result["hasIv"] = bool(enc.get("iv"))
        result["hasPayload"] = bool(enc.get("payload"))
        result["hasDecryptKeys"] = bool(enc.get("decrypt_keys"))
        result["hasIv2"] = bool(enc.get("iv2"))
        result["hasPayload2"] = bool(enc.get("payload2"))

        # Show key_parts info
        key_parts = enc.get("key_parts", [])
        if key_parts:
            key = b"".join(b64url_decode(p) for p in key_parts)
            result["keyLength"] = len(key)
            result["keyPartsCount"] = len(key_parts)

        # Show decrypt_keys if present
        dk = enc.get("decrypt_keys", {})
        if dk:
            result["decryptKeysAvailable"] = list(dk.keys())

    # ── Try main payload decryption ──
    ok, dec_result = try_decrypt(enc, "Main payload")
    if ok:
        ms = int((time.time() - t0) * 1000)
        sources = dec_result.get("sources", [])
        subtitles = dec_result.get("subtitles", [])

        result["success"] = True
        result["decryptedWith"] = "key_parts"
        result["timeMs"] = ms
        result["sourceCount"] = len(sources)
        result["subtitleCount"] = len(subtitles)

        urls = []
        for i, src in enumerate(sources):
            urls.append({
                "index": i,
                "quality": src.get("quality") or src.get("label") or src.get("height", ""),
                "mimeType": src.get("mimeType", ""),
                "url": src.get("url", ""),
            })
        result["sources"] = urls
        result["fullDecrypted"] = dec_result
        return result

    # Main failed, show error info
    result["mainDecryptError"] = dec_result

    # ── Try payload2 with iv2 ──
    if isinstance(enc, dict) and enc.get("iv2") and enc.get("payload2"):
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            key_parts = enc.get("key_parts", [])
            key = b"".join(b64url_decode(p) for p in key_parts)
            iv2 = b64url_decode(enc["iv2"])
            ct2 = b64url_decode(enc["payload2"])
            plaintext2 = AESGCM(key).decrypt(iv2, ct2, None)
            import json
            dec2 = json.loads(plaintext2.decode("utf-8"))
            ms = int((time.time() - t0) * 1000)
            result["success"] = True
            result["decryptedWith"] = "payload2+iv2"
            result["timeMs"] = ms
            result["fullDecrypted"] = dec2
            return result
        except Exception as e:
            result["payload2Error"] = str(e)

    # ── Try decrypt_keys ──
    if isinstance(enc, dict) and enc.get("decrypt_keys"):
        dk = enc["decrypt_keys"]
        result["decryptKeysAttempt"] = {}
        for key_name, key_b64 in dk.items():
            try:
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                iv = b64url_decode(enc.get("iv", ""))
                ct = b64url_decode(enc.get("payload", ""))
                key_bytes = b64url_decode(key_b64)
                plaintext = AESGCM(key_bytes).decrypt(iv, ct, None)
                import json
                dec = json.loads(plaintext.decode("utf-8"))
                result["success"] = True
                result["decryptedWith"] = "decrypt_keys.%s" % key_name
                result["fullDecrypted"] = dec
                return result
            except Exception as e:
                result["decryptKeysAttempt"][key_name] = str(e)

    # All decryption attempts failed
    ms = int((time.time() - t0) * 1000)
    result["success"] = False
    result["timeMs"] = ms
    result["error"] = "All decryption methods failed"
    result["keyPartsCount"] = len(enc.get("key_parts", [])) if isinstance(enc, dict) else 0
    result["ivLength"] = len(str(enc.get("iv", ""))) if isinstance(enc, dict) else 0
    result["payloadLength"] = len(str(enc.get("payload", ""))) if isinstance(enc, dict) else 0

    return result
