"""
step5_decrypt.py

Decrypt AES-256-GCM encrypted payload → JSON with video sources.

If this fails:
  - "Key is X bytes" = key_parts format wrong
  - "Ciphertext too short" = payload truncated
  - "InvalidTag" = wrong key, wrong IV, or tampered data

Needs: pip install cryptography
"""

import time
from helpers import decrypt_payload, get_session


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

    # Get the encrypted payload (might be nested under "playback")
    enc = body.get("playback", body)

    result = {
        "step": "5-decrypt",
        "encryptedKeys": list(enc.keys()) if isinstance(enc, dict) else "N/A",
    }

    # Try decryption
    try:
        decrypted = decrypt_payload(enc)
        ms = int((time.time() - t0) * 1000)

        sources = decrypted.get("sources", [])
        subtitles = decrypted.get("subtitles", [])

        result["success"] = True
        result["timeMs"] = ms
        result["sourceCount"] = len(sources)
        result["subtitleCount"] = len(subtitles)

        # Extract URLs
        urls = []
        for i, src in enumerate(sources):
            urls.append({
                "index": i,
                "quality": src.get("quality") or src.get("label") or src.get("height", ""),
                "mimeType": src.get("mimeType", ""),
                "url": src.get("url", ""),
            })
        result["sources"] = urls
        result["fullDecrypted"] = decrypted

    except ImportError:
        ms = int((time.time() - t0) * 1000)
        result["success"] = False
        result["timeMs"] = ms
        result["error"] = "cryptography not installed"
        result["fix"] = "pip install cryptography"

    except Exception as e:
        ms = int((time.time() - t0) * 1000)
        result["success"] = False
        result["timeMs"] = ms
        result["error"] = str(e)
        result["errorType"] = type(e).__name__
        result["keyPartsCount"] = len(enc.get("key_parts", [])) if isinstance(enc, dict) else 0
        result["ivLength"] = len(str(enc.get("iv", ""))) if isinstance(enc, dict) else 0
        result["payloadLength"] = len(str(enc.get("payload", ""))) if isinstance(enc, dict) else 0

    return result
