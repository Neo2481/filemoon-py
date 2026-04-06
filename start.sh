#!/bin/bash
# start.sh — Auto install + run
set -e
echo "=== Video Decryptor v4 ==="

PYTHON=""
command -v python3 &>/dev/null && PYTHON="python3" || \
command -v python &>/dev/null && PYTHON="python"
[ -z "$PYTHON" ] && { echo "ERROR: No Python. sudo apt install python3 python3-pip"; exit 1; }
echo "Python: $PYTHON ($($PYTHON --version 2>&1))"

# pip
$PYTHON -m pip --version &>/dev/null 2>&1 || \
    ($PYTHON -m ensurepip --default-pip 2>/dev/null || curl -sS https://bootstrap.pypa.io/get-pip.py | $PYTHON)

# install deps
echo "Installing..."
$PYTHON -m pip install --quiet flask cryptography requests 2>/dev/null && echo "  flask, cryptography, requests: OK"

$PYTHON -c "from curl_cffi.requests import Session" 2>/dev/null && echo "  curl_cffi: OK" || {
    echo "  Installing curl_cffi..."
    $PYTHON -m pip install --quiet curl_cffi 2>/dev/null && echo "  curl_cffi: OK" || {
        $PYTHON -m pip install --quiet --no-build-isolation curl_cffi 2>/dev/null && echo "  curl_cffi: OK" || {
            echo "  curl_cffi: FAILED (need: build-essential libcurl4-openssl-dev)"
        }
    }
}

echo ""
echo "=== Starting ==="
exec $PYTHON server.py
