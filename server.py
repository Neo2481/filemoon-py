"""
server.py — Flask app with step-by-step debug UI.

Each step is a separate file in /steps/ folder:
  steps/step1_homepage.py  - GET homepage (CF cookies)
  steps/step2_challenge.py - POST challenge (get nonce)
  steps/step3_attest.py    - POST attest (sign nonce, get token)
  steps/step4_playback.py  - POST playback (get encrypted data)
  steps/step5_decrypt.py   - Decrypt AES-256-GCM

Shared code:
  helpers.py               - Config, HTTP client, crypto, session store

If server crashes, check which file is the problem.
"""

import os
import sys
import uuid
import traceback

from flask import Flask, jsonify, request as flask_req

# ═══════════════════════════════════════════
#  APP
# ═══════════════════════════════════════════

app = Flask(__name__)
PORT = int(os.environ.get("PORT", 3000))

# ═══════════════════════════════════════════
#  IMPORT STEP FILES (lazy, with error handling)
# ═══════════════════════════════════════════

_step_modules = {}

def _import_step(name, path):
    """Import a step module, cache it. Returns module or error string."""
    if name in _step_modules:
        return _step_modules[name]
    try:
        mod = __import__(path, fromlist=["run"])
        _step_modules[name] = mod
        return mod
    except Exception as e:
        err = "Import %s failed: %s" % (path, e)
        _step_modules[name] = err
        return err


# ═══════════════════════════════════════════
#  FRONTEND
# ═══════════════════════════════════════════

@app.route("/")
def index():
    return HTML_PAGE, 200, {"Content-Type": "text/html; charset=utf-8"}


# ═══════════════════════════════════════════
#  HEALTH / STATUS
# ═══════════════════════════════════════════

@app.route("/health")
def health():
    # Check what's importable
    checks = {}
    for name in ["helpers", "step1", "step2", "step3", "step4", "step5"]:
        path = {
            "helpers": "helpers",
            "step1": "steps.step1_homepage",
            "step2": "steps.step2_challenge",
            "step3": "steps.step3_attest",
            "step4": "steps.step4_playback",
            "step5": "steps.step5_decrypt",
        }[name]
        try:
            __import__(path)
            checks[name] = "OK"
        except Exception as e:
            checks[name] = "ERROR: %s" % e

    # Check libraries
    libs = {}
    for lib in ["flask", "cryptography", "requests", "curl_cffi"]:
        try:
            __import__(lib)
            libs[lib] = True
        except ImportError:
            libs[lib] = False

    return jsonify({
        "status": "ok",
        "version": "v4-modular",
        "pid": os.getpid(),
        "libraries": libs,
        "modules": checks,
    })


# ═══════════════════════════════════════════
#  SESSION API
# ═══════════════════════════════════════════

@app.route("/api/new")
def api_new():
    sid = uuid.uuid4().hex[:12]
    return jsonify({"sessionId": sid})


# ═══════════════════════════════════════════
#  STEP-BY-STEP API ENDPOINTS
# ═══════════════════════════════════════════

@app.route("/api/step1-homepage", methods=["POST"])
def step1():
    try:
        from steps.step1_homepage import run
        data = flask_req.get_json(silent=True) or {}
        sid = data.get("sessionId", "")
        result = run(sid)
        return jsonify(result)
    except Exception as e:
        return jsonify({
            "step": "1-homepage",
            "fileError": True,
            "error": str(e),
            "traceback": traceback.format_exc(),
            "hint": "Check steps/step1_homepage.py and helpers.py",
        }), 500


@app.route("/api/step2-challenge", methods=["POST"])
def step2():
    import time; time.sleep(1)  # delay to mimic browser
    try:
        from steps.step2_challenge import run
        data = flask_req.get_json(silent=True) or {}
        sid = data.get("sessionId", "")
        result = run(sid)
        return jsonify(result)
    except Exception as e:
        return jsonify({
            "step": "2-challenge",
            "fileError": True,
            "error": str(e),
            "traceback": traceback.format_exc(),
            "hint": "Check steps/step2_challenge.py and helpers.py",
        }), 500


@app.route("/api/step3-attest", methods=["POST"])
def step3():
    import time; time.sleep(2)  # delay to mimic browser
    try:
        from steps.step3_attest import run
        data = flask_req.get_json(silent=True) or {}
        sid = data.get("sessionId", "")
        result = run(sid)
        return jsonify(result)
    except Exception as e:
        return jsonify({
            "step": "3-attest",
            "fileError": True,
            "error": str(e),
            "traceback": traceback.format_exc(),
            "hint": "Check steps/step3_attest.py and helpers.py",
        }), 500


@app.route("/api/step4-playback", methods=["POST"])
def step4():
    import time; time.sleep(2)  # delay to mimic browser
    try:
        from steps.step4_playback import run
        data = flask_req.get_json(silent=True) or {}
        sid = data.get("sessionId", "")
        code = data.get("code", "")
        result = run(sid, code)
        return jsonify(result)
    except Exception as e:
        return jsonify({
            "step": "4-playback",
            "fileError": True,
            "error": str(e),
            "traceback": traceback.format_exc(),
            "hint": "Check steps/step4_playback.py and helpers.py",
        }), 500


@app.route("/api/step5-decrypt", methods=["POST"])
def step5():
    try:
        from steps.step5_decrypt import run
        data = flask_req.get_json(silent=True) or {}
        sid = data.get("sessionId", "")
        result = run(sid)
        return jsonify(result)
    except Exception as e:
        return jsonify({
            "step": "5-decrypt",
            "fileError": True,
            "error": str(e),
            "traceback": traceback.format_exc(),
            "hint": "Check steps/step5_decrypt.py and helpers.py",
        }), 500


# ═══════════════════════════════════════════
#  RUN ALL (convenience)
# ═══════════════════════════════════════════

@app.route("/api/all/<code>", methods=["POST"])
def api_all(code):
    results = []
    try:
        from steps.step1_homepage import run as r1
        from steps.step2_challenge import run as r2
        from steps.step3_attest import run as r3
        from steps.step4_playback import run as r4
        from steps.step5_decrypt import run as r5
    except ImportError as e:
        return jsonify({"error": "Import failed: %s" % e, "hint": "Check /health endpoint"}), 500

    data = flask_req.get_json(silent=True) or {}
    sid = data.get("sessionId", "") or uuid.uuid4().hex[:12]

    try:
        # Step 1
        r = r1(sid)
        results.append(r)
        if r.get("cfChallenge") or r.get("cfBlocked"):
            return jsonify({"success": False, "failedAt": 1, "results": results})

        # Step 2
        r = r2(sid)
        results.append(r)
        if not r.get("nonce"):
            return jsonify({"success": False, "failedAt": 2, "results": results})

        # Step 3
        r = r3(sid)
        results.append(r)
        if not r.get("token"):
            return jsonify({"success": False, "failedAt": 3, "results": results})

        # Step 4
        r = r4(sid, code)
        results.append(r)
        if not r.get("canDecrypt"):
            return jsonify({"success": False, "failedAt": 4, "results": results})

        # Step 5
        r = r5(sid)
        results.append(r)
        return jsonify({
            "success": r.get("success", False),
            "results": results,
            "data": r.get("fullDecrypted") if r.get("success") else None,
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "results": results,
            "error": str(e),
            "traceback": traceback.format_exc(),
        }), 500


# ═══════════════════════════════════════════
#  HTML PAGE
# ═══════════════════════════════════════════

HTML_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Decryptor v4 — Step Debug</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0f1117;color:#e1e4e8;min-height:100vh}
.hdr{background:#161b22;border-bottom:1px solid #30363d;padding:14px 20px;display:flex;align-items:center;gap:12px}
.hdr h1{font-size:17px;font-weight:600}
.hdr .b{background:#238636;color:#fff;font-size:10px;padding:2px 7px;border-radius:10px;font-weight:700}
.wrap{max-width:880px;margin:0 auto;padding:20px}
.row{display:flex;gap:8px;margin-bottom:16px}
.row input{flex:1;background:#161b22;border:1px solid #30363d;color:#e1e4e8;padding:9px 13px;border-radius:7px;font-size:14px;outline:none}
.row input:focus{border-color:#58a6ff}
.btn{padding:9px 16px;border:1px solid #30363d;border-radius:7px;background:#21262d;color:#e1e4e8;font-size:13px;font-weight:500;cursor:pointer;white-space:nowrap;transition:.15s}
.btn:hover{background:#30363d}.btn:disabled{opacity:.4;cursor:not-allowed}
.btn-g{background:#238636;border-color:#238636;color:#fff}.btn-g:hover{background:#2ea043}
.btn-r{background:#da3633;border-color:#da3633;color:#fff}.btn-r:hover{background:#f85149}
.btn-b{background:#1f6feb;border-color:#1f6feb;color:#fff}.btn-b:hover{background:#388bfd}
.steps{display:flex;flex-direction:column;gap:10px}
.step{background:#161b22;border:1px solid #30363d;border-radius:9px;overflow:hidden}
.sh{display:flex;align-items:center;gap:10px;padding:12px 16px;cursor:pointer;user-select:none}
.sn{width:26px;height:26px;border-radius:50%;background:#21262d;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;flex-shrink:0;color:#8b949e}
.sn.ok{background:#238636;color:#fff}.sn.err{background:#da3633;color:#fff}.sn.run{background:#1f6feb;color:#fff;animation:p 1s infinite}
@keyframes p{0%,100%{opacity:1}50%{opacity:.4}}
.st{flex:1;font-size:13px;font-weight:500}
.stm{font-size:11px;color:#8b949e;font-family:monospace}
.ss{font-size:11px;padding:2px 7px;border-radius:9px;font-weight:600}
.sw{background:#21262d;color:#8b949e}.so{background:#23863620;color:#3fb950}.se{background:#da363320;color:#f85149}
.sb{border-top:1px solid #30363d;padding:12px 16px;display:none}
.sb.open{display:block}
.jv{background:#0d1117;border:1px solid #30363d;border-radius:5px;padding:10px;font-family:'Cascadia Code',Consolas,monospace;font-size:11px;white-space:pre-wrap;word-break:break-all;max-height:350px;overflow-y:auto;color:#79c0ff;line-height:1.5}
.sa{display:flex;gap:6px;padding:8px 16px;border-top:1px solid #30363d;display:none}
.sa.open{display:flex}
.bb{margin-top:16px;display:flex;gap:8px}
.tag{display:inline-block;background:#30363d;color:#e1e4e8;font-size:10px;padding:1px 6px;border-radius:4px;margin:0 2px}
</style>
</head>
<body>
<div class="hdr"><h1>Video Decryptor</h1><span class="b">v4 modular</span></div>
<div class="wrap">
<div class="row">
<input id="code" placeholder="Embed code (e.g. y7gzm68d1o5g/875828)"/>
<button class="btn btn-g" onclick="reset()">New Session</button>
</div>
<div class="steps">
<div class="step"><div class="sh" onclick="tg(1)"><div class="sn" id="n1">1</div><div class="st">GET Homepage <span class="tag">steps/step1_homepage.py</span></div><div class="stm" id="t1"></div><span class="ss sw" id="s1">wait</span></div><div class="sb" id="b1"><div class="jv" id="j1"></div></div><div class="sa" id="a1"><button class="btn btn-b" onclick="go(1)">Run Step 1</button></div></div>
<div class="step"><div class="sh" onclick="tg(2)"><div class="sn" id="n2">2</div><div class="st">POST Challenge <span class="tag">steps/step2_challenge.py</span></div><div class="stm" id="t2"></div><span class="ss sw" id="s2">wait</span></div><div class="sb" id="b2"><div class="jv" id="j2"></div></div><div class="sa" id="a2"><button class="btn btn-b" onclick="go(2)">Run Step 2</button></div></div>
<div class="step"><div class="sh" onclick="tg(3)"><div class="sn" id="n3">3</div><div class="st">POST Attest <span class="tag">steps/step3_attest.py</span></div><div class="stm" id="t3"></div><span class="ss sw" id="s3">wait</span></div><div class="sb" id="b3"><div class="jv" id="j3"></div></div><div class="sa" id="a3"><button class="btn btn-b" onclick="go(3)">Run Step 3</button></div></div>
<div class="step"><div class="sh" onclick="tg(4)"><div class="sn" id="n4">4</div><div class="st">POST Playback <span class="tag">steps/step4_playback.py</span></div><div class="stm" id="t4"></div><span class="ss sw" id="s4">wait</span></div><div class="sb" id="b4"><div class="jv" id="j4"></div></div><div class="sa" id="a4"><button class="btn btn-b" onclick="go(4)">Run Step 4</button></div></div>
<div class="step"><div class="sh" onclick="tg(5)"><div class="sn" id="n5">5</div><div class="st">Decrypt AES-256-GCM <span class="tag">steps/step5_decrypt.py</span></div><div class="stm" id="t5"></div><span class="ss sw" id="s5">wait</span></div><div class="sb" id="b5"><div class="jv" id="j5"></div></div><div class="sa" id="a5"><button class="btn btn-b" onclick="go(5)">Run Step 5</button></div></div>
</div>
<div class="bb">
<button class="btn btn-g" onclick="runAll()">Run All Steps</button>
<button class="btn btn-r" onclick="reset()">Reset</button>
</div>
</div>
<script>
let sid=null;
const urls=['/api/step1-homepage','/api/step2-challenge','/api/step3-attest','/api/step4-playback','/api/step5-decrypt'];

async function getSid(){if(!sid){let r=await fetch('/api/new');sid=(await r.json()).sessionId}return sid}
function tg(n){document.getElementById('b'+n).classList.toggle('open');document.getElementById('a'+n).classList.toggle('open')}
function ss(n,state,ms){const el=document.getElementById('s'+n),nm=document.getElementById('n'+n),tm=document.getElementById('t'+n);nm.className='sn '+(state==='ok'?'ok':state==='err'?'err':state==='run'?'run':'');el.className='ss '+(state==='ok'?'so':state==='err'?'se':'sw');el.textContent=state==='ok'?'OK':state==='err'?'ERROR':state==='run'?'...':'wait';if(ms)tm.textContent=ms+'ms';if(state==='run'||state==='ok'||state==='err'){document.getElementById('b'+n).classList.add('open');document.getElementById('a'+n).classList.add('open')}}
function jshow(n,d){const el=document.getElementById('j'+n);const s=typeof d==='string'?d:JSON.stringify(d,null,2);el.innerHTML=s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"([^"]+)"(\s*:)/g,'<span style="color:#d2a8ff">"$1"</span>$2').replace(/:\s*"([^"]*)"/g,': <span style="color:#a5d6ff">"$1"</span>').replace(/:\s*(\d+\.?\d*)/g,': <span style="color:#79c0ff">$1</span>')}

async function go(n){
const id=await getSid();
const code=document.getElementById('code').value.trim();
ss(n,'run');
let body={sessionId:id};
if(n===4)body.code=code;
try{
const r=await fetch(urls[n-1],{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
const d=await r.json();
const ok=r.ok&&!d.error&&!d.fileError&&d.success!==false;
ss(n,ok?'ok':'err',d.timeMs);
jshow(n,d);
if(n===5&&d.sources&&d.sources.length){let u='\n\n--- VIDEO URLs ---\n';d.sources.forEach(s=>{u+='\n['+s.quality+'] '+s.url});document.getElementById('j5').innerHTML+='<pre style="margin-top:10px;color:#3fb950">'+u.replace(/</g,'&lt;')+'</pre>'}
}catch(e){ss(n,'err');jshow(n,{fetchError:e.message})}
}

async function runAll(){const code=document.getElementById('code').value.trim();if(!code){alert('Enter code first');return}const id=await getSid();try{const r=await fetch('/api/all/'+encodeURIComponent(code),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({sessionId:id})});const d=await r.json();if(d.results)d.results.forEach((r,i)=>{ss(i+1,!r.error&&!r.fileError?'ok':'err',r.timeMs);jshow(i+1,r)});if(d.data){ss(5,'ok');jshow(5,d.data)}}catch(e){alert(e.message)}}

function reset(){sid=null;for(let n=1;n<=5;n++){ss(n,'wait');document.getElementById('j'+n).innerHTML='';document.getElementById('t'+n).textContent='';document.getElementById('b'+n).classList.remove('open');document.getElementById('a'+n).classList.remove('open')}}
</script>
</body>
</html>"""


# ═══════════════════════════════════════════
#  START
# ═══════════════════════════════════════════

if __name__ == "__main__":
    print()
    print("=" * 55)
    print("  Video Decryptor v4 — Modular")
    print("=" * 55)
    print("  Files:")
    print("    server.py              (Flask app)")
    print("    helpers.py             (config, crypto, HTTP)")
    print("    steps/step1_homepage.py")
    print("    steps/step2_challenge.py")
    print("    steps/step3_attest.py")
    print("    steps/step4_playback.py")
    print("    steps/step5_decrypt.py")
    print()
    print("  Port: %d" % PORT)
    print("  URL:  http://localhost:%d" % PORT)
    print()
    print("  Debug: http://localhost:%d/health" % PORT)
    print("    (shows which files loaded OK)")
    print("=" * 55)
    sys.stdout.flush()

    app.run(host="0.0.0.0", port=PORT, debug=False, use_reloader=False)
