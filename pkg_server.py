# -*- coding: utf-8 -*-
"""
pkg_server.py — the PKG service.

Holds msk (α, β). Its ONLY job is enrollment of high-level users:
    POST /enroll  {"id": "hl1", "attrs": ["A","B","C"]}  ->  sk_i and S_ID
After the high-level users have enrolled, this container can be stopped:
UKeyGen never contacts the PKG.

NOTE: the registry of enrolled identities lives in memory; restarting the PKG
loses it (acceptable for the prototype, see README / Limitations).
"""
import os
import threading
import time

from flask import Flask, jsonify, request

import kcabe_core as K

MPK_PATH = os.environ.get("MPK_PATH", "/data/public/mpk.json")
MSK_PATH = os.environ.get("MSK_PATH", "/secret/msk.json")

app = Flask(__name__)
group, mpk = K.load_mpk_json(MPK_PATH)
_, msk = K.load_msk_json(MSK_PATH)
st = {"registered": {}}

_lock = threading.Lock()
_stats = {"enroll_ok": 0, "enroll_rejected": 0, "busy_seconds": 0.0}


@app.post("/enroll")
def enroll():
    j = request.get_json(force=True)
    ID, attrs = j.get("id"), j.get("attrs")
    if not ID or not isinstance(attrs, list):
        return jsonify(error="bad request: need id and attrs"), 400
    with _lock:
        t0 = time.perf_counter()
        try:
            er = K.enroll(mpk, msk, st, ID, attrs)
        except (ValueError, PermissionError) as e:
            _stats["enroll_rejected"] += 1
            return jsonify(error=str(e)), 409
        blob = K.dump_enroll(group, er)
        _stats["enroll_ok"] += 1
        _stats["busy_seconds"] += time.perf_counter() - t0
    return jsonify(blob)


@app.get("/stats")
def stats():
    with _lock:
        return jsonify(role="pkg", registered=len(st["registered"]), **_stats)


@app.get("/health")
def health():
    return jsonify(ok=True)
