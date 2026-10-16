# -*- coding: utf-8 -*-
"""
hl_server.py — a trusted high-level user.

Start-up:   enroll ONCE with the PKG (sk_i, S_ID) and keep them in memory only.
Serving:    POST /ukeygen {"B": [...], "I_B": [...]}  ->  dk
            Computed locally: no PKG, no contact with the other group members.

Environment: HL_ID, HL_ATTRS (comma separated), PKG_URL
"""
import os
import threading
import time

import httpx
from flask import Flask, jsonify, request

import kcabe_core as K

MPK_PATH = os.environ.get("MPK_PATH", "/data/public/mpk.json")
PKG_URL = os.environ.get("PKG_URL", "http://pkg:5000")
MY_ID = os.environ["HL_ID"]
MY_ATTRS = [a for a in os.environ.get("HL_ATTRS", "A,B,C,D,E").split(",") if a]

app = Flask(__name__)
group, mpk = K.load_mpk_json(MPK_PATH)

_lock = threading.Lock()
_state = {"me": None, "ready": False, "error": None}
_stats = {"ukeygen_ok": 0, "ukeygen_rejected": 0, "busy_seconds": 0.0}


def _enroll_with_pkg(retries: int = 120):
    for _ in range(retries):
        try:
            r = httpx.post(f"{PKG_URL}/enroll", json={"id": MY_ID, "attrs": MY_ATTRS},
                           timeout=60)
            if r.status_code == 200:
                _state["me"] = K.load_enroll(group, r.json())
                _state["ready"] = True
                print(f"[{MY_ID}] enrolled with PKG; sk and S_ID kept in memory", flush=True)
                return
            _state["error"] = f"PKG answered {r.status_code}: {r.text}"
            print(f"[{MY_ID}] {_state['error']}", flush=True)
            if r.status_code == 409:      # already registered / system full: retrying won't help
                return
        except Exception as e:             # PKG not up yet
            _state["error"] = repr(e)
        time.sleep(1)


threading.Thread(target=_enroll_with_pkg, daemon=True).start()


@app.post("/ukeygen")
def ukeygen():
    if not _state["ready"]:
        return jsonify(error="not enrolled yet", detail=_state["error"]), 503
    j = request.get_json(force=True)
    B, I_B = j.get("B"), j.get("I_B")
    if not isinstance(B, list) or not isinstance(I_B, list):
        return jsonify(error="bad request: need B and I_B (lists)"), 400
    me = _state["me"]
    with _lock:
        t0 = time.perf_counter()
        try:
            dk = K.ukeygen(mpk, MY_ID, me.sk, me.S_ID, I_B, B)
        except PermissionError as e:
            _stats["ukeygen_rejected"] += 1
            return jsonify(error=str(e)), 403
        except ValueError as e:
            _stats["ukeygen_rejected"] += 1
            return jsonify(error=str(e)), 400
        blob = K.dump_dk(group, dk)
        _stats["ukeygen_ok"] += 1
        _stats["busy_seconds"] += time.perf_counter() - t0
    return jsonify(blob)


@app.get("/stats")
def stats():
    with _lock:
        return jsonify(role="hl", id=MY_ID, ready=_state["ready"], **_stats)


@app.get("/health")
def health():
    return jsonify(ok=_state["ready"], id=MY_ID), (200 if _state["ready"] else 503)
