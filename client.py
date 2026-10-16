# -*- coding: utf-8 -*-
"""
client.py — a low-level user (acceptance check for the service layer).

Picks a cooperative group I_B, sends the SAME (B, I_B) to every member,
collects one dk per member, and checks that all |I_B| keys are well-formed.
Run inside the compose network:
    docker compose run --rm client
"""
import argparse
import time

import httpx

import kcabe_core as K


def wait_ready(host: str, tries: int = 120):
    for _ in range(tries):
        try:
            if httpx.get(f"http://{host}:5000/health", timeout=5).status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(1)
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--members", default="hl1,hl2,hl3", help="I_B (also the host names)")
    ap.add_argument("--B", default="A,B")
    ap.add_argument("--mpk", default="/data/public/mpk.json")
    a = ap.parse_args()

    I_B, B = a.members.split(","), a.B.split(",")
    group, mpk = K.load_mpk_json(a.mpk)

    for h in I_B:
        print(f"[client] waiting for {h} ..." , flush=True)
        if not wait_ready(h):
            print(f"[client] {h} is not ready -> abort")
            raise SystemExit(1)

    t0 = time.perf_counter()
    got = []
    for h in I_B:
        r = httpx.post(f"http://{h}:5000/ukeygen", json={"B": B, "I_B": I_B}, timeout=120)
        if r.status_code != 200:
            print(f"[client] {h}: {r.status_code} {r.text}")
            continue
        got.append(K.load_dk(group, r.json()))
    dt = time.perf_counter() - t0

    ok = len(got) == len(I_B) and all(K.dk_is_well_formed(mpk, d) for d in got)
    print(f"[client] I_B={I_B} B={B}: received {len(got)}/{len(I_B)} dk in {dt:.2f}s "
          f"-> {'VALID KEY SET' if ok else 'INCOMPLETE'}")

    try:
        s = httpx.get("http://pkg:5000/stats", timeout=3).json()
        print(f"[client] PKG reachable, enrollments so far: {s['enroll_ok']}")
    except Exception:
        print("[client] PKG is unreachable (offline) — keys were issued without it")


if __name__ == "__main__":
    main()
