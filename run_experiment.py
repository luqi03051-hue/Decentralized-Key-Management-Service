# -*- coding: utf-8 -*-
"""
run_experiment.py — one experiment, three configurations (run inside the compose network).

  baseline : N users all enroll with the PKG (traditional: PKG issues every key)
  partial  : m high-level users enrolled with the PKG at start-up (already done by hl_server);
             the other N-m users each pick a cooperative group I_B (|I_B| = 3, random from the
             m high-level users) and collect one dk from every member. PKG stays online
             but receives no request in this phase.
  offline  : same as partial, but the PKG container is STOPPED before the phase starts.

Metric of interest: PKG load. Total system computation is reported as well (honest cost view).
Success criterion (key issuance only; no Enc/UDec in this prototype): the user received a
structurally valid key set (sk for baseline; |I_B| well-formed dk for partial/offline).

Typical use is through run_all.sh.
"""
import argparse
import json
import os
import random
import statistics
import time
from concurrent.futures import ThreadPoolExecutor

import httpx

import kcabe_core as K

PKG = "http://pkg:5000"
HL_IDS = ["hl1", "hl2", "hl3", "hl4", "hl5"]
GROUP_SIZE = 3
B = ["A", "B"]
RESULTS = "/results"


def wait_health(host: str, tries: int = 300) -> bool:
    for _ in range(tries):
        try:
            if httpx.get(f"http://{host}:5000/health", timeout=5).status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(1)
    return False


def get_stats(host: str):
    try:
        return httpx.get(f"http://{host}:5000/stats", timeout=5).json()
    except Exception:
        return None


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1))))]


def run_phase(jobs, fn, conc):
    """Run fn(job) concurrently; returns (wall_seconds, [(ok, latency)])."""
    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=conc) as ex:
        res = list(ex.map(fn, jobs))
    return time.perf_counter() - t0, res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["baseline", "partial", "offline"])
    ap.add_argument("--snapshot-pkg", action="store_true",
                    help="wait for all high-level users, save PKG stats, then exit")
    ap.add_argument("--n", type=int, default=100, help="N = number of users (= n of the system)")
    ap.add_argument("--conc", type=int, default=10, help="concurrent users")
    ap.add_argument("--rep", type=int, default=1)
    ap.add_argument("--mpk", default="/data/public/mpk.json")
    a = ap.parse_args()

    group, mpk = K.load_mpk_json(a.mpk)
    snap_path = os.path.join(RESULTS, "pkg_snapshot.json")
    os.makedirs(RESULTS, exist_ok=True)

    if a.snapshot_pkg:
        for h in HL_IDS:
            assert wait_health(h), f"{h} not ready"
        with open(snap_path, "w") as f:
            json.dump(get_stats("pkg"), f)
        print("[exp] PKG snapshot saved:", get_stats("pkg"))
        return

    N, m = a.n, len(HL_IDS)
    http = httpx.Client(timeout=300)

    # ---------------- baseline ----------------
    if a.mode == "baseline":
        assert wait_health("pkg")
        before = get_stats("pkg")

        def one(uid):
            t0 = time.perf_counter()
            try:
                r = http.post(f"{PKG}/enroll", json={"id": uid, "attrs": K.DEFAULT_ATTRS})
                ok = False
                if r.status_code == 200:
                    er = K.load_enroll(group, r.json())
                    ok = (len(er.sk["sk3"]) == mpk["n"]
                          and set(er.sk["sk2"]) == set(K.DEFAULT_ATTRS))
            except Exception:
                ok = False
            return ok, time.perf_counter() - t0

        wall, res = run_phase([f"u{i:03d}" for i in range(N)], one, a.conc)
        after = get_stats("pkg")
        pkg_total, pkg_during, pkg_reach = after, after["enroll_ok"] - before["enroll_ok"], True
        hl_stats = []

    # ---------------- partial / offline ----------------
    else:
        for h in HL_IDS:
            assert wait_health(h), f"{h} not ready"
        if a.mode == "partial":
            before = get_stats("pkg")
            assert before is not None, "PKG should be online in 'partial' mode"
        else:
            assert get_stats("pkg") is None, "PKG must be stopped in 'offline' mode"
            before = json.load(open(snap_path))

        rng = random.Random(1000 + a.rep)
        users = [(i, rng.sample(HL_IDS, GROUP_SIZE)) for i in range(N - m)]

        def one(job):
            _, members = job
            t0 = time.perf_counter()
            try:
                dks = []
                for h in members:
                    r = http.post(f"http://{h}:5000/ukeygen", json={"B": B, "I_B": members})
                    if r.status_code == 200:
                        dks.append(K.load_dk(group, r.json()))
                ok = (len(dks) == len(members)
                      and all(K.dk_is_well_formed(mpk, d) for d in dks))
            except Exception:
                ok = False
            return ok, time.perf_counter() - t0

        wall, res = run_phase(users, one, a.conc)
        after = get_stats("pkg")
        if a.mode == "partial":
            pkg_total, pkg_during, pkg_reach = after, after["enroll_ok"] - before["enroll_ok"], True
        else:
            assert after is None, "PKG unexpectedly reachable in 'offline' mode"
            pkg_total, pkg_during, pkg_reach = before, 0, False
        hl_stats = [get_stats(h) for h in HL_IDS]

    lats = [t for ok, t in res]
    out = {
        "mode": a.mode, "rep": a.rep, "N": N, "m": 0 if a.mode == "baseline" else m,
        "group_size": GROUP_SIZE, "concurrency": a.conc,
        "users": len(res), "users_ok": sum(1 for ok, _ in res if ok),
        "phase_wall_s": wall,
        "lat_p50_s": pct(lats, 50), "lat_p95_s": pct(lats, 95),
        "pkg_total_requests": pkg_total["enroll_ok"],
        "pkg_total_busy_s": pkg_total["busy_seconds"],
        "pkg_requests_during_phase": pkg_during,
        "pkg_reachable_after": pkg_reach,
        "hl_requests": [s["ukeygen_ok"] for s in hl_stats],
        "hl_busy_s": [s["busy_seconds"] for s in hl_stats],
    }
    path = os.path.join(RESULTS, f"{a.mode}_rep{a.rep}.json")
    with open(path, "w") as f:
        json.dump(out, f, indent=2)
    print(f"[exp] {a.mode} rep{a.rep}: users_ok={out['users_ok']}/{out['users']} "
          f"phase={wall:.2f}s PKG_requests_total={out['pkg_total_requests']} "
          f"PKG_busy={out['pkg_total_busy_s']:.2f}s PKG_requests_in_phase={pkg_during} "
          f"PKG_reachable_after={pkg_reach}")


if __name__ == "__main__":
    main()
