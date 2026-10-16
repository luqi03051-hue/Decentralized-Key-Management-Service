# -*- coding: utf-8 -*-
"""summarize.py — aggregate results/*.json into one table (mean ± std over repetitions)."""
import glob
import json
import os
import statistics as st
import sys

RES = sys.argv[1] if len(sys.argv) > 1 else "results"
ORDER = ["baseline", "partial", "offline"]
LABEL = {"baseline": "Baseline (PKG issues all keys)",
         "partial": "Case A (PKG enrolls m trusted users only)",
         "offline": "Case B (PKG stopped after enrollment)"}


def ms(xs, fmt="{:.2f}"):
    if len(xs) == 1:
        return fmt.format(xs[0])
    return (fmt + " ± " + fmt).format(st.mean(xs), st.stdev(xs))


runs = {}
for p in sorted(glob.glob(os.path.join(RES, "*_rep*.json"))):
    r = json.load(open(p))
    runs.setdefault(r["mode"], []).append(r)

rows = []
for mode in ORDER:
    rs = runs.get(mode)
    if not rs:
        continue
    hl_req = [sum(r["hl_requests"]) / len(r["hl_requests"]) for r in rs if r["hl_requests"]]
    hl_busy = [sum(r["hl_busy_s"]) / len(r["hl_busy_s"]) for r in rs if r["hl_busy_s"]]
    rows.append([
        LABEL[mode], str(len(rs)),
        ms([r["pkg_total_requests"] for r in rs], "{:.0f}"),
        ms([r["pkg_total_busy_s"] for r in rs]),
        ms([r["pkg_requests_during_phase"] for r in rs], "{:.0f}"),
        ms([r["phase_wall_s"] for r in rs]),
        ms([r["lat_p50_s"] * 1000 for r in rs], "{:.0f}"),
        ms([r["lat_p95_s"] * 1000 for r in rs], "{:.0f}"),
        f"{sum(r['users_ok'] for r in rs)}/{sum(r['users'] for r in rs)}",
        ms(hl_req, "{:.1f}") if hl_req else "-",
        ms(hl_busy) if hl_busy else "-",
        "yes" if rs[0]["pkg_reachable_after"] else "no",
    ])

hdr = ["Configuration", "runs", "PKG requests (total)", "PKG busy (s)",
       "PKG requests during user phase", "user phase wall (s)", "p50 (ms)", "p95 (ms)",
       "users with valid keys", "reqs / trusted user", "busy / trusted user (s)", "PKG reachable"]
lines = ["| " + " | ".join(hdr) + " |", "|" + "---|" * len(hdr)]
lines += ["| " + " | ".join(r) + " |" for r in rows]
table = "\n".join(lines)
print(table)

if "baseline" in runs and "partial" in runs:
    b = st.mean(r["pkg_total_busy_s"] for r in runs["baseline"])
    p = st.mean(r["pkg_total_busy_s"] for r in runs["partial"])
    print(f"\nPKG busy time: baseline {b:.2f}s -> KC-ABE {p:.2f}s  "
          f"({100 * (1 - p / b):.1f}% less, {b / p:.1f}x)")

with open(os.path.join(RES, "summary.md"), "w") as f:
    f.write(table + "\n")
