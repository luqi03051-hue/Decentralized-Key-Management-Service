# -*- coding: utf-8 -*-
"""
setup_once.py — run ONCE before `docker compose up`.

  mpk (public)  -> data/public/mpk.json        (mounted read-only into every container)
  msk (α, β)    -> data/pkg_secret/msk.json    (mounted into the PKG container ONLY)

Usage (from the project directory):
  docker run --rm -v "$PWD":/app kcabe-base:v1 python setup_once.py --n 20
"""
import argparse
import kcabe_core as K


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--curve", default="SS512")
    ap.add_argument("--n", type=int, default=20, help="number of users in the system")
    ap.add_argument("--attrs", default=",".join(K.DEFAULT_ATTRS))
    ap.add_argument("--public", default="data/public/mpk.json")
    ap.add_argument("--secret", default="data/pkg_secret/msk.json")
    a = ap.parse_args()

    res = K.setup(curve=a.curve, n=a.n, attrs=a.attrs.split(","))
    K.export_public_json(a.public, res)
    K.export_msk_json(a.secret, res)
    print(f"[setup] curve={a.curve} n={a.n} attrs={a.attrs}")
    print(f"[setup] mpk -> {a.public}")
    print(f"[setup] msk -> {a.secret}   (keep private; only the PKG container mounts it)")


if __name__ == "__main__":
    main()
