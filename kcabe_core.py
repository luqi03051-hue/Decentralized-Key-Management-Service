# -*- coding: utf-8 -*-
"""
kcabe_core.py  (KC-ABE core) — Setup / PKeyGen / UKeyGen only
-------------------------------------------------------------
Key Cooperative CP-ABE (KC-ABE), key-issuance part of the scheme.
Enc / PDec / UDec are intentionally NOT implemented in this prototype
(correctness and IND-sCPA security are established in the paper).

Roles (paper):
  PKG                 : Setup / PKeyGen  (+ SOK Extract, run once at enrollment)
  Trusted high-level  : UKeyGen          (no contact with the PKG, no contact
                                          with other group members)
  Low-level user      : collects |I_B| user private keys dk (one per member)

Notation (all in G = G1 of a symmetric pairing, exponents in Z_p):

  mpk = (g, w, v, {h_k}_{k=1..n}, {u_j}_{j in U}, e(g,g)^alpha)
  msk = alpha                      (+ beta : master key of the SOK scheme)

  PKeyGen(mpk, msk, ID_i, A_i):
      r_i <- Z_p
      sk_i = ( g^alpha w^{r_i},  g^{r_i},  {u_j^{-r_i}}_{j in A_i},
               {h_k^{r_i}}_{k=1..n} )

  SOK (Sakai-Ohgishi-Kasahara):
      S_ID      = H1(ID)^beta
      K_{i,j}   = H2( e(S_{ID_i}, H1(ID_j)) )   (= K_{j,i})

  Cooperative key of member i in I_B (members ordered by ID):
      a_{i,j} = -K_{i,j}  if i > j,   +K_{i,j}  if i < j
      x_i     = 1 + sum_{j != i} a_{i,j}
      ck_i    = g^{x_i}                          =>  prod_i ck_i = g^{|I_B|}

  UKeyGen(mpk, ID_i, sk_i, S_ID_i, I_B, B):      (B subset of A_i, |I_B| < n)
      y_i <- Z_p
      dk_i = ( g^alpha w^{r_i} * ck_i * (prod_{k=1}^{n-|I_B|} h_k)^{r_i}
                                      * (prod_{k=1}^{n-|I_B|} h_k * w)^{y_i},
               g^{r_i} g^{y_i},
               { u_j^{-r_i} u_j^{-y_i} }_{j in B},
               { h_k^{r_i} h_k^{y_i} }_{k=n-|I_B|+1..n} )

Implementation note: dk_i is computed from the components of sk_i
(sk_i[3][k] = h_k^{r_i}), so the high-level user never needs r_i itself.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, GT, pair

_KCABE_CORE_VERSION = "1.0"

DEFAULT_ATTRS = ["A", "B", "C", "D", "E"]


# ============================================================
# JSON / base64 / Charm serialization helpers
# ============================================================

def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def save_json(path: str, obj: Any) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)

def load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def serialize_any(group: PairingGroup, obj: Any) -> Any:
    """Recursively serialize Charm group elements to base64 JSON."""
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, dict):
        return {str(k): serialize_any(group, v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [serialize_any(group, v) for v in obj]
    return {"__charm__": _b64e(group.serialize(obj))}

def deserialize_any(group: PairingGroup, obj: Any) -> Any:
    """Recursively deserialize base64 JSON back to Charm group elements."""
    if isinstance(obj, dict) and "__charm__" in obj:
        return group.deserialize(_b64d(obj["__charm__"]))
    if isinstance(obj, dict):
        return {k: deserialize_any(group, v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [deserialize_any(group, v) for v in obj]
    return obj


# ============================================================
# Helpers: H1 : {0,1}* -> G1,  H2 : GT -> Z_p,  small group utils
# ============================================================

def H1(group: PairingGroup, ID: str) -> Any:
    return group.hash(("H1:" + ID).encode("utf-8"), G1)

def H2(group: PairingGroup, x: Any) -> Any:
    return group.hash(group.serialize(x), ZR)

def _neg(group: PairingGroup, x: Any) -> Any:
    """-x in Z_p."""
    return group.init(ZR, 0) - x

def _prod(elems: Sequence[Any]) -> Any:
    """Product of a non-empty sequence of group elements."""
    it = iter(elems)
    acc = next(it)
    for e in it:
        acc = acc * e
    return acc

def _canon_group(I_B: Sequence[str]) -> List[str]:
    """
    Canonical (sorted) member order of a cooperative group.
    All members MUST use the same order: the signs of a_{i,j} depend on it.
    """
    ids = list(I_B)
    if len(set(ids)) != len(ids):
        raise ValueError("I_B contains duplicate identities")
    return sorted(ids)


# ============================================================
# Scheme dataclasses
# ============================================================

@dataclass
class SetupResult:
    curve: str
    mpk: Dict[str, Any]
    msk: Dict[str, Any]       # {"alpha": ..., "beta": ...}
    st: Dict[str, Any]        # PKG state: {"registered": {ID: [attrs]}}

@dataclass
class EnrollResult:
    """What the PKG hands to a high-level user at enrollment (one time)."""
    ID: str
    A: List[str]
    sk: Dict[str, Any]        # {"sk0","sk1","sk2":{attr:..},"sk3":[..n..]}
    S_ID: Any                 # SOK private key  H1(ID)^beta

@dataclass
class UserKeyResult:
    """Output of UKeyGen: the user private key dk_B^{ID_i}."""
    issuer: str               # ID_i of the high-level user that issued it
    B: List[str]
    I_B: List[str]            # canonical (sorted) order
    dk: Dict[str, Any]        # {"d0","d1","d2":{attr:..},"d3":{k:..}}


# ============================================================
# Setup  (PKG)
# ============================================================

def setup(curve: str = "SS512", n: int = 20,
          attrs: Optional[List[str]] = None) -> SetupResult:
    """
    Setup(λ, U, n) -> (mpk, msk)

    n     : number of users in the system (h_1..h_n)
    attrs : attribute universe U

    Also samples the SOK master secret beta (kept by the PKG, not in mpk).
    """
    if n < 2:
        raise ValueError("n must be >= 2")
    attrs = list(attrs) if attrs else list(DEFAULT_ATTRS)
    group = PairingGroup(curve)

    g = group.random(G1)
    w = group.random(G1)
    v = group.random(G1)
    h = [group.random(G1) for _ in range(n)]
    u = {a: group.random(G1) for a in attrs}
    alpha = group.random(ZR)
    beta = group.random(ZR)

    mpk = {
        "curve": curve,
        "n": n,
        "attrs": attrs,
        "g": g, "w": w, "v": v,
        "h": h,
        "u": u,
        "egg_alpha": pair(g, g) ** alpha,
    }
    msk = {"alpha": alpha, "beta": beta}
    st = {"registered": {}}
    return SetupResult(curve=curve, mpk=mpk, msk=msk, st=st)


# ============================================================
# PKeyGen (PKG) + SOK Extract (PKG)
# ============================================================

def pkeygen(mpk: Dict[str, Any], msk: Dict[str, Any],
            ID: str, A: Sequence[str]) -> Dict[str, Any]:
    """
    PKeyGen(mpk, msk, ID_i, A_i) -> sk_i
    sk_i = (g^α w^r, g^r, {u_j^{-r}}_{j∈A_i}, {h_k^r}_{k=1..n})
    """
    group = PairingGroup(mpk["curve"])
    for a in A:
        if a not in mpk["u"]:
            raise ValueError(f"unknown attribute: {a}")

    r = group.random(ZR)
    g, w = mpk["g"], mpk["w"]
    return {
        "sk0": (g ** msk["alpha"]) * (w ** r),
        "sk1": g ** r,
        "sk2": {a: mpk["u"][a] ** _neg(group, r) for a in A},
        "sk3": [hk ** r for hk in mpk["h"]],
    }


def sok_extract(mpk: Dict[str, Any], msk: Dict[str, Any],
                st: Dict[str, Any], ID: str) -> Any:
    """
    SOK Extract: S_ID = H1(ID)^β.  The PKG first verifies that ID is registered.
    """
    if ID not in st["registered"]:
        raise PermissionError(f"identity not registered: {ID}")
    group = PairingGroup(mpk["curve"])
    return H1(group, ID) ** msk["beta"]


def enroll(mpk: Dict[str, Any], msk: Dict[str, Any], st: Dict[str, Any],
           ID: str, A: Sequence[str]) -> EnrollResult:
    """
    Enrollment of a high-level user — the ONLY step that involves the PKG.
    Registers ID, then issues sk_i (PKeyGen) and S_ID (SOK Extract).
    After this, the user can run UKeyGen with the PKG offline.
    """
    if ID in st["registered"]:
        raise ValueError(f"identity already registered: {ID}")
    if len(st["registered"]) >= mpk["n"]:
        raise ValueError("system is full (n users)")
    st["registered"][ID] = list(A)
    sk = pkeygen(mpk, msk, ID, A)
    S_ID = sok_extract(mpk, msk, st, ID)
    return EnrollResult(ID=ID, A=list(A), sk=sk, S_ID=S_ID)


# ============================================================
# SOK shared key + cooperative key  (high-level user, local)
# ============================================================

def sok_shared_key(mpk: Dict[str, Any], S_ID_i: Any, ID_j: str) -> Any:
    """K_{i,j} = H2( e(H1(ID_i)^β, H1(ID_j)) )  ∈ Z_p.  Non-interactive."""
    group = PairingGroup(mpk["curve"])
    return H2(group, pair(S_ID_i, H1(group, ID_j)))


def coop_exponent(mpk: Dict[str, Any], ID_i: str, S_ID_i: Any,
                  I_B: Sequence[str], order: Optional[Sequence[str]] = None) -> Any:
    """
    x_i = 1 + Σ_{j≠i} a_{i,j}  ∈ Z_p, with a_{i,j} = -K_{i,j} (i>j), +K_{i,j} (i<j).

    `order` is only meant for tests (to show that a wrong member order breaks
    the cancellation); by default members are sorted by ID.
    """
    group = PairingGroup(mpk["curve"])
    members = list(order) if order is not None else _canon_group(I_B)
    if ID_i not in members:
        raise ValueError("ID_i must be a member of I_B")
    pos = {ident: idx for idx, ident in enumerate(members)}

    x = group.init(ZR, 1)
    for ID_j in members:
        if ID_j == ID_i:
            continue
        K = sok_shared_key(mpk, S_ID_i, ID_j)
        x = x + (_neg(group, K) if pos[ID_i] > pos[ID_j] else K)
    return x


def coop_key(mpk: Dict[str, Any], ID_i: str, S_ID_i: Any,
             I_B: Sequence[str], order: Optional[Sequence[str]] = None) -> Any:
    """ck_i^B = g^{x_i}."""
    return mpk["g"] ** coop_exponent(mpk, ID_i, S_ID_i, I_B, order)


def check_cooperation(mpk: Dict[str, Any], cks: Sequence[Any], size: int) -> bool:
    """Self-check from the paper: Π_i ck_i == g^{|I_B|}."""
    return _prod(cks) == mpk["g"] ** PairingGroup(mpk["curve"]).init(ZR, size)


# ============================================================
# UKeyGen  (trusted high-level user, no PKG involved)
# ============================================================

def _ukeygen(mpk: Dict[str, Any], ID_i: str, sk: Dict[str, Any], S_ID_i: Any,
             I_B: Sequence[str], B: Sequence[str]) -> Tuple[UserKeyResult, Any]:
    group = PairingGroup(mpk["curve"])
    n = mpk["n"]
    members = _canon_group(I_B)
    m = len(members)

    if ID_i not in members:
        raise ValueError("ID_i must be a member of I_B")
    if not (1 <= m < n):
        raise ValueError("require 1 <= |I_B| < n")
    missing = [a for a in B if a not in sk["sk2"]]
    if missing:
        raise PermissionError(f"B is not a subset of A_i, missing: {missing}")

    g, w, h, u = mpk["g"], mpk["w"], mpk["h"], mpk["u"]

    ck = coop_key(mpk, ID_i, S_ID_i, members)
    y = group.random(ZR)

    head = n - m   # k = 1..n-|I_B|  (head),  k = n-|I_B|+1..n  (tail)
    prod_h_r = _prod(sk["sk3"][:head])           # (Π_{k<=n-m} h_k)^{r_i}
    prod_hw = _prod(h[:head]) * w                # Π_{k<=n-m} h_k · w

    d0 = sk["sk0"] * ck * prod_h_r * (prod_hw ** y)
    d1 = sk["sk1"] * (g ** y)
    d2 = {a: sk["sk2"][a] * (u[a] ** _neg(group, y)) for a in B}
    d3 = {str(k): sk["sk3"][k - 1] * (h[k - 1] ** y) for k in range(head + 1, n + 1)}

    dk = UserKeyResult(issuer=ID_i, B=list(B), I_B=members,
                       dk={"d0": d0, "d1": d1, "d2": d2, "d3": d3})
    return dk, ck


def ukeygen(mpk: Dict[str, Any], ID_i: str, sk: Dict[str, Any], S_ID_i: Any,
            I_B: Sequence[str], B: Sequence[str]) -> UserKeyResult:
    """UKeyGen(mpk, ID_i, sk_i, I_B, B) -> dk_B^{ID_i}   (ck_i stays local)."""
    dk, _ck = _ukeygen(mpk, ID_i, sk, S_ID_i, I_B, B)
    return dk


# ============================================================
# Export / load helpers
# ============================================================

def export_public_json(out_path: str, res: SetupResult) -> None:
    """mpk only — safe to share with every container."""
    group = PairingGroup(res.curve)
    save_json(out_path, {"mpk": serialize_any(group, res.mpk)})

def export_msk_json(out_path: str, res: SetupResult) -> None:
    """msk (α, β) — mounted into the PKG container ONLY."""
    group = PairingGroup(res.curve)
    save_json(out_path, {"curve": res.curve, "msk": serialize_any(group, res.msk)})

def load_mpk_json(path: str) -> Tuple[PairingGroup, Dict[str, Any]]:
    blob = load_json(path)
    group = PairingGroup(blob["mpk"]["curve"])
    return group, deserialize_any(group, blob["mpk"])

def load_msk_json(path: str) -> Tuple[PairingGroup, Dict[str, Any]]:
    blob = load_json(path)
    group = PairingGroup(blob["curve"])
    return group, deserialize_any(group, blob["msk"])


def dump_enroll(group: PairingGroup, er: EnrollResult) -> Dict[str, Any]:
    return {"ID": er.ID, "A": er.A,
            "sk": serialize_any(group, er.sk),
            "S_ID": serialize_any(group, er.S_ID)}

def load_enroll(group: PairingGroup, blob: Dict[str, Any]) -> EnrollResult:
    return EnrollResult(ID=blob["ID"], A=list(blob["A"]),
                        sk=deserialize_any(group, blob["sk"]),
                        S_ID=deserialize_any(group, blob["S_ID"]))

def dump_dk(group: PairingGroup, dk: UserKeyResult) -> Dict[str, Any]:
    return {"issuer": dk.issuer, "B": dk.B, "I_B": dk.I_B,
            "dk": serialize_any(group, dk.dk)}

def load_dk(group: PairingGroup, blob: Dict[str, Any]) -> UserKeyResult:
    return UserKeyResult(issuer=blob["issuer"], B=list(blob["B"]),
                         I_B=list(blob["I_B"]),
                         dk=deserialize_any(group, blob["dk"]))

def dk_is_well_formed(mpk: Dict[str, Any], dk: UserKeyResult) -> bool:
    """
    Structural check used by the experiment script (key issuance only):
    d2 has one entry per attribute in B, d3 has |I_B| entries.
    """
    n, m = mpk["n"], len(dk.I_B)
    d = dk.dk
    return (set(d["d2"].keys()) == set(dk.B)
            and set(d["d3"].keys()) == {str(k) for k in range(n - m + 1, n + 1)}
            and "d0" in d and "d1" in d)


# ============================================================
# Quick smoke test (run as script)
# ============================================================

def _smoke_test():
    print("=== KC-ABE smoke test ===")
    curve = "SS512"
    group = PairingGroup(curve)

    print("[1] Setup (n=20, U={A..E}) ...")
    res = setup(curve=curve, n=20)
    mpk, msk, st = res.mpk, res.msk, res.st

    print("[2] Enroll 3 high-level users (PKG involved) ...")
    ids = ["hl1", "hl2", "hl3"]
    users = {i: enroll(mpk, msk, st, i, DEFAULT_ATTRS) for i in ids}

    print("[3] SOK symmetry  K_ij == K_ji ...")
    k12 = sok_shared_key(mpk, users["hl1"].S_ID, "hl2")
    k21 = sok_shared_key(mpk, users["hl2"].S_ID, "hl1")
    t_sok = (k12 == k21)
    print(f"    {'PASS' if t_sok else 'FAIL'}")

    print("[4] Cooperation:  Π ck_i == g^|I_B|  (3 members, no PKG, no peer contact) ...")
    cks = [coop_key(mpk, i, users[i].S_ID, ids) for i in ids]
    t1 = check_cooperation(mpk, cks, 3)
    print(f"    {'PASS' if t1 else 'FAIL'}")

    print("[5] Wrong member order for one user must break the cancellation ...")
    bad = [coop_key(mpk, "hl1", users["hl1"].S_ID, ids, order=["hl2", "hl1", "hl3"]),
           cks[1], cks[2]]
    t2 = not check_cooperation(mpk, bad, 3)
    print(f"    {'PASS' if t2 else 'FAIL'}")

    print("[6] A missing member must break the cancellation ...")
    t3 = not check_cooperation(mpk, cks[:2], 2) and not check_cooperation(mpk, cks[:2], 3)
    print(f"    {'PASS' if t3 else 'FAIL'}")

    print("[7] UKeyGen output is well-formed and survives JSON round-trip ...")
    B = ["A", "B"]
    dks = [ukeygen(mpk, i, users[i].sk, users[i].S_ID, ids, B) for i in ids]
    t4 = all(dk_is_well_formed(mpk, dk) for dk in dks)
    rt = load_dk(group, dump_dk(group, dks[0]))
    t4 = t4 and rt.dk["d0"] == dks[0].dk["d0"] and rt.dk["d3"] == dks[0].dk["d3"]
    print(f"    {'PASS' if t4 else 'FAIL'}")

    print("[8] UKeyGen rejects B not a subset of A_i, and unregistered ID ...")
    lim = enroll(mpk, msk, st, "hl4", ["A"])
    t5 = False
    try:
        ukeygen(mpk, "hl4", lim.sk, lim.S_ID, ["hl4", "hl1"], ["A", "B"])
    except PermissionError:
        t5 = True
    t6 = False
    try:
        sok_extract(mpk, msk, st, "ghost")
    except PermissionError:
        t6 = True
    print(f"    {'PASS' if (t5 and t6) else 'FAIL'}")

    ok = all([t_sok, t1, t2, t3, t4, t5, t6])
    print("=== ALL TESTS PASSED ===" if ok else "=== SOME TESTS FAILED ===")


if __name__ == "__main__":
    _smoke_test()
