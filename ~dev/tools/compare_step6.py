# DEEP2_QWEN25_STEP6_DIVERGENCE_ORACLE_001 — per-layer checkpoint comparison
#
# Compares the C++ teacher-forced step-6 trace against the Python reference
# trace, layer by layer, and reports the FIRST diverging checkpoint.
#
# C++ trace format (parity_trace_cpp_step6.txt):
#   STEP=6 CP=LAYER_<n>_<CPNAME> COUNT=... MIN=... MAX=... MEAN=... L2=... FIRST8=... HASH=...
#   STEP=6 CP=KV_WRITE LAYER=<n> COUNT=... K_MIN=... ... K_HASH=... V_MIN=... ... V_HASH=...
#   STEP=6 CP=<GLOBAL> ... (EMBED, HIDDEN_FINAL, FINAL_NORM, LOGITS, LOGITS_TOP10)
#
# Python trace format (mt_ref_step6.txt):
#   STEP=6 CP=<CPNAME> LAYER=<n> COUNT=... MIN=... MAX=... MEAN=... L2=... FIRST8=... HASH=...
#   STEP=6 CP=KV_WRITE LAYER=<n> COUNT=... K_MIN=... ... V_HASH=...
#   STEP=6 CP=<GLOBAL> ...
#   STEP=6 CP=LOGITS_TOP10 TOP10=<idx>:<val>,...
#
# Usage: py -3.13 compare_step6.py <cppTrace> <pyTrace>
import re
import sys
import math

def open_any(path):
    """Open a text file that may be UTF-8 or UTF-16 (PowerShell > redirect)."""
    with open(path, "rb") as fh:
        head = fh.read(4)
    if head.startswith(b"\xff\xfe") or head.startswith(b"\xfe\xff"):
        return open(path, encoding="utf-16")
    if head.startswith(b"\xef\xbb\xbf"):
        return open(path, encoding="utf-8-sig")
    return open(path, encoding="utf-8", errors="replace")

CPP_TRACE = sys.argv[1] if len(sys.argv) > 1 else r"F:\~dev\tools\parity_trace_cpp_step6.txt"
PY_TRACE  = sys.argv[2] if len(sys.argv) > 2 else r"F:\~dev\tools\mt_ref_step6.txt"

# C++ per-layer record: STEP=6 CP=LAYER_<layer>_<CPNAME> ...
re_cpp_layer = re.compile(
    r"STEP=(\d+) CP=LAYER_(\d+)_([A-Z0-9_]+) COUNT=(\S+) "
    r"MIN=(\S+) MAX=(\S+) MEAN=(\S+) L2=(\S+) FIRST8=(\S+) HASH=(\S+)")
# C++ KV write: STEP=6 CP=KV_WRITE LAYER=<layer> COUNT=... K_HASH=... V_HASH=...
re_cpp_kv = re.compile(
    r"STEP=(\d+) CP=KV_WRITE LAYER=(\d+) COUNT=(\S+) "
    r"K_MIN=(\S+) K_MAX=(\S+) K_MEAN=(\S+) K_L2=(\S+) K_HASH=(\S+) "
    r"V_MIN=(\S+) V_MAX=(\S+) V_MEAN=(\S+) V_L2=(\S+) V_HASH=(\S+)")
# C++ global (non-layer) record: STEP=6 CP=<CPNAME> COUNT=... HASH=...
re_cpp_global = re.compile(
    r"STEP=(\d+) CP=([A-Z0-9_]+) COUNT=(\S+) "
    r"MIN=(\S+) MAX=(\S+) MEAN=(\S+) L2=(\S+) FIRST8=(\S+) HASH=(\S+)")
# Python record: STEP=6 CP=<CPNAME>[ LAYER=<n>] COUNT=... HASH=...
re_py = re.compile(
    r"STEP=(\d+) CP=([A-Z0-9_]+)(?: LAYER=(\d+))? COUNT=(\S+) "
    r"MIN=(\S+) MAX=(\S+) MEAN=(\S+) L2=(\S+) FIRST8=(\S+) HASH=(\S+)")
# Python KV write: STEP=6 CP=KV_WRITE LAYER=<layer> ... K_HASH=... V_HASH=...
re_py_kv = re.compile(
    r"STEP=(\d+) CP=KV_WRITE LAYER=(\d+) COUNT=(\S+) "
    r"K_MIN=(\S+) K_MAX=(\S+) K_MEAN=(\S+) K_L2=(\S+) K_HASH=(\S+) "
    r"V_MIN=(\S+) V_MAX=(\S+) V_MEAN=(\S+) V_L2=(\S+) V_HASH=(\S+)")

def parse_cpp(path):
    layers, kv, globals_, top10 = {}, {}, {}, None
    for line in open_any(path):
        line = line.strip()
        m = re_cpp_kv.match(line)
        if m:
            step = int(m.group(1))
            if step == 6:
                kv[int(m.group(2))] = {
                    "count": int(m.group(3)),
                    "k_hash": m.group(8), "v_hash": m.group(13),
                }
            continue
        m = re_cpp_layer.match(line)
        if m:
            step = int(m.group(1))
            if step == 6:
                lay = int(m.group(2))
                cp = m.group(3)
                d = layers.setdefault(lay, {})
                # C++ emits ATTN_SCORES/ATTN_PROBS once per head (40x/layer);
                # the reference emits head 0 only. Keep the FIRST (head 0).
                if cp in ("ATTN_SCORES", "ATTN_PROBS") and cp in d:
                    continue
                d[cp] = {
                    "count": int(m.group(4)),
                    "min": m.group(5), "max": m.group(6),
                    "mean": m.group(7), "l2": m.group(8),
                    "first8": m.group(9), "hash": m.group(10),
                }
            continue
        if "CP=LOGITS_TOP10" in line:
            mm = re.match(r"STEP=(\d+) CP=LOGITS_TOP10 TOP10=(\S+)", line)
            if mm and int(mm.group(1)) == 6:
                top10 = mm.group(2)
            continue
        m = re_cpp_global.match(line)
        if m:
            step = int(m.group(1))
            if step == 6 and m.group(2) not in ("KV_WRITE",):
                globals_[m.group(2)] = {
                    "count": int(m.group(3)),
                    "min": m.group(4), "max": m.group(5),
                    "mean": m.group(6), "l2": m.group(7),
                    "first8": m.group(8), "hash": m.group(9),
                }
    return layers, kv, globals_, top10

def parse_py(path):
    layers, kv, globals_, top10 = {}, {}, {}, None
    for line in open_any(path):
        line = line.strip()
        m = re_py_kv.match(line)
        if m:
            step = int(m.group(1))
            if step == 6:
                kv[int(m.group(2))] = {
                    "count": int(m.group(3)),
                    "k_hash": m.group(8), "v_hash": m.group(13),
                }
            continue
        m = re_py.match(line)
        if m:
            step = int(m.group(1))
            if step != 6:
                continue
            cp = m.group(2)
            if cp == "KV_WRITE":
                continue
            lay = m.group(3)
            rec = {
                "count": int(m.group(4)),
                "min": m.group(5), "max": m.group(6),
                "mean": m.group(7), "l2": m.group(8),
                "first8": m.group(9), "hash": m.group(10),
            }
            if lay is not None:
                layers.setdefault(int(lay), {})[cp] = rec
            else:
                globals_[cp] = rec
            continue
        mm = re.match(r"STEP=(\d+) CP=LOGITS_TOP10 TOP10=(\S+)", line)
        if mm and int(mm.group(1)) == 6:
            top10 = mm.group(2)
    return layers, kv, globals_, top10

def close(a, b, rel=1e-6, abs_=1e-7):
    try:
        fa, fb = float(a), float(b)
    except ValueError:
        return a == b
    if math.isinf(fa) or math.isinf(fb):
        return fa == fb
    return abs(fa - fb) <= max(abs_, rel * max(abs(fa), abs(fb)))

# Ordered checkpoint names as executed inside a layer.
LAYER_CP_ORDER = [
    "ATTN_NORM", "Q", "K", "V", "Q_ROPE", "K_ROPE",
    "ATTN_SCORES", "ATTN_PROBS", "ATTN_VALUE", "O_PROJ", "ATTN_RESIDUAL",
    "FFN_NORM", "FFN_GATE", "FFN_UP", "SWIGLU", "FFN_DOWN", "LAYER_RESIDUAL",
]

def compare_fieldwise(name, a, b, diffs):
    bad = []
    for f in ("min", "max", "mean", "l2"):
        if not close(a[f], b[f]):
            bad.append(f"{f}: cpp={a[f]} py={b[f]}")
    if a["hash"] != b["hash"]:
        bad.append(f"hash: cpp={a['hash']} py={b['hash']}")
    if a["count"] != b["count"]:
        bad.append(f"count: cpp={a['count']} py={b['count']}")
    if bad:
        diffs.append((name, "; ".join(bad)))

def main():
    cpp_l, cpp_kv, cpp_g, cpp_top = parse_cpp(CPP_TRACE)
    py_l,  py_kv,  py_g,  py_top  = parse_py(PY_TRACE)

    print(f"CPP trace: layers={len(cpp_l)} kv={len(cpp_kv)} globals={sorted(cpp_g)}")
    print(f"PY  trace: layers={len(py_l)} kv={len(py_kv)} globals={sorted(py_g)}")

    # ---- KV_WRITE per layer ----
    diffs = []
    for layer in sorted(py_kv):
        a = cpp_kv.get(layer)
        b = py_kv[layer]
        if a is None:
            diffs.append((f"GLOBAL KV L={layer}", "missing in C++ trace"))
            continue
        if a["k_hash"] != b["k_hash"] or a["v_hash"] != b["v_hash"]:
            diffs.append((f"L={layer} CP=KV_WRITE",
                          f"K cpp={a['k_hash']} py={b['k_hash']} "
                          f"V cpp={a['v_hash']} py={b['v_hash']}"))

    # ---- Per-layer checkpoints in execution order ----
    for layer in range(64):
        ca = cpp_l.get(layer, {})
        pb = py_l.get(layer, {})
        for cp in LAYER_CP_ORDER:
            if cp not in pb:
                continue
            name = f"L={layer} CP={cp}"
            if cp not in ca:
                diffs.append((name, "missing in C++ trace"))
            else:
                compare_fieldwise(name, ca[cp], pb[cp], diffs)

    # ---- Globals ----
    for cp in sorted(py_g):
        name = f"GLOBAL CP={cp}"
        if cp not in cpp_g:
            diffs.append((name, "missing in C++ trace"))
        else:
            compare_fieldwise(name, cpp_g[cp], py_g[cp], diffs)

    # ---- Report in EXECUTION ORDER: EMBED, L0..L63 (KV after K_ROPE), finals ----
    def exec_key(diff_name):
        m = re.match(r"L=(\d+) CP=(\w+)", diff_name)
        if m:
            lay, cp = int(m.group(1)), m.group(2)
            if cp == "KV_WRITE":
                idx = LAYER_CP_ORDER.index("K_ROPE") + 1
            else:
                idx = LAYER_CP_ORDER.index(cp) if cp in LAYER_CP_ORDER else 99
            return (lay, idx)
        m = re.match(r"GLOBAL CP=(\w+)", diff_name)
        if m:
            order = {"EMBED": (-1, 0), "FINAL_NORM": (64, 0), "LOGITS": (65, 0)}
            return order.get(m.group(1), (66, 0))
        return (67, 0)

    diffs.sort(key=lambda d: exec_key(d[0]))

    # ---- Per-layer divergence magnitude per checkpoint (relative L2 drift) ----
    print()
    print("Per-layer relative L2 drift (|L2cpp-L2py| / max) per checkpoint:")
    hdr = "layer".rjust(5) + "".join(cp[:8].rjust(10) for cp in LAYER_CP_ORDER)
    print(hdr)
    for layer in range(64):
        ca = cpp_l.get(layer, {})
        pb = py_l.get(layer, {})
        row = []
        for cp in LAYER_CP_ORDER:
            if cp not in pb or cp not in ca:
                row.append("".rjust(10))
                continue
            try:
                l2c, l2p = float(ca[cp]["l2"]), float(pb[cp]["l2"])
            except ValueError:
                row.append("".rjust(10))
                continue
            denom = max(abs(l2c), abs(l2p), 1e-30)
            row.append(f"{abs(l2c-l2p)/denom:.1e}".rjust(10))
        print(str(layer).rjust(5) + "".join(row))

    # ---- Top10 ----
    print()
    print(f"CPP TOP10: {cpp_top}")
    print(f"PY  TOP10: {py_top}")

    print()
    if not diffs:
        print("=== ALL STEP-6 CHECKPOINTS MATCH ===")
        return
    print(f"=== {len(diffs)} DIVERGENT CHECKPOINTS (first {min(30, len(diffs))} shown, execution order) ===")
    for name, msg in diffs[:30]:
        print(f"  {name}  {msg}")
    print(f"FIRST DIVERGENCE (execution order): {diffs[0][0]}")

if __name__ == "__main__":
    main()