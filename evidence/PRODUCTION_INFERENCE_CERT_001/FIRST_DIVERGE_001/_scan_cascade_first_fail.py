import glob, os, numpy as np

os.chdir(r"G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001")
gd = "stage_dump_ffn_down_2_xdonediv_cascade"
ref = "stage_dump_gpu_ref"


def load(p):
    return np.fromfile(p, dtype=np.float32)


def find(d, pat):
    g = sorted(glob.glob(os.path.join(d, pat)))
    return g[0] if g else None


def cmp(a, b, tol):
    if a is None or b is None:
        return None
    A, B = load(a), load(b)
    n = min(len(A), len(B))
    d = np.abs(A[:n] - B[:n])
    mx = float(d.max()) if n else float("nan")
    ngt = int(np.sum(d > tol))
    return mx, ngt, n, mx > tol


sites = []
for L in range(0, 22):
    for key, tol in [
        ("ATTN_PRE_O", 1e-4),
        ("ATTN_OUT", 1e-4),
        ("FFN_DOWN", 1e-5),
        ("FFN_ACT", 1e-5),
        ("FFN_GATE", 1e-5),
        ("FFN_UP", 1e-5),
    ]:
        a = find(gd, f"deep2_{key}_{L}_pos0*.bin")
        b = (
            find(ref, f"llama_{key}_{L}_pos0*.bin")
            or find(ref, f"deep2_{key}_{L}_pos0*.bin")
        )
        r = cmp(a, b, tol)
        if r:
            mx, ngt, n, fail = r
            sites.append((L, key, mx, ngt, fail, tol))

for key, tol in [("FINAL_NORM", 1e-4)]:
    a = find(gd, f"deep2_{key}_pos0*.bin")
    b = (
        find(ref, f"llama_{key}_pos0*.bin")
        or find(ref, "llama_REF_FINAL*.bin")
        or find("_cmp_attn_out14_stage", "llama_REF_FINAL*.bin")
    )
    r = cmp(a, b, tol)
    if r:
        mx, ngt, n, fail = r
        sites.append((99, key, mx, ngt, fail, tol))

print("LAYER KEY maxAbs n_gt FAIL tol")
for L, key, mx, ngt, fail, tol in sites:
    mark = "FAIL" if fail else "ok"
    print(f"{L:2d} {key:12s} {mx:.6e} n_gt={ngt} {mark} tol={tol}")

prio = {
    "ATTN_PRE_O": 0,
    "ATTN_OUT": 1,
    "FFN_GATE": 2,
    "FFN_UP": 3,
    "FFN_ACT": 4,
    "FFN_DOWN": 5,
    "FINAL_NORM": 6,
}
fails = []
for L, key, mx, ngt, fail, tol in sites:
    if not fail:
        continue
    # FFN_DOWN_2 closed under tol already excluded by fail flag
    if key == "FFN_DOWN" and L == 2 and mx <= 1e-5:
        continue
    fails.append((L, key, mx, ngt))
fails.sort(key=lambda t: (t[0], prio.get(t[1], 9)))
print("---")
print("FAILS_ORDERED:")
for t in fails[:40]:
    print(t)
print("TRUE_FIRST=", fails[0] if fails else None)

# Also compare against _cmp_attn_out14_stage refs for 14
print("--- ATTN14 vs stage refs ---")
for key, tol in [("ATTN_PRE_O_14", 1e-4), ("ATTN_OUT_14", 1e-4)]:
    a = find(gd, f"deep2_{key}_pos0*.bin")
    b = find("_cmp_attn_out14_stage", f"deep2_{key}*.bin") or find(
        "_cmp_attn_out14_stage", f"llama_{key.replace('_14','')}*.bin"
    )
    # prefer llama for OUT
    if key == "ATTN_OUT_14":
        b = find("_cmp_attn_out14_stage", "llama_ATTN_OUT_14.bin") or b
    if key == "ATTN_PRE_O_14":
        b = find("_cmp_attn_out14_stage", "deep2_ATTN_PRE_O_14.bin") or b
    r = cmp(a, b, tol)
    print(key, "a", a, "b", b, "r", r)

# Compare cascade ATTN_OUT_14 to llama ref in stage folder and gpu_ref
print("--- direct ---")
for name in [
    "ATTN_PRE_O_14",
    "ATTN_OUT_14",
    "FINAL_NORM",
]:
    a = find(gd, f"deep2_{name}_pos0*.bin")
    candidates = [
        find(ref, f"llama_{name}_pos0*.bin"),
        find(ref, f"deep2_{name}_pos0*.bin"),
        find("_cmp_attn_out14_stage", f"llama_{name}.bin"),
        find("_cmp_attn_out14_stage", f"deep2_{name}.bin"),
        find("_cmp_attn_out14_stage", f"deep2_{name}_pos0*.bin"),
        find("_cmp_attn_out14_stage", "llama_REF_FINAL_HIDDEN_pos0.bin")
        if name == "FINAL_NORM"
        else None,
    ]
    for b in candidates:
        if b:
            r = cmp(a, b, 1e-4)
            print(name, "vs", b, "->", r)
