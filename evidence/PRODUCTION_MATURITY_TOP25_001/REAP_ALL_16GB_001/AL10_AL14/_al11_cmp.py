import re
import json
from pathlib import Path

def read_text(p):
    b = Path(p).read_bytes()
    if len(b) >= 2 and b[0] == 0xFF and b[1] == 0xFE:
        return b.decode("utf-16-le")
    if len(b) >= 4 and b[1] == 0 and b[3] == 0 and b[0] != 0:
        try:
            return b.decode("utf-16-le")
        except Exception:
            pass
    return b.decode("utf-8", errors="replace")

pat = re.compile(
    r"\[STAGE_DIGEST\]\s+side=(\S+)\s+key=(\S+)\s+pos=(\d+)\s+n=(\d+)\s+"
    r"l2=(\S+)\s+max_abs=(\S+)\s+min=(\S+)\s+max=(\S+)\s+sum=(\S+)\s+"
    r"fnv=([0-9a-fA-F]+)\s+nf=(\d+)"
)

def parse_ordered(path):
    t = read_text(path)
    rows = []
    for m in pat.finditer(t):
        rows.append(
            {
                "key": m.group(2),
                "pos": int(m.group(3)),
                "fnv": m.group(10).lower(),
                "l2": m.group(5),
                "n": int(m.group(4)),
            }
        )
    return rows

ev = Path(r"G:\~dev\rawrxd\evidence\REAP16_BATCH_001\CALIBRATED_001\AL09")
full = parse_ordered(ev / "al09_full.out.txt")
phys = parse_ordered(ev / "al09_phys2.err.txt")
Fi = {(r["pos"], r["key"]): (i, r) for i, r in enumerate(full)}
Pi = {(r["pos"], r["key"]): (i, r) for i, r in enumerate(phys)}

first = None
matches = 0
checked = 0
missing_window = []
for i, r in enumerate(phys):
    k = (r["pos"], r["key"])
    in_window = (
        (r["pos"] == 2 and r["key"] in ("LAYER17_OUT", "FINAL_NORM", "PROMPT_POST_LAYERS", "PROMPT_FINAL_NORM"))
        or (r["pos"] == 2 and any(x in r["key"] for x in ["FINAL", "LOGIT", "ARGMAX", "PROMPT_POST", "LM_"]))
        or (r["pos"] == 3)
        or (r["pos"] == 2 and re.search(r"(LAYER|ATTN|FFN|POST|NORM|V_|Q_|K_)(1[89]|[2-5][0-9]|6[01])", r["key"]))
    )
    if k not in Fi:
        if in_window:
            missing_window.append({"pos": r["pos"], "key": r["key"], "phys_fnv": r["fnv"]})
        continue
    fr = Fi[k][1]
    checked += 1
    if fr["fnv"] == r["fnv"]:
        matches += 1
    else:
        first = {
            "pos": r["pos"],
            "key": r["key"],
            "full_fnv": fr["fnv"],
            "phys_fnv": r["fnv"],
            "full_l2": fr["l2"],
            "phys_l2": r["l2"],
            "phys_ord": i,
            "full_ord": Fi[k][0],
        }
        break

print("checked", checked, "matches_until_break", matches)
print("FIRST_DIVERGENT", json.dumps(first))
print("missing_in_full_window_count", len(missing_window))

print("\n=== pos=2 shared keys ===")
for key in sorted({r["key"] for r in phys if r["pos"] == 2} & {r["key"] for r in full if r["pos"] == 2}):
    f = Fi[(2, key)][1]
    p = Pi[(2, key)][1]
    m = f["fnv"] == p["fnv"]
    print(("MATCH" if m else "DIFF "), key, "full=", f["fnv"], "phys=", p["fnv"])

print("\n=== pos=3 shared keys ===")
for key in sorted({r["key"] for r in phys if r["pos"] == 3} & {r["key"] for r in full if r["pos"] == 3}):
    f = Fi[(3, key)][1]
    p = Pi[(3, key)][1]
    m = f["fnv"] == p["fnv"]
    print(("MATCH" if m else "DIFF "), key, "full=", f["fnv"], "phys=", p["fnv"])

print("\nFULL keys pos2", sorted({r["key"] for r in full if r["pos"] == 2}))
print("PHYS keys pos2", sorted({r["key"] for r in phys if r["pos"] == 2}))
print("FULL keys pos3", sorted({r["key"] for r in full if r["pos"] == 3}))
print("PHYS keys pos3", sorted({r["key"] for r in phys if r["pos"] == 3}))

# first DIFF in pos=3 shared in phys execution order
print("\n=== first pos3 mismatch in phys order ===")
for r in phys:
    if r["pos"] != 3:
        continue
    k = (3, r["key"])
    if k not in Fi:
        print("MISSING_FULL", r["key"], r["fnv"])
        break
    if Fi[k][1]["fnv"] != r["fnv"]:
        print("DIFF", r["key"], "full", Fi[k][1]["fnv"], "phys", r["fnv"])
        break
    print("OK", r["key"])

layer_pat = re.compile(r"AL09_LAYER_OUT layer=(\d+) tok=(\d+) n=(\d+) fnv=([0-9a-fA-F]+)")

def layers(path):
    d = {}
    for m in layer_pat.finditer(read_text(path)):
        d[(int(m.group(2)), int(m.group(1)))] = m.group(4).lower()
    return d

fl = layers(ev / "al09_full_cmd.err.txt")
pl = layers(ev / "al09_phys_layer.err.txt")
print("\nFULL_CMD toks", sorted({t for t, l in fl}), "max_layer", {t: max(l for tt, l in fl if tt == t) for t in sorted({t for t, l in fl})})
for ly in range(0, 62):
    if (3, ly) in fl and (3, ly) in pl:
        if fl[(3, ly)] != pl[(3, ly)]:
            print("FIRST_LAYER_OUT_DIFF tok3 layer", ly, fl[(3, ly)], pl[(3, ly)])
            break
    elif (3, ly) in pl and (3, ly) not in fl:
        lm = None
        for l2 in range(ly - 1, -1, -1):
            if (3, l2) in fl and (3, l2) in pl and fl[(3, l2)] == pl[(3, l2)]:
                lm = l2
                break
        print("FULL missing tok3 layer", ly, "last_exact", lm, "phys_fnv", pl[(3, ly)])
        break

# needles
for name in ["al09_full.out.txt", "al09_full.err.txt", "al09_phys2.err.txt", "al09_full.meta.txt", "al09_phys2.meta.txt"]:
    p = ev / name
    if not p.exists():
        continue
    t = read_text(p)
    for pat2 in [
        r"ARGMAX_TOKEN=\S+",
        r"LOGITS_ARGMAX_END[^\n]*",
        r"EXIT=%?-?\d+",
        r"EXIT=-?\d+",
        r"bad_alloc",
        r"0xC000[0-9A-Fa-f]+",
        r"exception[^\n]{0,120}",
        r"n_past=\d+",
        r"kv[^\n]{0,80}",
    ]:
        ms = re.findall(pat2, t, flags=re.I)
        if ms:
            print(name, pat2, "->", ms[:8])
