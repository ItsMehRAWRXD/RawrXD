import numpy as np, json
from pathlib import Path

ev = Path(r"F:\rawrxd\evidence\DEEPSEEK2_DIV_20261121\op_trace_run\op_trace")
ref = Path(r"F:\rawrxd\evidence\LLAMA_REF_MOE_20261121\ref\pos0")

meta = json.load(open(ev / "cpu_pos0_op_metadata.json"))
names = {o["op_index"]: o["op"] for o in meta["ops"]}

cache = {}
for p in ref.glob("*.bin"):
    if "__dup" in p.name:
        continue
    a = np.fromfile(p, dtype="<f4")
    cache.setdefault(a.size, []).append((p.name, a))

for idx in range(6, 30):
    f = ev / f"cpu_pos0_op{idx}.f32"
    if not f.exists():
        continue
    d = np.fromfile(f, dtype="<f4").astype(np.float64)
    best = (None, -2.0, 0.0)
    for nm, a in cache.get(d.size, []):
        a = a.astype(np.float64)
        na = np.linalg.norm(a)
        nd = np.linalg.norm(d)
        c = float(d @ a) / (na * nd) if na > 0 and nd > 0 else float("nan")
        if c > best[1]:
            best = (nm, c, float(np.max(np.abs(d - a))))
    nm = names.get(idx, "?")
    print("op%2d %-28s n=%-6d best=%s cos=%.9f max_abs=%.4g"
          % (idx, nm, d.size, best[0], best[1], best[2]))