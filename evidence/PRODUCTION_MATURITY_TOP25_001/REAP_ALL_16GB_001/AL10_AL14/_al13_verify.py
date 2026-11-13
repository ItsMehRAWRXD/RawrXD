"""AL13: verify phys CALIB expert tensor families+bias vs FULL selected originals."""
import hashlib
import json
import sys
from pathlib import Path

try:
    from gguf import GGUFReader
    import numpy as np
except Exception as e:
    print("IMPORT_FAIL", e)
    sys.exit(2)

FULL = r"F:\ollamamodels\MiniMax-M2.7-Q4_K_M\MiniMax-M2.7-Q4_K_M\MiniMax-M2.7-Q4_K_M-00001-of-00003.gguf"
PHYS = r"F:\ollamamodels\MiniMax-M2.7-REAP16-CALIB-ROUTE27\MiniMax-M2.7-Q4_K_M-00001-of-00003.gguf"
SEL = r"G:\~dev\rawrxd\evidence\REAP16_BATCH_001\CALIBRATED_001\selection_calib_top27.json"
OUT = Path(r"G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\REAP_ALL_16GB_001\AL10_AL14\AL13_EXPERT_MAPPING.json")

FAMILIES = [
    "ffn_gate_exps.weight",
    "ffn_up_exps.weight",
    "ffn_down_exps.weight",
    "ffn_gate_inp.weight",
    "exp_probs_b.bias",
]


def meta_kv(reader):
    out = {}
    for f in reader.fields.values():
        name = f.name
        if any(k in name for k in ("expert", "expert_count", "moe", "n_expert")):
            try:
                val = f.parts[-1][0] if hasattr(f.parts[-1], "__getitem__") else f.parts[-1]
                out[name] = int(val) if hasattr(val, "__int__") else str(val)
            except Exception:
                out[name] = str(f.parts)
    return out


def tensor_map(path):
    r = GGUFReader(path, "r")
    m = {}
    for t in r.tensors:
        m[t.name] = t
    return r, m


def slice_equal(full_raw, phys_raw, full_E, phys_E, selected_sorted, kind):
    """Compare each selected expert slice FULL[e] vs PHYS[slot]."""
    if kind == "exps":
        # last dim experts or first? MiniMax Q4_K often [n_embd, n_experts] packing in raw by expert stride
        n = len(full_raw)
        stride = n // full_E
        if len(phys_raw) // phys_E != stride:
            return {"ok": False, "why": "stride_mismatch", "full_stride": stride, "phys_stride": len(phys_raw) // phys_E}
        bad = []
        for slot, e in enumerate(selected_sorted):
            a = full_raw[e * stride : (e + 1) * stride]
            b = phys_raw[slot * stride : (slot + 1) * stride]
            if a != b:
                bad.append({"slot": slot, "expert": e, "full_sha12": hashlib.sha256(a).hexdigest()[:12], "phys_sha12": hashlib.sha256(b).hexdigest()[:12]})
                if len(bad) >= 5:
                    break
        return {"ok": len(bad) == 0, "checked": len(selected_sorted), "bad_head": bad, "stride": stride}
    if kind == "gate_inp":
        # rows=E cols=H float32 typically; raw is E*H*4 or H*E
        # compare by expert row using shape
        return None
    if kind == "bias":
        stride = 4  # f32
        if len(full_raw) // full_E != stride or len(phys_raw) // phys_E != stride:
            # try raw length ratio
            stride_f = len(full_raw) // full_E
            stride_p = len(phys_raw) // phys_E
            if stride_f != stride_p:
                return {"ok": False, "why": "bias_stride_mismatch", "sf": stride_f, "sp": stride_p}
            stride = stride_f
        bad = []
        for slot, e in enumerate(selected_sorted):
            a = full_raw[e * stride : (e + 1) * stride]
            b = phys_raw[slot * stride : (slot + 1) * stride]
            if a != b:
                bad.append({"slot": slot, "expert": e})
                if len(bad) >= 5:
                    break
        return {"ok": len(bad) == 0, "checked": len(selected_sorted), "bad_head": bad, "stride": stride}
    return {"ok": False, "why": "unknown_kind"}


def main():
    sel = json.loads(Path(SEL).read_text(encoding="utf-8"))
    fr, fm = tensor_map(FULL)
    pr, pm = tensor_map(PHYS)
    full_meta = meta_kv(fr)
    phys_meta = meta_kv(pr)

    # expert_count from metadata fields
    def find_expert_count(meta, tensors):
        for k, v in meta.items():
            if "expert_count" in k or k.endswith(".expert_count"):
                return k, v
        # infer from tensor shape of blk.0.ffn_gate_exps.weight
        t = tensors.get("blk.0.ffn_gate_exps.weight")
        if t is not None:
            shape = list(map(int, t.shape))
            return "infer_from_ffn_gate_exps.shape", shape
        return None, None

    f_ek, f_ev = find_expert_count(full_meta, fm)
    p_ek, p_ev = find_expert_count(phys_meta, pm)

    layers_to_check = [0, 1, 17]
    results = []
    families_present = {}
    for fam in FAMILIES + ["ffn_shexp.weight", "ffn_gate_shexp.weight"]:
        families_present[fam] = {
            "full_L0": f"blk.0.{fam}" in fm if not fam.startswith("exp") else f"blk.0.{fam}" in fm,
            "phys_L0": (f"blk.0.{fam}" in pm),
        }
    # fix bias name
    families_present = {}
    for fam in FAMILIES:
        n0 = f"blk.0.{fam}"
        families_present[fam] = {"full": n0 in fm, "phys": n0 in pm}
    for extra in ["ffn_shexp.weight", "ffn_gate_shexp.weight", "ffn_up_shexp.weight", "ffn_down_shexp.weight"]:
        n0 = f"blk.0.{extra}"
        families_present[extra] = {"full": n0 in fm, "phys": n0 in pm}

    for layer in layers_to_check:
        L = [x for x in sel["layers"] if x["layer"] == layer][0]
        selected_sorted = sorted(e["expert"] for e in L["selected"])
        assert len(selected_sorted) == 27
        layer_res = {"layer": layer, "selected_sorted": selected_sorted, "families": {}}
        for fam in FAMILIES:
            fname = f"blk.{layer}.{fam}"
            if fname not in fm or fname not in pm:
                layer_res["families"][fam] = {"status": "MISSING", "full": fname in fm, "phys": fname in pm}
                continue
            ft = fm[fname]
            pt = pm[fname]
            fb = np.ascontiguousarray(ft.data).tobytes()
            pb = np.ascontiguousarray(pt.data).tobytes()
            fshape = list(map(int, ft.shape))
            pshape = list(map(int, pt.shape))
            if "exps.weight" in fam:
                # expert axis: usually last
                full_E = fshape[-1] if len(fshape) >= 2 else None
                phys_E = pshape[-1] if len(pshape) >= 2 else None
                # if shapes look like [E, ...]
                if full_E not in (256, 27) and fshape[0] in (256, 27):
                    full_E = fshape[0]
                if phys_E not in (256, 27) and pshape[0] in (256, 27):
                    phys_E = pshape[0]
                # fallback via nbytes ratio
                if full_E not in (256, 27):
                    full_E = 256
                if phys_E not in (256, 27):
                    phys_E = 27
                cmp = slice_equal(fb, pb, full_E, phys_E, selected_sorted, "exps")
                layer_res["families"][fam] = {
                    "status": "PASS" if cmp.get("ok") else "FAIL",
                    "full_shape": fshape,
                    "phys_shape": pshape,
                    "full_E": full_E,
                    "phys_E": phys_E,
                    "cmp": cmp,
                }
            elif fam == "ffn_gate_inp.weight":
                # router: FULL E=256, PHYS E=27 — compare selected rows
                # shape often [E, H] or [H, E]
                if fshape[0] in (256, 27):
                    full_E, H = fshape[0], fshape[1]
                    row_major = True
                elif fshape[1] in (256, 27):
                    H, full_E = fshape[0], fshape[1]
                    row_major = False
                else:
                    layer_res["families"][fam] = {"status": "OPEN_SHAPE", "full_shape": fshape, "phys_shape": pshape}
                    continue
                if pshape[0] in (27, 256):
                    phys_E, pH = pshape[0], pshape[1]
                    prow = True
                else:
                    pH, phys_E = pshape[0], pshape[1]
                    prow = False
                esize = (H * 4) if ft.data.dtype.itemsize else (len(fb) // full_E)
                # use numpy reshape
                farr = np.ascontiguousarray(ft.data)
                parr = np.ascontiguousarray(pt.data)
                bad = []
                for slot, e in enumerate(selected_sorted):
                    if row_major:
                        a = np.ascontiguousarray(farr[e]).tobytes()
                    else:
                        a = np.ascontiguousarray(farr[:, e]).tobytes()
                    if prow:
                        b = np.ascontiguousarray(parr[slot]).tobytes()
                    else:
                        b = np.ascontiguousarray(parr[:, slot]).tobytes()
                    if a != b:
                        bad.append({"slot": slot, "expert": e})
                        if len(bad) >= 5:
                            break
                layer_res["families"][fam] = {
                    "status": "PASS" if not bad else "FAIL",
                    "full_shape": fshape,
                    "phys_shape": pshape,
                    "checked": 27,
                    "bad_head": bad,
                }
            elif fam.endswith("bias"):
                farr = np.ascontiguousarray(ft.data).reshape(-1)
                parr = np.ascontiguousarray(pt.data).reshape(-1)
                bad = []
                for slot, e in enumerate(selected_sorted):
                    if float(farr[e]) != float(parr[slot]):
                        bad.append({"slot": slot, "expert": e, "full": float(farr[e]), "phys": float(parr[slot])})
                        if len(bad) >= 5:
                            break
                layer_res["families"][fam] = {
                    "status": "PASS" if not bad else "FAIL",
                    "full_len": int(farr.size),
                    "phys_len": int(parr.size),
                    "checked": 27,
                    "bad_head": bad,
                }
            else:
                layer_res["families"][fam] = {"status": "SKIP"}
        results.append(layer_res)

    # count expert tensors phys vs full
    def count_exps(tensors):
        c = {"gate_exps": 0, "up_exps": 0, "down_exps": 0, "gate_inp": 0, "bias": 0}
        for n in tensors:
            if n.endswith("ffn_gate_exps.weight"):
                c["gate_exps"] += 1
            elif n.endswith("ffn_up_exps.weight"):
                c["up_exps"] += 1
            elif n.endswith("ffn_down_exps.weight"):
                c["down_exps"] += 1
            elif n.endswith("ffn_gate_inp.weight"):
                c["gate_inp"] += 1
            elif n.endswith("exp_probs_b.bias"):
                c["bias"] += 1
        return c

    report = {
        "gate": "AL13",
        "PROMOTE": 0,
        "CERTIFIED": 0,
        "full_path": FULL,
        "phys_path": PHYS,
        "selection": SEL,
        "full_expert_meta": {"key": f_ek, "value": f_ev, "fields": full_meta},
        "phys_expert_meta": {"key": p_ek, "value": p_ev, "fields": phys_meta},
        "families_present_L0": families_present,
        "tensor_family_counts": {"full": count_exps(fm), "phys": count_exps(pm)},
        "layers": results,
        "note": "expert_count metadata on FULL expected 256; PHYS tensors compacted to E=27 per layer",
    }
    # overall
    statuses = []
    for lr in results:
        for fam, v in lr["families"].items():
            statuses.append(v.get("status"))
    report["overall"] = "PASS" if statuses and all(s == "PASS" for s in statuses) else ("FAIL" if "FAIL" in statuses else "OPEN")
    OUT.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print("WROTE", OUT)
    print("OVERALL", report["overall"])
    print("full_meta_expert", f_ek, f_ev)
    print("phys_meta_expert", p_ek, p_ev)
    for lr in results:
        for fam, v in lr["families"].items():
            print(f"L{lr['layer']} {fam} {v.get('status')}")


if __name__ == "__main__":
    main()
