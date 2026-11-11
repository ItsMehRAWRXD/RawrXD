#!/usr/bin/env python3
"""Reverse-engineer the Qwen4Exp tensor contract before native lowering.

This tool is deliberately read-only. It consumes the trusted GGUF manifest JSON
emitted by deep2_shard_probe and produces a machine-readable operator contract.
It never marks an operator executable; the native runtime must still provide a
Vulkan implementation and independent parity receipt.
"""
from __future__ import annotations
import argparse, json, re, sys
from pathlib import Path

BLOCK_RE = re.compile(r"^blk\.(\d+)\.")

def load(paths):
    tensors = []
    for p in paths:
        text = Path(p).read_text(encoding="utf-8")
        # deep2_shard_probe emits Windows paths with literal backslashes;
        # normalize them before JSON parsing.
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            obj = json.loads(text.replace("\\", "/"))
        if obj.get("arch") not in ("", "qwen4exp"):
            raise SystemExit(f"{p}: expected qwen4exp, got {obj.get('arch')!r}")
        tensors.extend(obj.get("tensors", []))
    return tensors

def shape(t): return list(t.get("dims", []))
def by_name(ts, pat): return [t for t in ts if re.search(pat, t["name"])]
def one(ts, suffix): return next((t for t in ts if t["name"].endswith(suffix)), None)

def contract(ts):
    names = {t["name"] for t in ts}
    blocks = sorted({int(m.group(1)) for t in ts if (m := BLOCK_RE.match(t["name"]))})
    def dims(suffix):
        t = one(ts, suffix)
        return shape(t) if t else None
    hc = by_name(ts, r"\.hc_(attn|ffn)_(down|inject|norm|up)\.weight$")
    experts = by_name(ts, r"\.ffn_(gate|up|down)_exps\.weight$")
    qsa = by_name(ts, r"\.indexer\.(q_proj|k_proj|q_norm|k_norm)\.weight$")
    ple = by_name(ts, r"\.ple_(conv1d|key|norm_conv|norm_key|norm_query|value)\.weight$")
    gdn = by_name(ts, r"\.ssm_(a|alpha|beta|conv1d|dt|norm|out)(\.weight)?$")
    # These are real tensors, but they are auxiliary/global ownership rather
    # than block-local operator parameters. Keep them explicit instead of
    # silently dropping them or inflating the block-local count.
    gdn_aux = by_name(ts, r"\.ssm_dt\.bias$")
    ple_aux = by_name(ts, r"^per_layer_token_embd\.weight$")
    hc_aux = by_name(ts, r"^output_hc_(down|norm|up)\.weight$")
    checks = []
    def check(ok, msg): checks.append({"ok": bool(ok), "detail": msg})
    check(len(blocks) == 48, f"block_count={len(blocks)} (expected 48 from canonical Qwen4Exp manifest)")
    check(len(hc) == 48 * 8, f"hyperconnection tensors={len(hc)} (expected 384)")
    check(len(experts) == 48 * 3, f"expert projection tensors={len(experts)} (expected 144)")
    check(bool(qsa), f"QSA indexer tensors={len(qsa)}")
    check(bool(ple), f"PLE tensors={len(ple)}")
    check(bool(gdn), f"GDN tensors={len(gdn)}")
    check(len(gdn_aux) == 36, f"GDN auxiliary dt.bias tensors={len(gdn_aux)} (expected 36)")
    check(len(ple_aux) == 1, f"PLE auxiliary global embedding tensors={len(ple_aux)} (expected 1)")
    check(len(hc_aux) == 3, f"HC auxiliary global tensors={len(hc_aux)} (expected 3)")
    check(dims("blk.0.hc_attn_inject.weight") == [10240, 4], f"HC inject shape={dims('blk.0.hc_attn_inject.weight')}")
    check(dims("blk.0.hc_attn_down.weight") == [10240, 320], f"HC down shape={dims('blk.0.hc_attn_down.weight')}")
    check(dims("blk.0.hc_attn_up.weight") == [320, 10240], f"HC up shape={dims('blk.0.hc_attn_up.weight')}")
    check(dims("blk.0.ssm_a") == [48], f"GDN A shape={dims('blk.0.ssm_a')}")
    check(dims("blk.1.ple_conv1d.weight") == [4, 10240], f"PLE conv shape={dims('blk.1.ple_conv1d.weight')}")
    check(dims("blk.0.ffn_gate_exps.weight") == [2560, 640, 512], f"MoE gate shape={dims('blk.0.ffn_gate_exps.weight')}")
    check(dims("blk.0.ffn_down_exps.weight") == [640, 2560, 512], f"MoE down shape={dims('blk.0.ffn_down_exps.weight')}")
    return {
        "schema": "rawrxd.deep2.qwen4exp.operator_contract.v1",
        "architecture": "qwen4exp",
        "tensor_count": len(ts), "block_count": len(blocks),
        "operators": {
            "PLE": {"state": "REVERSE_ENGINEERED", "tensor_count": len(ple), "primary_tensor_count": len(ple), "auxiliary_tensor_count": len(ple_aux), "conv_kernel": 4, "channels": 10240, "reference": "3rdparty/r9700-stack/r9700_vllm/ple/short_conv.py"},
            "Hyperconnection": {"state": "REVERSE_ENGINEERED", "tensor_count": len(hc), "primary_tensor_count": len(hc), "auxiliary_tensor_count": len(hc_aux), "stream_count": 4, "low_rank": 320, "hidden": 10240, "reference": "3rdparty/r9700-stack/r9700_vllm/hc.py"},
            "QSA": {"state": "REVERSE_ENGINEERED", "tensor_count": len(qsa), "indexer_top_k": 2048, "reference": "3rdparty/r9700-stack/r9700_vllm/attn/qsa.py"},
            "GDN": {"state": "REVERSE_ENGINEERED", "tensor_count": len(gdn), "primary_tensor_count": len(gdn), "auxiliary_tensor_count": len(gdn_aux), "inner_size": 6144, "state_size": 128, "groups": 16, "reference": "3rdparty/r9700-stack/r9700_vllm/models/gdn.py"},
            "SparseMoE": {"state": "REVERSE_ENGINEERED", "tensor_count": len(experts), "experts": 512, "top_k": 10, "expert_width": 640, "reference": "3rdparty/r9700-stack/r9700_vllm/moe/route.py"},
        },
        "checks": checks,
        "native_execution": {"PLE": False, "Hyperconnection": False, "QSA": False, "GDN": False, "SparseMoE": False},
        "certification": "NOT_CERTIFIED",
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", action="append", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    out = contract(load(a.manifest))
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print(f"QWEN4EXP_CONTRACT={a.out}")
    print(f"TENSORS={out['tensor_count']} BLOCKS={out['block_count']} CHECKS_PASS={sum(c['ok'] for c in out['checks'])}/{len(out['checks'])}")
    return 0 if all(c["ok"] for c in out["checks"]) else 2
if __name__ == "__main__": sys.exit(main())

