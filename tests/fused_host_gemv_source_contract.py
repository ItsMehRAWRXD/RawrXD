#!/usr/bin/env python3
"""Source-shape regression gate ONLY. Does not claim Vulkan correctness or TPS."""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]

def function_body(path: str, name: str) -> str:
    source = (ROOT / path).read_text(encoding="utf-8")
    start = source.find("bool VulkanCompute::" + name + "(")
    if start < 0:
        raise AssertionError(f"{path}: missing {name}")
    opening = source.find("{", start)
    if opening < 0:
        raise AssertionError(f"{path}: missing body for {name}")
    depth = 1
    i = opening + 1
    while i < len(source) and depth:
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
        i += 1
    if depth:
        raise AssertionError(f"{path}: unbalanced body for {name}")
    return source[start:i]

FUSED = {
    "src/deep2/vulkan_compute_engine_adapter.cpp": {
        "DispatchGEMV": "RunWeightHostRoundTrip",
        "DispatchGEMVQuant": "RunWeightHostRoundTrip",
    },
    "src/deep2/vulkan_compute_adapter_fused.cpp": {
        "DispatchGEMVFusedQ4KT": "RunWeightHostBatchQ4K",
        "DispatchGEMVQ6kPacked": "RunWeightHostRoundTrip",
    },
}
failures = []
for file, methods in FUSED.items():
    for method, call in methods.items():
        try:
            body = function_body(file, method)
            if "backend_->" + call + "(" not in body:
                raise AssertionError(f"{method} missing fused backend call")
            for old in ("backend_->UploadVector(", "backend_->DownloadVector("):
                if old in body:
                    raise AssertionError(f"{method} reintroduced serialized host transfer")
        except AssertionError as exc:
            failures.append(str(exc))

try:
    quant = function_body("src/deep2/vulkan_compute_engine_adapter.cpp",
                          "DispatchGEMVQuant")
    if "ggmlType != 13" not in quant:
        raise AssertionError("quantization type 13 was dropped from supported path")
    lane = function_body("src/deep2/vulkan_compute.cpp",
                         "RunWeightHostRoundTrip")
    saved = lane.index("const uint32_t previousLaneTag = q4kLane_;")
    changed = lane.index("SetQ4kLaneTag(kQ4kLaneDual)")
    restored = lane.index("laneRestore{this, previousLaneTag}")
    if not saved < changed < restored:
        raise AssertionError("previous lane tag was not saved before changing it")
except (AssertionError, ValueError) as exc:
    failures.append(str(exc))

if failures:
    for message in failures:
        print("SOURCE_CONTRACT_FAIL:", message, file=sys.stderr)
    sys.exit(1)
print("SOURCE_CONTRACT_PASS: four fused host GEMV calls + saved lane state")
print("NOT_CERTIFIED: compiler, GPU numerics, full-model parity, and TPS require runtime evidence")
