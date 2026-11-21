#!/usr/bin/env python3
"""Restore linkage: add quant_dot_dispatch.cpp to the rawrxd_gpu_compute lib so
the WeightCacheRetention() reference in vulkan_compute.obj resolves within the
same library (self-contained). Additive; does not touch Deep2 source.

Fail-closed: the anchor must match exactly once.
"""
import sys

PATH = r"F:\rawrxd\CMakeLists.txt"
with open(PATH, "rb") as fh:
    raw = fh.read()
bom = b""
if raw[:3] == b"\xef\xbb\xbf":
    bom = raw[:3]
    text = raw[3:].decode("utf-8")
else:
    text = raw.decode("utf-8")

NL = "\r\n" if "\r\n" in text else "\n"

anchor = "    add_library(rawrxd_gpu_compute STATIC" + NL + "        src/deep2/vulkan_compute.cpp"
repl = ("    add_library(rawrxd_gpu_compute STATIC" + NL +
        "        src/deep2/vulkan_compute.cpp" + NL +
        "        # G44 link fix: vulkan_compute.cpp calls QuantDot::WeightCacheRetention();" + NL +
        "        # keep the policy definition in the same library so consumers do not need" + NL +
        "        # executable-specific symbol injection." + NL +
        "        src/deep2/quant_dot_dispatch.cpp")

c = text.count(anchor)
print(f"[anchor] count={c}")
if c != 1:
    print("ABORT: anchor not unique; no write")
    sys.exit(2)

text = text.replace(anchor, repl, 1)
with open(PATH, "wb") as fh:
    fh.write(bom + text.encode("utf-8"))
print("WROTE", PATH)