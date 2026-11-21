#!/usr/bin/env python3
"""Add ${CMAKE_SOURCE_DIR} to rawrxd_gpu_compute include dirs so
quant_dot_dispatch.cpp's '#include "include/vulkan_compute.h"' resolves.
src/deep2 stays first, so bare 'vulkan_compute.h' still resolves to the Deep2
definition. Fail-closed: anchor must match exactly once.
"""
import sys

PATH = r"F:\rawrxd\CMakeLists.txt"
with open(PATH, "rb") as fh:
    raw = fh.read()
bom = b""
if raw[:3] == b"\xef\xbb\xbf":
    bom = raw[:3]; text = raw[3:].decode("utf-8")
else:
    text = raw.decode("utf-8")
NL = "\r\n" if "\r\n" in text else "\n"

anchor = NL.join([
    "    target_include_directories(rawrxd_gpu_compute PUBLIC",
    "        ${CMAKE_SOURCE_DIR}/src",
])
repl = NL.join([
    "    target_include_directories(rawrxd_gpu_compute PUBLIC",
    "        ${CMAKE_SOURCE_DIR}",
    "        ${CMAKE_SOURCE_DIR}/src",
])
c = text.count(anchor)
print(f"[anchor] count={c}")
if c != 1:
    print("ABORT: anchor not unique; no write"); sys.exit(2)
text = text.replace(anchor, repl, 1)
with open(PATH, "wb") as fh:
    fh.write(bom + text.encode("utf-8"))
print("WROTE", PATH)