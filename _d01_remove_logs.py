#!/usr/bin/env python3
"""D01: Remove hot-path success logging from forwardLayerGpuResident."""
import re, sys

path = r"F:\~dev\rawrxd\src\deep2\Deep2Engine_GpuForward.cpp"

with open(path, 'r', encoding='utf-8') as f:
    text = f.read()

# Remove GPU_FORWARD_STAGE success-path logs (keep FAIL_STAGE logs)
# Pattern: std::fprintf(stderr, "GPU_FORWARD_STAGE=...\n", ...);
# But NOT std::fprintf(stderr, "GPU_FORWARD_FAIL_STAGE=...\n", ...);
text = re.sub(
    r'\s*std::fprintf\(stderr,\s*"GPU_FORWARD_STAGE=[^"]*"[^;]*\);\s*\n',
    '\n', text)

# Remove GEMV_ENTER, GEMV_DISPATCH_GEMVQUANT, GEMV_DISPATCH_GEMVQUANT_DONE,
# GEMV_DISPATCH_DEVICE, GEMV_DISPATCH_DEVICE_DONE logs
# But keep GPU_GEMV_GEOMETRY_FAIL, GPU_GEMV_DENSE_BYTES_FAIL
text = re.sub(
    r'\s*std::fprintf\(stderr,\s*"GEMV_ENTER[^"]*"[^;]*\);\s*\n',
    '\n', text)
text = re.sub(
    r'\s*std::fprintf\(stderr,\s*"GEMV_DISPATCH_GEMVQUANT[^"]*"[^;]*\);\s*\n',
    '\n', text)
text = re.sub(
    r'\s*std::fprintf\(stderr,\s*"GEMV_DISPATCH_GEMVQUANT_DONE[^"]*"[^;]*\);\s*\n',
    '\n', text)
text = re.sub(
    r'\s*std::fprintf\(stderr,\s*"GEMV_DISPATCH_DEVICE[^"]*"[^;]*\);\s*\n',
    '\n', text)
text = re.sub(
    r'\s*std::fprintf\(stderr,\s*"GEMV_DISPATCH_DEVICE_DONE[^"]*"[^;]*\);\s*\n',
    '\n', text)

# Remove GPU_LAYER_ENTER (already done in previous edit, but clean up any remaining)
text = re.sub(
    r'\s*std::fprintf\(stderr,\s*"GPU_LAYER_ENTER[^"]*"[^;]*\);\s*\n',
    '\n', text)

# Also remove GPU_QKV_GEOMETRY_FAIL, GPU_FFN_GEOMETRY_FAIL, GPU_FFN_DENSE_BYTES_FAIL
# Wait, keep error logs. Only remove success-path logs.

# Remove GPU_QKV_DENSE_BYTES_FAIL log line (it's an error but in hot path; keep for debugging?)
# Actually keep error logs.

with open(path, 'w', encoding='utf-8') as f:
    f.write(text)

print("D01 log removal complete.")
