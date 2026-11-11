#!/usr/bin/env python3
"""Elementwise diff of two FP32 dumps - RAWRXD_MODELGENIE_PRODUCTION_RUNTIME_001"""
import struct
import sys

a = struct.unpack("<%df" % (len(open(sys.argv[1], "rb").read()) // 4),
                  open(sys.argv[1], "rb").read())
b = struct.unpack("<%df" % (len(open(sys.argv[2], "rb").read()) // 4),
                  open(sys.argv[2], "rb").read())
if len(a) != len(b):
    raise SystemExit("length mismatch %d vs %d" % (len(a), len(b)))
n = len(a)
diffs = [abs(x - y) for x, y in zip(a, b)]
exact = sum(1 for x, y in zip(a, b) if x == y)
worst = sorted(range(n), key=lambda i: diffs[i], reverse=True)[:5]
nz_a = sum(1 for x in a if x != 0.0)
nz_b = sum(1 for y in b if y != 0.0)
print("elements            : %d" % n)
print("bitwise identical   : %d (%.4f%%)" % (exact, 100.0 * exact / n))
print("max |diff|          : %.9g" % diffs[0] if False else "max |diff|          : %.9g" % max(diffs))
print("mean |diff|         : %.9g" % (sum(diffs) / n))
print("nonzero a / b       : %d / %d" % (nz_a, nz_b))
print("nonfinite a / b     : %d / %d" %
      (sum(1 for x in a if x != x or abs(x) == float("inf")),
       sum(1 for y in b if y != y or abs(y) == float("inf"))))
print("worst indices:")
for i in worst:
    print("  [%d] native=%.9g ref=%.9g diff=%.9g" % (i, a[i], b[i], diffs[i]))
if max(diffs) == 0.0:
    print("\nVERDICT: DEQUANTIZATION_IDENTICAL")
else:
    print("\nVERDICT: DEQUANTIZATION_DIFFERS")
