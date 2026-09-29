#!/usr/bin/env python3
"""Byte-exact utmp dance trace for block 0 scales of blk.4.ffn_gate."""
import struct

s = bytes([246, 87, 86, 84, 235, 16, 84, 7, 255, 160, 29, 245])
k1, k2, k3 = 0x3F3F3F3F, 0x0F0F0F0F, 0x03030303

u = list(struct.unpack("<III", s[:12])) + [0]
print("before dance:")
print("  utmp[0] =", hex(u[0]), "bytes", list(struct.pack("<I", u[0])))
print("  utmp[1] =", hex(u[1]), "bytes", list(struct.pack("<I", u[1])))
print("  utmp[2] =", hex(u[2]), "bytes", list(struct.pack("<I", u[2])))

u[3] = ((u[2] >> 4) & k2) | (((u[1] >> 6) & k3) << 4)
print("utmp[3] =", hex(u[3]), "bytes", list(struct.pack("<I", u[3])))
# decode per llama mins[4..7] expectation: (s[8]>>4)|(s[4]&0xF)<<4 = 15 | 11<<4 = 191
b = list(struct.pack("<I", u[3]))
print("expected mins[4] = 191; got byte0 =", b[0])

# llama's canonical get_scale_min_k4 for j>=4:
for j in range(4, 8):
    m = (s[j + 4] >> 4) | ((s[j] & 0xF) << 4)
    print(f"llama mins[{j}] = (s[{j+4}]>>4)|((s[{j}]&0xF)<<4) = {m}")