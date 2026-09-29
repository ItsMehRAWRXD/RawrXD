import struct
b = open(r"F:\~dev\_parity_golden_p0.bin","rb").read()
off = 16
ver, endian = struct.unpack_from("<II", b, off); off += 8
def rs(o):
    n = struct.unpack_from("<I", b, o)[0]; return b[o+4:o+4+n].decode("utf-8","replace"), o+4+n
msha, off = rs(off)
mbytes, = struct.unpack_from("<Q", b, off); off += 8
arch, off = rs(off)
prompt, off = rs(off)
np_, = struct.unpack_from("<Q", b, off); off += 8
toks = struct.unpack_from(f"<{np_}i", b, off); off += 4*np_
ns, = struct.unpack_from("<Q", b, off); off += 8
print(f"VER={ver} ARCH={arch} PROMPT=[{prompt}] PTOKS={list(toks)} NSTEPS={ns}")
s_in, s_top1, nlog = struct.unpack_from("<iiQ", b, off); off += 16
print(f"STEP0_INPUT={s_in} TOP1={s_top1} NLOGITS={nlog}")
logits = struct.unpack_from(f"<{nlog}f", b, off)
order = sorted(range(nlog), key=lambda i: -logits[i])
print("TOP10_IDS=", order[:10])
print("TOP10_VALS=", [round(logits[i],4) for i in order[:10]])
print("LOGITS_MIN_MAX=", round(min(logits),4), round(max(logits),4))
