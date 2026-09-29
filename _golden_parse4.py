import struct
b = open(r"F:\~dev\_parity_golden_p0.bin","rb").read()
off = 16
n, = struct.unpack_from("<Q", b, off); off += 8
print("str1 len", n)
msha = b[off:off+n].decode(); off += n
print("msha", msha)
mbytes, = struct.unpack_from("<Q", b, off); off += 8
print("mbytes", mbytes)
n, = struct.unpack_from("<Q", b, off); off += 8
arch = b[off:off+n].decode(); off += n
print("arch", arch)
n, = struct.unpack_from("<Q", b, off); off += 8
prompt = b[off:off+n].decode(); off += n
print("prompt", repr(prompt))
np_, = struct.unpack_from("<Q", b, off); off += 8
print("np", np_)
toks = list(struct.unpack_from(f"<{np_}i", b, off)); off += 4*np_
print("toks", toks)
ns, = struct.unpack_from("<Q", b, off); off += 8
print("ns", ns)
s_in, s_top1, nlog = struct.unpack_from("<iiQ", b, off); off += 16
print(f"step0 input={s_in} top1={s_top1} nlogits={nlog}")
logits = struct.unpack_from(f"<{nlog}f", b, off)
order = sorted(range(nlog), key=lambda i: -logits[i])
print("TOP10_IDS=", order[:10])
print("TOP10_VALS=", [round(logits[i],4) for i in order[:10]])
print("min/max", round(min(logits),4), round(max(logits),4))
