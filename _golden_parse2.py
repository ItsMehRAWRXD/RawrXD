import struct
b = open(r"F:\~dev\_parity_golden_p0.bin","rb").read()
print("total", len(b))
print("magic", b[:16])
off = 16
print("ver,endian @16:", struct.unpack_from("<II", b, off))
off += 8
n, = struct.unpack_from("<I", b, off); off += 4
print("str1 len:", n, "val:", b[off:off+n])
off += n
print("then q:", struct.unpack_from("<Q", b, off)); off += 8
n2, = struct.unpack_from("<I", b, off); off += 4
print("str2 len:", n2, "val:", b[off:off+n2])
off += n2
n3, = struct.unpack_from("<I", b, off); off += 4
print("str3 len:", n3, "val:", b[off:off+n3][:60])
off += n3
print("next q (np?):", struct.unpack_from("<Q", b, off)); off += 8
print("following ints:", struct.unpack_from("<8i", b, off))
