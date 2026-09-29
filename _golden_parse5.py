import struct
b = open(r"F:\~dev\_parity_golden_p0.bin","rb").read()
print("hexdump[0:40]:", b[:40].hex(" "))
