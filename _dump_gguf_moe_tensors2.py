import struct, sys

def skip_string(f):
    n = struct.unpack('<Q', f.read(8))[0]
    f.seek(n, 1)

def skip_value(f, vt):
    if vt in (0,1,7): f.seek(1, 1)
    elif vt in (2,3): f.seek(2, 1)
    elif vt in (4,5,6): f.seek(4, 1)
    elif vt == 8: skip_string(f)
    elif vt == 9:
        atype = struct.unpack('<I', f.read(4))[0]
        alen = struct.unpack('<Q', f.read(8))[0]
        if atype == 8:
            for _ in range(alen): skip_string(f)
        else:
            sz = {0:1,1:1,2:2,3:2,4:4,5:4,6:4,7:1,10:8,11:8,12:8}.get(atype, 1)
            f.seek(alen * sz, 1)
    elif vt in (10,11,12): f.seek(8, 1)

path = sys.argv[1]
with open(path, 'rb') as f:
    f.seek(4)  # magic
    ver = struct.unpack('<I', f.read(4))[0]
    n_tensors = struct.unpack('<Q', f.read(8))[0]
    n_meta = struct.unpack('<Q', f.read(8))[0]
    for _ in range(n_meta):
        skip_string(f)
        vt = struct.unpack('<I', f.read(4))[0]
        skip_value(f, vt)
    for i in range(n_tensors):
        n_dims = struct.unpack('<I', f.read(4))[0]
        f.seek(8 * n_dims, 1)
        f.seek(4, 1)  # type
        f.seek(8, 1)  # offset
        skip_string(f)  # name
    # alignment
    align = struct.unpack('<Q', f.read(8))[0]
    f.seek(align, 1)
    # tensor data follows; nothing to do

# This script was fixed but the user may not need it anymore.
# Keeping as placeholder.
