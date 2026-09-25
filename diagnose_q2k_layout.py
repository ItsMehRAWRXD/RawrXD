import struct, sys, os

def fp16_to_f32(h):
    sign = (h >> 15) & 1
    exp = (h >> 10) & 0x1F
    man = h & 0x3FF
    if exp == 0:
        if man == 0: return -0.0 if sign else 0.0
        v = (man / (2**24)) * (-1 if sign else 1)
        return v
    if exp == 31: return float('-inf') if sign else float('inf')
    v = (1.0 + man / 1024.0) * (2.0 ** (exp - 15))
    return -v if sign else v

def parse_gguf(f):
    magic = f.read(4)
    version = struct.unpack('<I', f.read(4))[0]
    tc = struct.unpack('<Q', f.read(8))[0]
    mc = struct.unpack('<Q', f.read(8))[0]
    print(f'magic={magic} version={version} tensorCount={tc} metaCount={mc}')
    
    for i in range(mc):
        keyLen = struct.unpack('<Q', f.read(8))[0]
        key = f.read(keyLen).decode('utf-8')
        vtype = struct.unpack('<I', f.read(4))[0]
        if vtype == 0: f.read(1)
        elif vtype == 1: f.read(1)
        elif vtype == 2: f.read(2)
        elif vtype == 3: f.read(2)
        elif vtype == 4: f.read(4)
        elif vtype == 5: f.read(4)
        elif vtype == 6: f.read(4)
        elif vtype == 7: f.read(1)
        elif vtype == 8:
            sl = struct.unpack('<Q', f.read(8))[0]
            f.read(sl)
        elif vtype == 9:
            arrType = struct.unpack('<I', f.read(4))[0]
            arrLen = struct.unpack('<Q', f.read(8))[0]
            for _ in range(arrLen):
                if arrType == 8:
                    sl = struct.unpack('<Q', f.read(8))[0]
                    f.read(sl)
                elif arrType in (4,5,6,7):
                    f.read(4 if arrType != 7 else 1)
                elif arrType in (10,11,12):
                    f.read(8)
                else:
                    break
        elif vtype == 10: f.read(8)
        elif vtype == 11: f.read(8)
        elif vtype == 12: f.read(8)
        else:
            print(f'unknown meta type {vtype}')
            break
    
    pos_after_meta = f.tell()
    align = 32
    pad = (align - (pos_after_meta % align)) % align
    f.read(pad)
    tensor_data_start = f.tell()
    print(f'tensor_data_start=0x{tensor_data_start:08X} ({tensor_data_start})')
    
    tensors = []
    for i in range(tc):
        tnameLen = struct.unpack('<Q', f.read(8))[0]
        tname = f.read(tnameLen).decode('utf-8')
        nDims = struct.unpack('<I', f.read(4))[0]
        dims = [struct.unpack('<Q', f.read(8))[0] for _ in range(nDims)]
        ttype = struct.unpack('<I', f.read(4))[0]
        toffset = struct.unpack('<Q', f.read(8))[0]
        tensors.append((tname, dims, ttype, toffset))
    
    return tensor_data_start, tensors

def try_layout_A(raw84):
    """Layout: d(f16)+dmin(f16) at bytes 0..3, scales[16] at 4..19, qs[64] at 20..83"""
    d_raw = struct.unpack('<H', raw84[0:2])[0]
    dmin_raw = struct.unpack('<H', raw84[2:4])[0]
    scales = list(raw84[4:20])
    qs = list(raw84[20:84])
    d = fp16_to_f32(d_raw)
    dmin = fp16_to_f32(dmin_raw)
    weights = []
    for sb in range(16):
        sc = scales[sb]
        sub_scale = d * (sc & 0x0F)
        sub_min = dmin * (sc >> 4)
        for j in range(16):
            byte_idx = sb * 4 + (j // 4)
            bit_pos = (j % 4) * 2
            q = (qs[byte_idx] >> bit_pos) & 0x03
            w = sub_scale * q - sub_min
            weights.append(w)
    return d, dmin, scales, qs, weights

def try_layout_B(raw84):
    """Layout: scales[16] at 0..15, qs[64] at 16..79, d(f16) at 80..81, dmin(f16) at 82..83"""
    scales = list(raw84[0:16])
    qs = list(raw84[16:80])
    d_raw = struct.unpack('<H', raw84[80:82])[0]
    dmin_raw = struct.unpack('<H', raw84[82:84])[0]
    d = fp16_to_f32(d_raw)
    dmin = fp16_to_f32(dmin_raw)
    weights = []
    for sb in range(16):
        sc = scales[sb]
        sub_scale = d * (sc & 0x0F)
        sub_min = dmin * (sc >> 4)
        for j in range(16):
            byte_idx = sb * 4 + (j // 4)
            bit_pos = (j % 4) * 2
            q = (qs[byte_idx] >> bit_pos) & 0x03
            w = sub_scale * q - sub_min
            weights.append(w)
    return d, dmin, scales, qs, weights

def analyze_block(raw84, label):
    print(f"\n=== Layout {label} ===")
    d, dmin, scales, qs, weights = (try_layout_A(raw84) if label == "A" else try_layout_B(raw84))
    print(f"d={d:.6f} dmin={dmin:.6f}")
    print(f"scales=[{' '.join(f'{s:02X}' for s in scales)}]")
    print(f"qs_first16=[{' '.join(f'{q:02X}' for q in qs[:16])}]")
    w_min = min(weights)
    w_max = max(weights)
    w_mean = sum(weights) / len(weights)
    print(f"weights: min={w_min:.4f} max={w_max:.4f} mean={w_mean:.4f}")
    plausible = abs(w_max) < 50 and abs(w_min) < 50 and abs(w_mean) < 10
    print(f"PLAUSIBLE={plausible}")
    return weights, plausible

def main():
    path = r'D:\rawrxd\llama3.2-3b-Q2_K.gguf'
    with open(path, 'rb') as f:
        tensor_data_start, tensors = parse_gguf(f)
    
    target = 'blk.0.attn_q.weight'
    tinfo = None
    for tname, dims, ttype, toffset in tensors:
        if tname == target:
            tinfo = (tname, dims, ttype, toffset)
            break
    
    if not tinfo:
        print(f'Tensor {target} not found')
        return

    tname, dims, ttype, toffset = tinfo
    print(f'Found tensor: {tname} dims={dims} type={ttype} offset={toffset}')

    abs_offset = tensor_data_start + toffset
    print(f'Absolute data offset: 0x{abs_offset:08X} ({abs_offset})')

    with open(path, 'rb') as f2:
        f2.seek(abs_offset)
        raw84 = f2.read(84)
    print(f'Read {len(raw84)} bytes')
    print(f'Raw bytes (hex): {" ".join(f"{b:02X}" for b in raw84)}')
    
    # Quick heuristic: bytes 0..1 and bytes 80..81 - which look more like fp16?
    h0 = struct.unpack('<H', raw84[0:2])[0]
    h2 = struct.unpack('<H', raw84[2:4])[0]
    h80 = struct.unpack('<H', raw84[80:82])[0]
    h82 = struct.unpack('<H', raw84[82:84])[0]
    
    f0 = fp16_to_f32(h0)
    f2 = fp16_to_f32(h2)
    f80 = fp16_to_f32(h80)
    f82 = fp16_to_f32(h82)
    
    print(f"\nHeuristic: bytes 0..1 as fp16 = {f0:.6f}, bytes 2..3 as fp16 = {f2:.6f}")
    print(f"Heuristic: bytes 80..81 as fp16 = {f80:.6f}, bytes 82..83 as fp16 = {f82:.6f}")
    
    # Try both layouts
    wA, pA = analyze_block(raw84, "A")
    wB, pB = analyze_block(raw84, "B")
    
    print(f"\n=== VERDICT ===")
    if pB and not pA:
        print("Layout B is plausible; Layout A is NOT. GGUF uses scales-first.")
    elif pA and not pB:
        print("Layout A is plausible; Layout B is NOT. GGUF uses d/dmin-first.")
    elif pA and pB:
        print("BOTH layouts plausible — need more samples.")
    else:
        print("NEITHER layout plausible — data may be corrupt or another format.")

if __name__ == '__main__':
    main()
