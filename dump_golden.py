import struct

def dump_golden_registry():
    with open(r'D:\rawrxd\phi3-mini-Q2_K.gguf', 'rb') as f:
        magic = f.read(4)
        version = struct.unpack("<I", f.read(4))[0]
        tensors = struct.unpack("<Q", f.read(8))[0]
        kvs = struct.unpack("<Q", f.read(8))[0]
        
        def read_string(f):
            strlen = struct.unpack('<Q', f.read(8))[0]
            return f.read(strlen).decode('utf-8')
            
        def skip_val(f, val_type):
            if val_type == 0: f.read(1)
            elif val_type == 1: f.read(1)
            elif val_type == 2: f.read(2)
            elif val_type == 3: f.read(2)
            elif val_type == 4: f.read(4)
            elif val_type == 5: f.read(4)
            elif val_type == 6: f.read(4)
            elif val_type == 7: f.read(1)
            elif val_type == 8: read_string(f)
            elif val_type == 9:
                arr_type = struct.unpack('<I', f.read(4))[0]
                arr_len = struct.unpack('<Q', f.read(8))[0]
                for _ in range(arr_len):
                    skip_val(f, arr_type)
            elif val_type in (10, 11, 12): f.read(8)

        # parse KVs to find alignment
        alignment = 32
        for _ in range(kvs):
            key = read_string(f)
            val_type = struct.unpack('<I', f.read(4))[0]
            if key == "general.alignment":
                if val_type == 4: alignment = struct.unpack('<I', f.read(4))[0]
                elif val_type == 5: alignment = struct.unpack('<i', f.read(4))[0]
                else: skip_val(f, val_type)
            else:
                skip_val(f, val_type)
                
        tensor_data = []
        for i in range(tensors):
            name = read_string(f)
            ndims = struct.unpack('<I', f.read(4))[0]
            dims = [struct.unpack('<Q', f.read(8))[0] for _ in range(ndims)]
            ttype = struct.unpack('<I', f.read(4))[0]
            offset = struct.unpack('<Q', f.read(8))[0]
            tensor_data.append({"name": name, "type": ttype, "dims": dims, "offset": offset})
            
        data_offset = f.tell()
        remainder = data_offset % alignment
        if remainder != 0:
            data_offset += alignment - remainder
            
        # compute sizes by sorting offsets
        tensor_data.sort(key=lambda x: x["offset"])
        with open(r'd:\rawrxd\golden_tensor_registry.txt', 'w') as out:
            out.write(f"Alignment: {alignment}\n")
            out.write(f"Tensor Data Start: {data_offset}\n\n")
            out.write(f"{'Index':<5} | {'Name':<35} | {'Type':<4} | {'NDims':<5} | {'Shape':<15} | {'Offset':<12} | {'Absolute':<12} | {'ByteSize'}\n")
            out.write("-" * 115 + "\n")
            for i, t in enumerate(tensor_data):
                shape = "x".join(map(str, t["dims"]))
                abs_offset = data_offset + t["offset"]
                size = "Unknown"
                if i < len(tensor_data) - 1:
                    size = tensor_data[i+1]["offset"] - t["offset"]
                out.write(f"{i:<5} | {t['name']:<35} | {t['type']:<4} | {len(t['dims']):<5} | {shape:<15} | {t['offset']:<12} | {abs_offset:<12} | {size}\n")
                
dump_golden_registry()
