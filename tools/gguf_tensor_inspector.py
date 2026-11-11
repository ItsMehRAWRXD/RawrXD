#!/usr/bin/env python3
"""
GGUF Tensor Inspector - Diagnose lazy load hangs
Validates tensor offsets and sizes to detect potential infinite loops
"""

import struct
import sys
import os

def inspect_gguf(filepath):
    """Inspect GGUF file tensor metadata"""
    
    print(f"Inspecting: {filepath}")
    print("=" * 70)
    
    file_size = os.path.getsize(filepath)
    print(f"File size: {file_size:,} bytes ({file_size / (1024**3):.2f} GB)")
    
    with open(filepath, 'rb') as f:
        # Read header
        magic = f.read(4)
        if magic != b'GGUF':
            print(f"ERROR: Invalid magic bytes: {magic}")
            return
        
        version = struct.unpack('<I', f.read(4))[0]
        print(f"GGUF Version: {version}")
        
        n_tensors, n_kv = struct.unpack('<QQ', f.read(16))
        print(f"Tensors: {n_tensors}, KV pairs: {n_kv}")
        print()
        
        # Skip KV pairs (simplified - just seek past them)
        # In reality you'd parse each KV, but for tensor inspection we just need tensor info
        
        # Read KV pairs first (skip them to get to tensor info)
        # GGUF v3 format: after header, read KV pairs, then tensor info
        for i in range(n_kv):
            # Read key
            key_len = struct.unpack('<Q', f.read(8))[0]
            key = f.read(key_len).decode('utf-8', errors='replace')
            
            # Read type
            val_type = struct.unpack('<I', f.read(4))[0]
            
            # Skip value based on type
            if val_type == 0:  # UINT8
                f.read(1)
            elif val_type == 1:  # INT8
                f.read(1)
            elif val_type == 2:  # UINT16
                f.read(2)
            elif val_type == 3:  # INT16
                f.read(2)
            elif val_type == 4:  # UINT32
                f.read(4)
            elif val_type == 5:  # INT32
                f.read(4)
            elif val_type == 6:  # FLOAT32
                f.read(4)
            elif val_type == 7:  # BOOL
                f.read(1)
            elif val_type == 8:  # STRING
                str_len = struct.unpack('<Q', f.read(8))[0]
                f.read(str_len)
            elif val_type == 9:  # ARRAY
                arr_type = struct.unpack('<I', f.read(4))[0]
                arr_len = struct.unpack('<Q', f.read(8))[0]
                # Skip array elements (simplified)
                for _ in range(arr_len):
                    if arr_type == 8:  # String array
                        s_len = struct.unpack('<Q', f.read(8))[0]
                        f.read(s_len)
                    elif arr_type == 4:  # UINT32
                        f.read(4)
                    else:
                        f.read(4)  # Default
            elif val_type == 10:  # UINT64
                f.read(8)
            elif val_type == 11:  # INT64
                f.read(8)
            elif val_type == 12:  # FLOAT64
                f.read(8)
        
        # Read tensor info
        tensors = []
        for i in range(n_tensors):
            name_len = struct.unpack('<Q', f.read(8))[0]
            name = f.read(name_len).decode('utf-8', errors='replace')
            
            n_dims = struct.unpack('<I', f.read(4))[0]
            if n_dims > 10 or n_dims < 0:  # Sanity check
                print(f"Warning: Invalid n_dims={n_dims} for tensor {name}, skipping")
                break
            dims = struct.unpack(f'<{n_dims}Q', f.read(8 * n_dims))
            
            type_id = struct.unpack('<I', f.read(4))[0]
            offset = struct.unpack('<Q', f.read(8))[0]
            
            tensors.append({
                'name': name,
                'dims': dims,
                'type': type_id,
                'offset': offset
            })
        
        # Calculate tensor sizes
        type_sizes = {
            0: ('F32', 4),      # 4 bytes per element
            1: ('F16', 2),      # 2 bytes per element
            2: ('Q4_0', 18/32), # 18 bytes per 32 elements
            3: ('Q4_1', 20/32),
            6: ('Q5_0', 22/32),
            7: ('Q5_1', 24/32),
            8: ('Q8_0', 34/32),
            9: ('Q8_1', 36/32),
            10: ('Q2_K', 84/256),
            11: ('Q3_K', 110/256),
            12: ('Q4_K', 144/256),
            13: ('Q5_K', 176/256),
            14: ('Q6_K', 210/256),
            15: ('Q8_K', 1),
        }
        
        # Find token_embd.weight
        print("Looking for token_embd.weight...")
        print()
        
        for t in tensors:
            if 'token_embd' in t['name'] or t['name'] == 'output.weight':
                ne = 1
                for d in t['dims']:
                    ne *= d
                
                type_name, type_mult = type_sizes.get(t['type'], (f'UNKNOWN({t["type"]})', 4))
                data_size = int(ne * type_mult)
                
                # Check if offset is valid
                end_offset = t['offset'] + data_size
                valid = end_offset <= file_size
                
                print(f"Tensor: {t['name']}")
                print(f"  Dims: {t['dims']} (ne={ne:,})")
                print(f"  Type: {type_name} (id={t['type']})")
                print(f"  Offset: {t['offset']:,} (0x{t['offset']:x})")
                print(f"  Data size: {data_size:,} bytes ({data_size / (1024**2):.2f} MB)")
                print(f"  End offset: {end_offset:,}")
                print(f"  Valid: {'YES' if valid else 'NO - EXCEEDS FILE SIZE!'}")
                print()
                
                if not valid:
                    print(f"  ERROR: Tensor extends beyond file size!")
                    print(f"    File size: {file_size:,}")
                    print(f"    Tensor end: {end_offset:,}")
                    print(f"    Overflow: {end_offset - file_size:,} bytes")
                    print()
        
        # Summary statistics
        print("=" * 70)
        print("Summary:")
        
        total_tensor_bytes = 0
        for t in tensors:
            ne = 1
            for d in t['dims']:
                ne *= d
            _, type_mult = type_sizes.get(t['type'], ('UNKNOWN', 4))
            total_tensor_bytes += int(ne * type_mult)
        
        print(f"Total tensor data: {total_tensor_bytes:,} bytes ({total_tensor_bytes / (1024**3):.2f} GB)")
        print(f"File size: {file_size:,} bytes ({file_size / (1024**3):.2f} GB)")
        
        if total_tensor_bytes > file_size:
            print(f"WARNING: Tensor data exceeds file size by {total_tensor_bytes - file_size:,} bytes!")
        
        # Check for potential infinite loop conditions
        print()
        print("Checking for potential infinite loop conditions...")
        
        issues = []
        for t in tensors:
            ne = 1
            for d in t['dims']:
                ne *= d
            
            _, type_mult = type_sizes.get(t['type'], ('UNKNOWN', 4))
            data_size = int(ne * type_mult)
            end_offset = t['offset'] + data_size
            
            if end_offset > file_size:
                issues.append(f"  {t['name']}: extends {end_offset - file_size:,} bytes past EOF")
            
            if t['offset'] > file_size:
                issues.append(f"  {t['name']}: offset {t['offset']:,} is past EOF {file_size:,}")
            
            if data_size == 0:
                issues.append(f"  {t['name']}: zero data size (possible calculation error)")
        
        if issues:
            print("POTENTIAL ISSUES FOUND:")
            for issue in issues:
                print(issue)
        else:
            print("No obvious issues found in tensor metadata.")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <gguf_file>")
        sys.exit(1)
    
    filepath = sys.argv[1]
    if not os.path.exists(filepath):
        print(f"ERROR: File not found: {filepath}")
        sys.exit(1)
    
    inspect_gguf(filepath)
