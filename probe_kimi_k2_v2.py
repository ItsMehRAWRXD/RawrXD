#!/usr/bin/env python3
"""Kimi K2 Shard 0 Tensor Inventory Probe v2 - writes to file"""
import struct, os

GGUF_TYPES = {
    0: 'F32', 1: 'F16', 2: 'Q4_0', 3: 'Q4_1',
    6: 'Q5_0', 7: 'Q5_1', 8: 'Q8_0', 9: 'Q8_1',
    10: 'Q2_K', 11: 'Q3_K', 12: 'Q4_K', 13: 'Q5_K',
    14: 'Q6_K', 15: 'Q8_K', 16: 'IQ2_XXS', 17: 'IQ2_XS',
    18: 'IQ3_XXS', 19: 'IQ1_S', 20: 'IQ4_NL',
    21: 'IQ3_S', 22: 'IQ2_S', 23: 'IQ4_XS',
    24: 'I8', 25: 'I16', 26: 'I32', 27: 'I64',
    28: 'F64', 29: 'IQ1_M', 30: 'BF16',
}

GGUF_TYPE_SIZES = {
    0: 4, 1: 2, 2: 18, 3: 20, 6: 22, 7: 24, 8: 34, 9: 35,
    10: 12, 11: 96, 12: 144, 13: 176, 14: 210, 15: 290,
    16: 66, 17: 74, 18: 98, 19: 50, 20: 82, 21: 110, 22: 82,
    23: 98, 24: 1, 25: 2, 26: 4, 27: 8, 28: 8, 29: 58, 30: 2,
}

def align32(offset):
    return (offset + 31) & ~31

def main():
    shard = r'F:\OllamaModels\Kimi-K2-Instruct-0905-GGUF\Q4_K_M\Kimi-K2-Instruct-0905-Q4_K_M-00001-of-00013.gguf'
    out_path = r'd:\rawrxd\kimi_k2_shard0_inventory.txt'
    
    with open(out_path, 'w') as out:
        with open(shard, 'rb') as f:
            magic = f.read(4)
            version = struct.unpack('<I', f.read(4))[0]
            n_tensors = struct.unpack('<Q', f.read(8))[0]
            n_metadata = struct.unpack('<Q', f.read(8))[0]
            
            out.write(f'GGUF magic: {magic}\n')
            out.write(f'Version: {version}\n')
            out.write(f'Tensors: {n_tensors}\n')
            out.write(f'Metadata: {n_metadata}\n')
            
            # Skip metadata - we know it ends at 6911104
            f.seek(6911104)
            tensor_info_start = f.tell()
            out.write(f'Tensor info start: {tensor_info_start}\n')
            
            tensors = []
            for i in range(n_tensors):
                pos = f.tell()
                n_dims = struct.unpack('<I', f.read(4))[0]
                dims = struct.unpack(f'<{n_dims}Q', f.read(n_dims * 8))
                name_len = struct.unpack('<Q', f.read(8))[0]
                name = f.read(name_len).decode('utf-8', errors='replace')
                ggml_type = struct.unpack('<I', f.read(4))[0]
                offset = struct.unpack('<Q', f.read(8))[0]
                
                tensors.append({
                    'index': i, 'pos': pos, 'name': name,
                    'n_dims': n_dims, 'dims': dims,
                    'ggml_type': ggml_type,
                    'type_name': GGUF_TYPES.get(ggml_type, f'UNKNOWN_{ggml_type}'),
                    'offset': offset,
                })
            
            data_section_start = align32(f.tell())
            file_size = os.path.getsize(shard)
            
            out.write(f'Data section start: {data_section_start}\n')
            out.write(f'File size: {file_size}\n\n')
            
            # Calculate sizes
            for t in tensors:
                nelements = 1
                for d in t['dims']:
                    nelements *= d
                t['nelements'] = nelements
                
                ggml_type = t['ggml_type']
                block_size = GGUF_TYPE_SIZES.get(ggml_type, 1)
                
                if ggml_type in [0, 1, 24, 25, 26, 27, 28, 30]:
                    byte_size = nelements * block_size
                else:
                    nblocks = (nelements + 31) // 32
                    byte_size = nblocks * block_size
                
                t['byte_size'] = byte_size
                t['abs_offset'] = data_section_start + t['offset']
                t['end_offset'] = t['abs_offset'] + byte_size
            
            # Write all tensors
            out.write('=== All Tensors ===\n')
            out.write(f"{'idx':>3} | {'name':<50} | {'dims':<30} | {'type':<8} | {'offset':>12} | {'size':>15}\n")
            out.write('-' * 140 + '\n')
            for t in tensors:
                dims_str = str(t['dims'])
                out.write(f"{t['index']:3d} | {t['name']:<50} | {dims_str:<30} | {t['type_name']:<8} | {t['offset']:12d} | {t['byte_size']:15d}\n")
            
            # Validation
            out.write('\n=== Validation ===\n')
            sorted_tensors = sorted(tensors, key=lambda x: x['abs_offset'])
            overlaps = []
            for i in range(len(sorted_tensors) - 1):
                t1 = sorted_tensors[i]
                t2 = sorted_tensors[i + 1]
                if t1['end_offset'] > t2['abs_offset']:
                    overlaps.append((t1['name'], t2['name'], t1['end_offset'] - t2['abs_offset']))
            
            if overlaps:
                out.write(f'Found {len(overlaps)} overlaps!\n')
                for o in overlaps[:5]:
                    out.write(f'  {o[0]} overlaps {o[1]} by {o[2]} bytes\n')
            else:
                out.write('No overlaps detected\n')
            
            total_data = max(t['end_offset'] for t in tensors) - data_section_start
            out.write(f'Total data section size: {total_data} bytes ({total_data / 1e9:.2f} GB)\n')
            out.write(f'File size: {file_size} bytes ({file_size / 1e9:.2f} GB)\n')
            
            # Classification
            categories = {
                'embedding': [], 'output': [], 'norm': [],
                'mla_attn': [], 'mla_kv': [], 'mla_q': [], 'mla_o': [],
                'router': [], 'shared_expert': [], 'expert': [], 'other': [],
            }
            
            for t in tensors:
                name = t['name']
                if name == 'token_embd.weight':
                    categories['embedding'].append(t)
                elif name == 'output.weight':
                    categories['output'].append(t)
                elif 'output_norm' in name or 'attn_norm' in name or 'ffn_norm' in name:
                    categories['norm'].append(t)
                elif 'attn_q_a' in name or 'attn_q_b' in name:
                    categories['mla_q'].append(t)
                elif 'attn_kv_a' in name or 'attn_kv_b' in name:
                    categories['mla_kv'].append(t)
                elif 'attn_k' in name or 'attn_v' in name:
                    categories['mla_attn'].append(t)
                elif 'attn_o' in name:
                    categories['mla_o'].append(t)
                elif 'ffn_gate_inp' in name:
                    categories['router'].append(t)
                elif 'ffn_gate_s' in name or 'ffn_up_s' in name or 'ffn_down_s' in name:
                    categories['shared_expert'].append(t)
                elif 'ffn_experts' in name:
                    categories['expert'].append(t)
                else:
                    categories['other'].append(t)
            
            out.write('\n=== Tensor Classification ===\n')
            total_size = 0
            for cat, items in categories.items():
                cat_size = sum(t['byte_size'] for t in items)
                total_size += cat_size
                out.write(f'{cat:20s}: {len(items):4d} tensors | {cat_size / 1e9:8.3f} GB\n')
            out.write(f'{"total":20s}: {sum(len(v) for v in categories.values()):4d} tensors | {total_size / 1e9:8.3f} GB\n')
    
    print(f'Output written to: {out_path}')

if __name__ == '__main__':
    main()
