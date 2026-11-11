from gate5_transformer_layer import GGUFParser

parser = GGUFParser(r'D:\rawrxd\.archive\Full Source\build\llama_cli\models\model.gguf')
parser.parse()

print(f'Tensor data offset: {parser.tensor_data_offset}')

# Get tensor offsets
q_info = parser.tensors['blk.0.attn_q.weight']
norm_info = parser.tensors['blk.0.attn_norm.weight']

print(f'blk.0.attn_q.weight: offset={q_info["offset"]}, dims={q_info["dims"]}, type={q_info["type"]}')
print(f'blk.0.attn_norm.weight: offset={norm_info["offset"]}, dims={norm_info["dims"]}, type={norm_info["type"]}')

# Check file position
print(f'File position after parse: {parser.file.tell()}')
