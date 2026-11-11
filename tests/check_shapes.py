import sys
sys.path.insert(0, '.')
from gate5_transformer_layer import GGUFParser

parser = GGUFParser(r'D:\rawrxd\.archive\Full Source\build\llama_cli\models\model.gguf')
parser.parse()

# Check layer 0 tensor shapes
for name in ['blk.0.attn_q.weight', 'blk.0.attn_k.weight', 'blk.0.attn_v.weight', 'blk.0.attn_output.weight']:
    if name in parser.tensors:
        info = parser.tensors[name]
        print(f'{name}: {info["dims"]}, type={info["type"]}')
