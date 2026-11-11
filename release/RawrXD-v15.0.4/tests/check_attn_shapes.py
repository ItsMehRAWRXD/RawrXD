from gate9_autoregressive_gen import GGUFParser

parser = GGUFParser(r'D:\rawrxd\.archive\Full Source\build\llama_cli\models\model.gguf')
parser.parse()

# Check attention weight shapes
for name in ['blk.0.attn_q.weight', 'blk.0.attn_k.weight', 'blk.0.attn_v.weight']:
    info = parser.tensors[name]
    print(f"{name}: {info['dims']}")
