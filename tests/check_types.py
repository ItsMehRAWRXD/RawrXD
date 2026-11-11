from gate7_token_generation import GGUFParser

parser = GGUFParser(r'D:\rawrxd\.archive\Full Source\build\llama_cli\models\model.gguf')
parser.parse()

# Check output.weight type
info = parser.tensors['output.weight']
print(f"output.weight: dims={info['dims']}, type={info['type']}")

# Check token_embd.weight type
info = parser.tensors['token_embd.weight']
print(f"token_embd.weight: dims={info['dims']}, type={info['type']}")

# List all GGML types
print("\nGGML Types:")
print("  0 = F32")
print("  1 = F16")
print("  2 = Q4_0")
print("  3 = Q4_1")
print("  14 = Q6_K (likely)")
