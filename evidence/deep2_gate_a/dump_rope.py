import os
p = r'F:\rawrxd\tmp_llama_ref\ggml\src\ggml-cpu\ops.cpp'
src = open(p, 'rb').read().decode('utf-8', errors='replace')
i = src.find('static void rope_yarn')
print(src[i:i+1200])
print('=== cache_init ===')
j = src.find('static void ggml_rope_cache_init')
print(src[j:j+900])
