import re, os
p = r'F:\rawrxd\tmp_llama_ref\ggml\src\ggml-cpu\arch\x86\quants.c'
src = open(p, 'rb').read().decode('utf-8', errors='replace')
i = src.find('ggml_vec_dot_f32')
while i != -1:
    chunk = src[i:i+1500]
    if 'AVX2' in chunk or '_mm256' in chunk:
        print(chunk[:1500])
        print('======')
        break
    i = src.find('ggml_vec_dot_f32', i+1)
