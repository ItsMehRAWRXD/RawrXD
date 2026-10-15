import os
p = r'F:\rawrxd\tmp_llama_ref\ggml\src\ggml-cpu\ops.cpp'
src = open(p, 'rb').read().decode('utf-8', errors='replace')
i = src.find('static void ggml_compute_forward_soft_max_f32')
print(src[i+5860-5867:i+6050])
