# qwen_reference_coherence.py -- decisive check: does REAL llama.cpp produce
# coherent output for qwen2.5-coder-1.5b-base.gguf? Greedy (temperature 0),
# same prompt family as the parity battery.
from llama_cpp import Llama

ll = Llama(model_path=r"F:\rawrxd\models\qwen2.5-coder_1.5b-base.gguf",
           n_ctx=1024, n_gpu_layers=0, seed=0, verbose=False)

for prompt in ["def add(a, b):", "int add(int a, int b) {", '<|repo_name|>test<|file_sep|>calc.py\n']:
    out = ll.create_completion(prompt, max_tokens=48, temperature=0.0, top_k=1)
    print('PROMPT :', repr(prompt))
    print('REFGEN :', repr(out['choices'][0]['text']))
    print('---')
