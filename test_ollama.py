import ollama
import time

print('Starting generation...')
start = time.time()
r = ollama.generate(model='qwen2.5-coder:1.5b-base', prompt='Hello', options={'num_predict': 10})
print(f"Response: {r['response'][:50]}")
print(f"Eval count: {r.get('eval_count', 0)}")
print(f"Time: {time.time() - start:.2f}s")
