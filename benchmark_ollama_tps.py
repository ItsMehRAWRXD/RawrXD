#!/usr/bin/env python3
"""
Ollama TPS Benchmark - Python version with proper token counting
Processes models in batches of 5
"""

import ollama
import time
import csv
from datetime import datetime

# Model list - 24 models total
MODELS = [
    # Batch 1 - Small models
    "qwen2.5-coder:1.5b-base",
    "nemotron-3-nano:4b", 
    "llama3.2:3b",
    "gemma3:4b",
    "qwen3:8b",
    
    # Batch 2 - Medium models
    "llama3.1:8b",
    "granite3.3:8b",
    "deepseek-coder-v2:16b",
    "qwen3.8:27b",
    "starcoder2:15b",
    
    # Batch 3 - Large models
    "deepseek-r1:32b",
    "gemma3:latest",
    "ornith-1.5:35b",
    "bigdaddyglocal:latest",
    "bigdaddygnative:latest",
    
    # Batch 4 - XL models  
    "deepseek-r1:70b",
    "gpt-oss:20b",
    "gpt-oss:latest",
    "qwen3-next:80b",
    "laguna-s-2.1:Q4_K_M",
    
    # Batch 5 - Specialized models
    "bluehawana/deepseek-v4-flash:iq2_m",
    "pdurugyan/qwen3.5-9b-deepseek-v4-flash-Q4_K_M-v_2:latest",
    "qwen35-40b-heretic-q8:latest",
    "nemotron-3.5-lightning:30b",
]

PROMPT = "Explain quantum computing in one paragraph."
RESULTS_FILE = r"F:\OllamaModels\ollama_tps_benchmark.csv"

def benchmark_model(model_name):
    """Benchmark a single model and return TPS metrics"""
    print(f"\n  Testing: {model_name}")
    
    try:
        start_time = time.time()
        
        # Generate response
        response = ollama.generate(
            model=model_name,
            prompt=PROMPT,
            options={"temperature": 0.7, "num_predict": 200}
        )
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Get token count from response
        eval_count = response.get('eval_count', 0)
        prompt_eval_count = response.get('prompt_eval_count', 0)
        
        # Calculate TPS (tokens per second for generation)
        tps = eval_count / duration if duration > 0 else 0
        
        print(f"    [OK] TPS: {tps:.2f} | Tokens: {eval_count} | Time: {duration:.2f}s")
        
        return {
            'model': model_name,
            'tokens_generated': eval_count,
            'prompt_tokens': prompt_eval_count,
            'duration_sec': round(duration, 2),
            'tps': round(tps, 2),
            'status': 'OK'
        }
        
    except Exception as e:
        print(f"    [FAIL] ERROR: {str(e)[:80]}")
        return {
            'model': model_name,
            'tokens_generated': 0,
            'prompt_tokens': 0,
            'duration_sec': 0,
            'tps': 0,
            'status': f'ERROR: {str(e)[:80]}'
        }

def main():
    print("=" * 60)
    print("OLLAMA TPS BENCHMARK")
    print(f"Models: {len(MODELS)}")
    print(f"Prompt: {PROMPT}")
    print("=" * 60)
    
    results = []
    batch_size = 5
    
    for i in range(0, len(MODELS), batch_size):
        batch_num = i // batch_size + 1
        batch = MODELS[i:i+batch_size]
        
        print(f"\n{'='*60}")
        print(f"BATCH {batch_num}/{(len(MODELS) + batch_size - 1) // batch_size}")
        print(f"{'='*60}")
        
        for model in batch:
            result = benchmark_model(model)
            results.append(result)
            time.sleep(1)  # Brief pause between runs
    
    # Save results
    with open(RESULTS_FILE, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['model', 'tokens_generated', 'prompt_tokens', 'duration_sec', 'tps', 'status'])
        writer.writeheader()
        writer.writerows(results)
    
    # Print summary
    print(f"\n{'='*60}")
    print("FINAL RESULTS")
    print(f"{'='*60}")
    print(f"{'Model':<50} {'TPS':<10} {'Tokens':<8} {'Time':<8} {'Status'}")
    print(f"{'-'*60}")
    for r in results:
        print(f"{r['model']:<50} {r['tps']:<10} {r['tokens_generated']:<8} {r['duration_sec']:<8} {r['status']}")
    
    print(f"\nResults saved to: {RESULTS_FILE}")
    
    # Find fastest model
    successful = [r for r in results if r['status'] == 'OK']
    if successful:
        fastest = max(successful, key=lambda x: x['tps'])
        print(f"\nFastest Model: {fastest['model']} at {fastest['tps']:.2f} TPS")

if __name__ == "__main__":
    main()
