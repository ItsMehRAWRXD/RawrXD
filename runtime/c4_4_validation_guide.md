# C4.4 Validation Guide

## Purpose

Verify that `StreamingMultiLayerBackend` produces correct output by comparing against llama.cpp reference.

## Prerequisites

1. **RawrXD runtime** built with C4.3 transformer execution
2. **llama.cpp** built and available
3. **Test model**: Small GGUF (e.g., `phi-2-q4_k.gguf` or `llama-3-8b-instruct-q4_k.gguf`)

## Validation Steps

### Step 1: Run RawrXD Test

```bash
./test_c4_4_validation \
    --model phi-2-q4_k.gguf \
    --prompt "The capital of France is" \
    --dump-logits \
    --max-tokens 5
```

Output:
```
=== C4.4 Validation Test ===

Model: phi-2-q4_k.gguf
Prompt: "The capital of France is"
...

=== Top 20 Logits ===
Rank |   Token ID |           Logit |     Probability
------------------------------------------------------------
     1 |      12345 |        12.345678 |        0.456789
     2 |      12346 |        11.234567 |        0.345678
...
```

### Step 2: Run llama.cpp Reference

```bash
./main \
    -m phi-2-q4_k.gguf \
    -p "The capital of France is" \
    --logits-all \
    -n 1 \
    --temp 0.0
```

Capture the logits output to a file:
```bash
./main -m phi-2-q4_k.gguf -p "The capital of France is" --logits-all -n 1 --temp 0.0 2>&1 | tee llama_logits.txt
```

### Step 3: Compare

Compare the top logits:
- Token IDs should match exactly
- Logit values should match within ±0.1% tolerance
- Top-1 token should be identical

### Step 4: Automated Comparison (Future)

```bash
# Generate reference
./main -m model.gguf -p "prompt" --logits-all --temp 0.0 > reference.txt

# Compare
./test_c4_4_validation --model model.gguf --prompt "prompt" --compare-ref reference.txt
```

## Expected Results

For a correct implementation:

| Metric | Tolerance | Notes |
|--------|-----------|-------|
| Top-1 token | Exact match | Should be identical |
| Top-5 tokens | Exact match | Order and IDs |
| Logit values | ±0.1% | Floating point differences |
| Generated text | Exact match | With temp=0.0 |

## Troubleshooting

### Logits don't match

1. **Check quantization**: Ensure both use same Q4_K format
2. **Check architecture**: Verify hidden_size, num_heads match
3. **Check RoPE**: If using modern models, ensure RoPE is implemented
4. **Check GQA**: Verify grouped query attention handling

### Generation differs

1. **Temperature**: Use `--temp 0.0` for deterministic comparison
2. **Top-k**: Set to vocab_size to disable filtering
3. **Tokenizer**: Ensure identical tokenization

## Success Criteria

✅ **PASS**: Top-5 tokens match llama.cpp exactly  
⚠️ **WARN**: Top-1 matches, minor differences in tail  
❌ **FAIL**: Top-1 differs or significant logit divergence

## Next Steps After Validation

Once validated:
1. ✅ Transformer execution is correct
2. → Optimize with AVX2/AVX-512 kernels
3. → Add FlashAttention-style attention
4. → Implement batched inference
5. → Add full CLI interface
