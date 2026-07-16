# RawrXD Advanced Inference Guide

Comprehensive guide for advanced inference optimizations in RawrXD.

## Table of Contents

1. [Overview](#overview)
2. [Speculative Decoding](#speculative-decoding)
3. [Continuous Batching](#continuous-batching)
4. [Prefix Caching](#prefix-caching)
5. [Dynamic Batching](#dynamic-batching)
6. [Flash Attention](#flash-attention)
7. [Quantized GEMM](#quantized-gemm)
8. [Performance Tuning](#performance-tuning)

## Overview

RawrXD implements state-of-the-art inference optimizations:

| Technique | Speedup | Use Case |
|-----------|---------|----------|
| Speculative Decoding | 1.5-2x | Long sequences |
| Continuous Batching | 2-5x throughput | High concurrency |
| Prefix Caching | 10-50% | Repeated prompts |
| Flash Attention | 2-4x memory | Long context |
| Quantized GEMM | 2-4x compute | Edge deployment |

## Speculative Decoding

Speculative decoding uses a smaller draft model to predict multiple tokens, then verifies them in parallel with the target model.

### Configuration

```cpp
SpeculativeConfig config;
config.num_draft_tokens = 4;        // Draft 4 tokens at a time
config.acceptance_threshold = 0.6f; // Accept if prob > 0.6
config.use_tree_attention = true;   // Use tree-based verification

auto decoder = std::make_unique<SpeculativeDecoder>(config);
decoder->initialize(target_model, draft_model);
```

### Draft Models

| Type | Speed | Accuracy | Setup |
|------|-------|----------|-------|
| Small Model | Fast | High | Requires separate model |
| Self-Speculative | Medium | Medium | Uses target model layers |
| Prompt Lookup | Very Fast | Variable | No model needed |

### Usage

```cpp
auto result = decoder->speculativeStep(context);
// result.accepted_tokens contains verified tokens
// result.num_accepted shows how many were accepted
```

## Continuous Batching

Process multiple requests concurrently with dynamic batch formation.

### Configuration

```cpp
ContinuousBatchingConfig config;
config.max_batch_size = 16;
config.max_tokens_per_batch = 8192;
config.batch_timeout_ms = 10.0f;
config.enable_chunking = true;

auto batcher = std::make_unique<ContinuousBatcher>(config);
batcher->initialize(model);
batcher->start();
```

### Request Submission

```cpp
Request request;
request.prompt_tokens = tokenizer.encode(prompt);
request.max_new_tokens = 256;
request.temperature = 0.7f;
request.stream = true;
request.stream_callback = [](const std::vector<int>& tokens) {
    // Handle streaming output
};

batcher->submitRequest(request);
```

### PagedAttention

Memory-efficient KV cache management:

```cpp
PagedAttentionManager page_manager(10000);  // 10K pages

// Allocate pages for sequence
auto pages = page_manager.allocatePages(seq_id, num_tokens);

// Automatic page reuse and eviction
```

## Prefix Caching

Cache KV activations for common prompt prefixes.

### Configuration

```cpp
PrefixCacheConfig config;
config.max_entries = 1000;
config.max_memory_mb = 1024;
config.min_prefix_length = 10;

PrefixCache cache(config);
cache.initialize();
```

### Usage

```cpp
// Check cache
auto cached = cache.lookup(prompt_tokens);
if (cached) {
    // Use cached KV cache
    kv_cache = cached->kv_cache_data;
} else {
    // Compute and store
    kv_cache = model.computeKV(prompt_tokens);
    cache.store(prompt_tokens, kv_cache);
}
```

### Radix Tree Cache

More efficient for overlapping prefixes:

```cpp
RadixPrefixCache radix_cache(config);

// Automatically shares prefixes
// "The weather in" and "The weather in New York" share "The weather in"
```

## Dynamic Batching

Optimize batch sizes based on sequence lengths.

### Configuration

```cpp
DynamicBatchingConfig config;
config.max_batch_size = 16;
config.max_tokens_per_batch = 8192;
config.sort_by_length = true;

DynamicBatcher batcher(config);
```

### Bucketing

Group similar-length sequences:

```cpp
LengthBucketer bucketer({32, 64, 128, 256, 512, 1024});
int bucket = bucketer.getBucket(sequence_length);
int padded_length = bucketer.padToBucket(sequence_length);
```

### Token Budget

Control memory usage:

```cpp
TokenBudgetBatcher budget_batcher(8192);  // Max 8K tokens per batch

for (auto& request : requests) {
    if (budget_batcher.tryAdd(request, tokens)) {
        // Added to batch
    } else {
        // Process current batch first
        auto batch = budget_batcher.finalize();
        process(batch);
        budget_batcher.tryAdd(request, tokens);
    }
}
```

## Flash Attention

Memory-efficient attention computation.

### Configuration

```cpp
FlashAttentionConfig config;
config.block_size_q = 128;
config.block_size_kv = 128;
config.causal = true;
config.softmax_scale = 1.0f / sqrt(head_dim);

FlashAttention flash_attn(config);
```

### Usage

```cpp
// Standard attention
auto output = flash_attn.forward(query, key, value);

// With KV cache for generation
auto output = flash_attn.forwardWithKVCache(
    query, key_cache, value_cache, cache_len);

// Multi-head attention
auto output = flash_attn.multiHeadForward(
    query, key, value, num_heads, attention_mask);
```

### Flash Decoding

Optimized for autoregressive generation:

```cpp
// Single token decoding
auto output = FlashDecoding::decodeStep(
    query, key_cache, value_cache, seq_len);

// Parallel retrieval for long sequences
auto output = FlashDecoding::decodeParallel(
    query, key_cache, value_cache, seq_len, num_chunks);
```

## Quantized GEMM

Accelerated matrix multiplication with quantized weights.

### Configuration

```cpp
QuantizedGEMMConfig config;
config.type = QuantizedGEMMConfig::Type::INT4;
config.group_size = 128;
config.per_channel = false;

QuantizedGEMM gemm(config);
```

### Usage

```cpp
// Quantize weights
auto [weights_q, scales] = quant_utils::quantizeInt4(weights, 128);

// Quantized GEMM
auto output = gemm.forward(activations, weights_q, scales);
```

### GPTQ

Group-wise quantization with activation reordering:

```cpp
GPTQGEMM gptq(128, true);  // group_size=128, act_order=true
auto output = gptq.forwardGPTQ(activations, weights_q, scales, g_idx);
```

### AWQ

Activation-aware quantization:

```cpp
AWQGEMM awq(128);
auto output = awq.forwardAWQ(activations, weights_q, scales, awq_scales);
```

## Performance Tuning

### Benchmarking

```cpp
// Benchmark attention
AttentionBenchmark::benchmarkFlashAttention(4096, 128, 32);

// Compare implementations
AttentionBenchmark::compareImplementations();
```

### Optimization Checklist

1. **Enable Flash Attention**: Reduces memory from O(N²) to O(N)
2. **Use Continuous Batching**: Increases throughput 2-5x
3. **Enable Prefix Caching**: Reduces compute for repeated prompts
4. **Quantize Weights**: INT4 for memory, INT8 for accuracy
5. **Tune Batch Size**: Find optimal for your hardware
6. **Use Speculative Decoding**: For long sequences

### Memory Optimization

```cpp
// Gradient checkpointing for training
MemoryOptimizer::GradientCheckpointing gc;
gc.enable();
gc.checkpointLayer("transformer.layers.0");

// CPU offloading
MemoryOptimizer::CPUOffload offload;
offload.enable();
offload.offload(optimizer_state);
```

### Profiling

```cpp
MemoryOptimizer::MemoryProfiler profiler;
profiler.startProfiling();

// Run inference

profiler.endProfiling();
profiler.printReport();
```

## Examples

### High-Throughput Server

```cpp
// Combine all optimizations
auto batcher = std::make_unique<ContinuousBatcher>(config);
batcher->initialize(model);

auto cache = std::make_unique<PrefixCache>(cache_config);
auto flash = std::make_unique<FlashAttention>(flash_config);

batcher->start();

// Handle requests with all optimizations
```

### Edge Deployment

```cpp
// Quantized + Flash Attention
QuantizedGEMM gemm(QuantizedGEMMConfig::Type::INT4);
FlashAttention flash_attn(config);

// Minimal memory footprint
```

## Performance Expectations

| Configuration | Throughput | Latency | Memory |
|---------------|------------|---------|--------|
| Baseline | 10 tok/s | 100ms | 16GB |
| + Flash Attention | 12 tok/s | 80ms | 8GB |
| + Continuous Batching | 50 tok/s | 150ms | 16GB |
| + Speculative | 20 tok/s | 50ms | 16GB |
| + Quantized (INT4) | 40 tok/s | 25ms | 4GB |
| All Optimizations | 100+ tok/s | 30ms | 8GB |

*Results vary based on model size, sequence length, and hardware.*
