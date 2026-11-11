# Deep2Engine - 671B Model Inference on Dual GPU

## Overview

Deep2Engine is a production-ready inference engine for running 671B parameter language models on consumer dual-GPU setups (AMD Radeon RX 7900 XTX 32GB + RX 7800 XT 16GB). It implements out-of-core execution, tensor parallelism, and infinite context management.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Deep2Engine                              │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Token Generation Pipeline                             │   │
│  │  - Async token generation                              │   │
│  │  - Context management (128K tokens)                      │   │
│  │  - Streaming output                                    │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                  │
│  ┌──────────────────────────┼──────────────────────────┐        │
│  │                          │                          │        │
│  ▼                          ▼                          ▼        │
│ ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐   │
│ │OutOfCoreScheduler│  │ DualGpuPipeline │  │SequentialBlowoff│   │
│ │                 │  │                 │  │     Valve       │   │
│ │ Layer-by-layer │  │ Tensor Parallel │  │ Infinite Context│   │
│ │ execution with │  │ 2:1 split       │  │ Memory mgmt     │   │
│ │ 2:1 split      │  │ P2P transfer    │  │ SSD spillover   │   │
│ └────────┬────────┘  └────────┬────────┘  └────────┬────────┘   │
│          │                    │                    │             │
│          └────────────────────┼────────────────────┘             │
│                               │                                 │
│                    ┌──────────┴──────────┐                      │
│                    │ VulkanComputeKernels  │                      │
│                    │                     │                      │
│                    │ - RMSNorm           │                      │
│                    │ - QKV GEMM          │                      │
│                    │ - FlashAttention      │                      │
│                    │ - FFN SwiGLU          │                      │
│                    └──────────┬──────────┘                      │
│                               │                                 │
│                    ┌──────────┴──────────┐                      │
│                    │     Dual GPU          │                      │
│                    │  R9700    7800 XT     │                      │
│                    │  32GB     16GB        │                      │
│                    │  53L      27L         │                      │
│                    └───────────────────────┘                      │
└─────────────────────────────────────────────────────────────────┘
```

## Components

### 1. SequentialBlowoffValve (Never Ending Rainbow Road)

**Purpose**: Infinite context memory management with 4-tier hierarchy

**Features**:
- **GPU0 (R9700)**: 32GB - Hot tier, active compute
- **GPU1 (7800 XT)**: 16GB - Warm tier, prefetch buffer  
- **RAM**: 64GB - Medium tier, KV cache overflow
- **SSD**: 11TB - Cold tier, weight storage + spilled KV

**Key Capabilities**:
- Real Windows Overlapped I/O for async SSD operations
- IOCP (I/O Completion Port) for efficient async I/O
- Pressure-based automatic eviction (85% GPU0, 80% GPU1, 90% RAM)
- Sequential ring buffer for FIFO eviction
- Page fault handling with automatic loading from SSD
- Circular buffer for sequence ID recycling

**API**:
```cpp
SequentialBlowoffValve valve(config);
valve.Initialize();
uint64_t block_id = valve.AllocateBlock(size, is_kv_cache);
void* ptr = valve.Access(block_id);
valve.EvictToTier(block_id, Tier::SSD_NVMe);
```

### 2. OutOfCoreScheduler

**Purpose**: Layer-by-layer execution for 671B models that don't fit in GPU memory

**Features**:
- 80 transformer layers split 53/27 between GPU0/GPU1 (2:1 ratio)
- Real-time layer loading/eviction based on memory pressure
- Predictive prefetching (3 layers ahead)
- Async execution with worker threads
- Memory pressure relief with LRU eviction

**Layer Assignment**:
- GPU0 (R9700): Layers 0-52 (53 layers, ~445B params)
- GPU1 (7800 XT): Layers 53-79 (27 layers, ~226B params)

**API**:
```cpp
OutOfCoreScheduler scheduler(config);
scheduler.Initialize(gpu0, gpu1, queue0, queue1);
scheduler.LoadModelWeights(path);
uint64_t token_id = scheduler.ScheduleToken(prev_token);
```

### 3. DualGpuPipeline

**Purpose**: Tensor parallelism with P2P transfer between GPUs

**Features**:
- 2:1 tensor split (R9700 gets 2x the work of 7800 XT)
- Real Windows DMA for GPU-to-GPU P2P transfers
- Async command buffer execution
- All-Reduce and All-Gather collective operations
- Load balancing and pipeline efficiency tracking

**Tensor Sharding**:
```cpp
// 8192 x 8192 matrix
// GPU0: 5461 rows (66.7%)
// GPU1: 2731 rows (33.3%)
```

**API**:
```cpp
DualGpuPipeline pipeline(config);
pipeline.Initialize(gpu0, gpu1, queue0, queue1, queue_family);
pipeline.CreateShardedTensor(rows, cols, elem_size, shards);
pipeline.SubmitOp(TensorOpType::LINEAR, inputs, outputs, weights);
```

### 4. VulkanComputeKernels

**Purpose**: Optimized Vulkan compute shaders for transformer operations

**Kernels**:

#### RMSNorm
- **Workgroup**: (128, 1, 1)
- **Algorithm**: Parallel reduction for mean, then normalize
- **Optimization**: Shared memory for reduction

#### QKV GEMM
- **Workgroup**: (16, 16, 1) tile-based
- **Algorithm**: Tiled matrix multiply with shared memory
- **Fused**: Q, K, V projections in single kernel

#### FlashAttention
- **Workgroup**: (64, 1, 1) per head
- **Algorithm**: Online softmax with tiling
- **Optimization**: O(1) memory per sequence (FlashAttention v2)

#### FFN SwiGLU
- **Workgroup**: (256, 1, 1)
- **Algorithm**: Fused gate + up + Swish activation + down
- **Fused**: Single kernel for entire FFN

**API**:
```cpp
VulkanComputeKernels kernels;
kernels.Initialize(device, queue, queue_family);
kernels.DispatchRMSNorm(config, input, weight, output);
kernels.DispatchQKV(config, input, weight, output);
kernels.DispatchAttention(config, q, k, v, output);
kernels.DispatchFFN(config, input, gate_w, up_w, down_w, output);
```

### 5. Deep2Engine (Integration Layer)

**Purpose**: End-to-end inference engine combining all components

**Features**:
- Async token generation with worker thread
- Context management up to 128K tokens
- KV cache compression (FP8)
- Streaming token output
- Comprehensive performance reporting

**Configuration**:
```cpp
Deep2EngineConfig config;
config.num_layers = 80;
config.num_heads = 64;
config.head_dim = 128;
config.hidden_dim = 8192;
config.max_context_length = 128 * 1024;
config.gpu0_split_ratio = 0.667f;
config.gpu1_split_ratio = 0.333f;
config.enable_kv_cache_compression = true;
config.kv_cache_quantization = 8.0f;  // FP8
```

**Usage**:
```cpp
Deep2Engine engine(config);
engine.Initialize(gpu0, gpu1, queue0, queue1);
engine.LoadModel("path/to/671B/model");

// Generate tokens
std::vector<uint32_t> input = {token_ids...};
engine.ExtendContext(input);

uint64_t token_id = engine.GenerateToken(input);
engine.WaitForToken(token_id, 10000);

GenerationResult result = engine.GetTokenResult(token_id);
std::cout << "Generated token: " << result.token_id << "\n";
std::cout << "Latency: " << result.latency_ms << " ms\n";
```

## Performance Characteristics

### Memory Requirements

| Component | GPU0 (R9700) | GPU1 (7800 XT) | RAM | SSD |
|-----------|--------------|----------------|-----|-----|
| Weights | 28GB | 14GB | - | 671GB |
| KV Cache | Variable | Variable | 56GB | Spillover |
| Activations | ~2GB | ~1GB | - | - |
| **Total** | **30GB** | **15GB** | **56GB** | **11TB** |

### Expected Performance

| Metric | Target | Notes |
|--------|--------|-------|
| Throughput | 2-5 tokens/sec | Depends on context length |
| Latency | 200-500ms/token | With full context |
| Memory Pressure | <90% | Automatic eviction |
| P2P Bandwidth | 32 GB/s | PCIe 4.0 x16 |
| SSD Read | 7 GB/s | NVMe sequential |

### Layer Distribution

```
Layer 0-52:   GPU0 (R9700)     - 53 layers, 445B params
Layer 53-79:  GPU1 (7800 XT)   - 27 layers, 226B params
              Total: 80 layers, 671B params
```

## Build Instructions

### Prerequisites
- Windows 10/11
- Visual Studio 2022
- Vulkan SDK 1.3+
- CMake 3.20+
- Ninja

### Build
```bash
cd D:\RawrXD
mkdir build
cd build
cmake -G Ninja -DCMAKE_BUILD_TYPE=Release ..
ninja
```

### Run Tests
```bash
# Integration test
Deep2Engine_IntegrationTest.exe

# Smoke test
SequentialBlowoffValve_SmokeTest.exe
```

## File Structure

```
src/
├── memory/
│   ├── SequentialBlowoffValve.hpp    # Infinite context memory
│   └── SequentialBlowoffValve.cpp
├── inference/
│   ├── OutOfCoreScheduler.hpp        # Layer scheduler
│   ├── OutOfCoreScheduler.cpp
│   ├── DualGpuPipeline.hpp           # Tensor parallelism
│   ├── DualGpuPipeline.cpp
│   ├── Deep2Engine.hpp               # Main engine
│   └── Deep2Engine.cpp
├── kernels/
│   ├── VulkanComputeKernels.hpp      # GPU kernels
│   └── VulkanComputeKernels.cpp
└── tests/
    └── Deep2Engine_IntegrationTest.cpp # Integration tests
```

## API Reference

### SequentialBlowoffValve

```cpp
// Configuration
struct BlowoffConfig {
    size_t gpu0_max_bytes = 28ULL * 1024 * 1024 * 1024;
    size_t gpu1_max_bytes = 14ULL * 1024 * 1024 * 1024;
    size_t ram_max_bytes = 56ULL * 1024 * 1024 * 1024;
    float gpu0_pressure_threshold = 0.85f;
    std::string ssd_swap_path = "D:\\RawrXD_Cache\\swap.bin";
};

// Core API
bool Initialize();
void Shutdown();
uint64_t AllocateBlock(size_t size_bytes, bool is_kv_cache);
bool FreeBlock(uint64_t block_id);
void* Access(uint64_t block_id);
bool EvictToTier(uint64_t block_id, Tier target_tier);
float GetPressure(Tier tier) const;
bool ShouldBlowOff(Tier tier) const;
void EmergencyBlowOff(size_t required_bytes, Tier from_tier);
```

### OutOfCoreScheduler

```cpp
// Configuration
struct OutOfCoreConfig {
    uint32_t num_layers = 80;
    uint32_t num_heads = 64;
    uint32_t head_dim = 128;
    uint32_t hidden_dim = 8192;
    float gpu0_split_ratio = 0.667f;
    float gpu1_split_ratio = 0.333f;
    uint32_t prefetch_lookahead = 3;
};

// Core API
bool Initialize(VkDevice gpu0, VkDevice gpu1, VkQueue q0, VkQueue q1);
bool LoadModelWeights(const std::string& path);
uint64_t ScheduleToken(uint64_t prev_token);
bool WaitForToken(uint64_t token_id, uint32_t timeout_ms);
OutOfCoreMetrics GetMetrics() const;
```

### DualGpuPipeline

```cpp
// Configuration
struct DualGpuConfig {
    float gpu0_weight_ratio = 0.667f;
    float gpu1_weight_ratio = 0.333f;
    bool enable_p2p_transfer = true;
    bool enable_async_execution = true;
};

// Core API
bool Initialize(VkDevice gpu0, VkDevice gpu1, VkQueue q0, VkQueue q1, 
                uint32_t queue_family);
bool CreateShardedTensor(uint32_t rows, uint32_t cols, uint32_t elem_size,
                         std::vector<TensorShard>& shards);
uint64_t SubmitOp(TensorOpType op, const std::vector<TensorShard>& inputs,
                  std::vector<TensorShard>& outputs, 
                  const std::vector<TensorShard>& weights);
bool AllReduce(const TensorShard& input, TensorShard& output);
bool TransferGpuToGpu(uint32_t src_gpu, uint32_t dst_gpu,
                      const TensorShard& src, TensorShard& dst);
```

### Deep2Engine

```cpp
// Configuration
struct Deep2EngineConfig {
    uint32_t num_layers = 80;
    uint32_t max_context_length = 128 * 1024;
    float gpu0_split_ratio = 0.667f;
    bool enable_kv_cache_compression = true;
    float kv_cache_quantization = 8.0f;
};

// Core API
bool Initialize(VkDevice gpu0, VkDevice gpu1, VkQueue q0, VkQueue q1);
bool LoadModel(const std::string& path);
uint64_t GenerateToken(const std::vector<uint32_t>& input);
bool WaitForToken(uint64_t token_id, uint32_t timeout_ms);
GenerationResult GetTokenResult(uint64_t token_id);
bool ExtendContext(const std::vector<uint32_t>& tokens);
std::string GetPerformanceReport() const;
```

## Performance Tuning

### GPU Split Ratio
Adjust based on actual performance:
```cpp
// If GPU0 is faster than expected
config.gpu0_split_ratio = 0.70f;  // Give GPU0 more layers

// If GPU1 is bottleneck
config.gpu0_split_ratio = 0.75f;  // Reduce GPU1 load
```

### Prefetch Lookahead
```cpp
// More lookahead = more memory usage, less latency
config.prefetch_lookahead = 5;  // Prefetch 5 layers ahead

// Less lookahead = less memory, more latency
config.prefetch_lookahead = 2;
```

### KV Cache Compression
```cpp
// FP8 compression (8 bits)
config.kv_cache_quantization = 8.0f;  // 2x memory savings

// FP16 (16 bits) - no compression
config.kv_cache_quantization = 16.0f;

// FP4 (4 bits) - aggressive compression
config.kv_cache_quantization = 4.0f;
```

## Troubleshooting

### Out of Memory
1. Reduce `prefetch_lookahead`
2. Enable KV cache compression: `kv_cache_quantization = 8.0f`
3. Reduce context length: `max_context_length`
4. Check SSD swap path has sufficient space

### Low Throughput
1. Verify P2P transfer is enabled
2. Check GPU utilization in Task Manager
3. Reduce batch size if using batching
4. Enable async prefetch: `enable_async_prefetch = true`

### High Latency
1. Increase prefetch lookahead
2. Pre-warm model layers
3. Check SSD read speed (should be >3 GB/s)
4. Reduce context length

## License

MIT License - See LICENSE file

## Credits

- FlashAttention algorithm: Dao et al.
- Vulkan compute: Khronos Group
- Out-of-core scheduling: Inspired by DeepSpeed ZeRO-Infinity
