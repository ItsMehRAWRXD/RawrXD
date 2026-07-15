# RawrXD Roadmap v15.0

**Status:** Development  
**Focus:** Observability and Verification

---

## v14.7.3 - RELEASED ✅

- GUI built and running
- Tests passing
- CI/CD configured
- GitHub release published

**Branch:** `release/14.7.3`  
**Tag:** `v14.7.3`

---

## v15.0 - In Development

### Milestone 1: Validation Framework 🔄

**Goal:** Automated validation for every layer

```
tests/
├── cpu/           ✅ Directory created
├── gpu/           ✅ Directory created
├── tokenizer/     ✅ Directory created
├── gguf/          ✅ Directory created
├── kernels/       ✅ Directory created
├── transformer/   ✅ Directory created
├── sampler/       ✅ Directory created
└── integration/   ✅ Directory created
```

**Tasks:**
- [ ] CPU kernel tests (AVX2, AVX512, Scalar)
- [ ] GPU tests (Vulkan, WebGPU)
- [ ] Tokenizer tests
- [ ] GGUF format tests
- [ ] Kernel accuracy tests
- [ ] Transformer layer tests
- [ ] Sampler tests
- [ ] Integration tests
- [ ] Automated test runner

**Deliverable:** `run_validation.bat` executes all tests

---

### Milestone 2: Golden Reference 📋

**Goal:** Reference outputs for regression testing

```
reference/
├── tinyllama/
│   ├── logits.bin
│   ├── hidden_states.bin
│   ├── tokens.txt
│   └── manifest.json
├── phi3/
└── ministral/
```

**Tasks:**
- [ ] Generate reference outputs for tinyllama
- [ ] Generate reference outputs for phi3
- [ ] Store logits, hidden states, tokens
- [ ] Create SHA256 hashes
- [ ] Regression test automation

**Deliverable:** Regression tests compare against reference automatically

---

### Milestone 3: Runtime Profiler 📊

**Goal:** Per-operation profiling

**Operations to profile:**
- Tokenizer
- Embedding
- RMSNorm
- QKV
- RoPE
- Attention
- Softmax
- KV Cache
- FFN
- Sampling
- Decode

**Metrics:**
- Milliseconds
- Cycles
- Bandwidth
- FLOPs
- Cache misses

**Deliverable:** Profiler integrated into IDE

---

### Milestone 4: Runtime Inspector 🔍

**Goal:** Layer-by-layer inspection

**Features:**
- Click through layers
- View tensors
- See dimensions
- Memory addresses
- Quantization info
- Execution time

**Deliverable:** Inspector UI in IDE

---

### Milestone 5: Token Introspection 🔥

**Goal:** Complete inference debugger

**Display per token:**
- Logits
- Entropy
- Top-k
- Probability
- Sampled token
- Rejected tokens
- Latency
- KV cache usage

**Deliverable:** TokenHeatmap expanded to full debugger

---

### Milestone 6: Kernel Explorer ⚡

**Goal:** SIMD and GPU kernel view

**CPU:**
- AVX2
- AVX512
- Scalar

**GPU:**
- Vulkan
- WebGPU

**Metrics:**
- Dispatch count
- Average runtime
- Occupancy
- Utilization

**Deliverable:** Kernel explorer UI

---

### Milestone 7: Model Explorer 🗂️

**Goal:** GGUF model tree view

**Tree:**
```
Model
├── Metadata
├── Vocabulary
├── Tensors
├── Quantization
├── Layers
├── Memory
└── KV Cache
```

**Tensor view:**
- Histogram
- Min/max
- Checksum
- Quantization stats

**Deliverable:** Model explorer panel

---

### Milestone 8: Execution Timeline 📈

**Goal:** Browser-style performance profiler

**Visual:**
```
Tokenizer    ██████
Embedding    ██
Attention    ██████████
FFN          ████
Sampling     █
```

**Features:**
- Zoom to microsecond
- Filter by operation
- Compare runs

**Deliverable:** Timeline visualization

---

### Milestone 9: Memory Visualizer 💾

**Goal:** Live memory monitoring

**Display:**
- RAM usage
- VRAM usage
- KV Cache
- Allocator state
- Mapped files
- Tensor pool

**Features:**
- Fragmentation view
- Allocation history
- Leak detection

**Deliverable:** Memory visualization panel

---

### Milestone 10: AI Runtime Dashboard 🎯

**Goal:** One-screen overview

**Widgets:**
- Model info
- Backend status
- CPU/GPU utilization
- Context window
- TPS meter
- Latency graph
- Memory gauge
- Agent status
- Extensions list
- Telemetry stream

**Deliverable:** Dashboard UI

---

## Long-term Roadmap

- [ ] Multi-agent orchestration
- [ ] Visual execution graphs
- [ ] Live prompt inspection
- [ ] Extension SDK with hot reload
- [ ] Local model benchmarking
- [ ] Distributed inference
- [ ] Plugin marketplace
- [ ] Fine-tuning and LoRA
- [ ] Vulkan/WebGPU profiler
- [ ] Replayable sessions

---

## Current Priority

1. ✅ Complete automated regression testing (Milestone 1)
2. 🔄 Add runtime profiling (Milestone 3)
3. 📋 Validate CPU/GPU numerical parity
4. 📋 Expand performance benchmarking
5. 📋 Stabilize APIs and documentation

---

## Status

**v14.7.3:** ✅ RELEASED  
**v15.0-dev:** 🔄 Milestone 1 in progress

**Last Updated:** 2026-07-15
