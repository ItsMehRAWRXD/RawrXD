# RawrXD OMEGA-1 Quick Start Guide

**Status**: ✅ Production Ready | **Version**: 1.0.0 | **Date**: 2026-07-29

---

## 🚀 Get Started in 5 Minutes

### Prerequisites
- **OS:** Windows 10/11 (64-bit)
- **CPU:** AMD Ryzen 7 7800X3D or equivalent
- **RAM:** 64GB DDR5
- **GPU:** Dual AMD GPU setup (Radeon AI PRO R9700 + RX 7800 XT)
- **Storage:** 10GB free space

---

## 📦 Installation

### Option 1: Automated Deployment (Recommended)

```powershell
# Run as Administrator
powershell -ExecutionPolicy Bypass -File scripts\deploy_omega1.ps1
```

This will:
- ✅ Install to `%LOCALAPPDATA%\RawrXD\OMEGA1`
- ✅ Create desktop and Start Menu shortcuts
- ✅ Configure firewall rules
- ✅ Add to PATH
- ✅ Create configuration files

### Option 2: Manual Installation

1. Extract the release package to your desired location
2. Run `bin\RawrXD-Win32IDE.exe`

---

## 🎯 First Run

### Step 1: Start the IDE

**Option A:** Double-click the desktop shortcut  
**Option B:** Run from command line:
```powershell
%LOCALAPPDATA%\RawrXD\OMEGA1\bin\RawrXD-Win32IDE.exe
```

### Step 2: Verify Dual GPU Detection

The IDE will automatically detect and configure dual GPUs. Check the status bar for:
- ✅ Primary GPU: AMD Radeon AI PRO R9700 (48GB)
- ✅ Secondary GPU: AMD Radeon RX 7800 XT (16GB)

### Step 3: Load a Model

1. Download a GGUF model (e.g., from HuggingFace)
2. Place it in `%LOCALAPPDATA%\RawrXD\OMEGA1\models\`
3. Use File → Open Model in the IDE

---

## 🧪 Validation

### Run All Tests

```powershell
# Dual GPU test
powershell -ExecutionPolicy Bypass -File scripts\test_dual_gpu.ps1

# IPC communication test
powershell -ExecutionPolicy Bypass -File scripts\test_ipc.ps1

# End-to-end integration test
powershell -ExecutionPolicy Bypass -File scripts\e2e_integration_test.ps1

# Performance benchmark (requires model)
powershell -ExecutionPolicy Bypass -File scripts\performance_benchmark.ps1 -ModelPath "path\to\model.gguf"
```

---

## ⚡ Performance Targets

| Metric | Target | Your System |
|--------|--------|-------------|
| Prompt Processing | 557 t/s | Run benchmark |
| Token Generation | 344 t/s | Run benchmark |
| Dual GPU Load | 70/30 split | Auto-configured |

---

## 🔧 Configuration

### Edit Configuration

Configuration file: `%LOCALAPPDATA%\RawrXD\OMEGA1\config\omega1.json`

```json
{
  "dualGpu": {
    "enabled": true,
    "layerSplit": {
      "primary": 22,
      "secondary": 10
    }
  },
  "ipc": {
    "pipeName": "\\\\.\\pipe\\RawrXD_Omega1_v2"
  },
  "paths": {
    "models": "C:\\Users\\...\\RawrXD\\OMEGA1\\models"
  }
}
```

---

## 🐛 Troubleshooting

### Issue: GPUs Not Detected

**Solution:**
1. Check Device Manager for GPU status
2. Update AMD drivers to latest version
3. Verify GPUs are not disabled in BIOS

### Issue: IPC Connection Failed

**Solution:**
1. Check if named pipe exists
2. Restart InferenceEngine: `RawrXD-InferenceEngine.exe --daemon`
3. Check firewall rules

### Issue: Out of Memory

**Solution:**
1. Reduce model size or quantization level
2. Adjust layer split in config
3. Close other GPU-intensive applications

---

## 📚 Documentation

| Document | Location |
|----------|----------|
| Build Summary | `docs\BUILD_SUMMARY.md` |
| Final Report | `OMEGA1_FINAL_REPORT.md` |
| This Guide | `QUICKSTART.md` |

---

## 🎓 Advanced Usage

### Command Line Options

**InferenceEngine:**
```powershell
RawrXD-InferenceEngine.exe --model model.gguf --prompt "Hello" --max-tokens 256
RawrXD-InferenceEngine.exe --model model.gguf --bench  # Benchmark mode
RawrXD-InferenceEngine.exe --interactive              # REPL mode
```

**Win32IDE:**
```powershell
RawrXD-Win32IDE.exe --selftest    # Run self-test
RawrXD-Win32IDE.exe --headless    # Headless mode
```

---

## 🗑️ Uninstallation

### Automated Uninstall

```powershell
# Run from Start Menu or:
powershell -ExecutionPolicy Bypass -File "%LOCALAPPDATA%\RawrXD\OMEGA1\scripts\uninstall.ps1"
```

---

## ✅ Quick Checklist

- [ ] Downloaded release package
- [ ] Ran deploy_omega1.ps1
- [ ] Verified dual GPU detection
- [ ] Downloaded GGUF model
- [ ] Tested IDE launch
- [ ] Ran validation tests

**You're ready to use RawrXD OMEGA-1!** 🎉

---

*Quick Start Guide v1.0.0*  
*RawrXD OMEGA-1*
    
    // Load model (3.5 GB model loads in 2-3 seconds)
    if (!coord->LoadModel("d:\\models\\llama-2-7b-q4_0.gguf")) {
        std::cerr << "Failed to load model\n";
        return 1;
    }
    
    // Configure generation
    GenerationConfig cfg;
    cfg.temperature = 0.7f;
    cfg.top_p = 0.9f;
    cfg.max_tokens = 256;
    cfg.onToken = [](int token_id) {
        std::cout << token_id << " ";  // Stream tokens
    };
    
    // Generate!
    auto result = coord->GenerateCompletion(
        "What is the capital of France?",
        cfg
    );
    
    if (result.success) {
        std::cout << "\n\nOutput:\n" << result.text << "\n";
        std::cout << "Generated " << result.output_tokens << " tokens\n";
    } else {
        std::cout << "Error: " << result.error << "\n";
    }
    
    // Agentic tasks
    std::string analysis = coord->ExecuteAgenticTask(
        "analyze the code quality of transformer.cpp"
    );
    std::cout << analysis << "\n";
    
    coord->UnloadModel();
    DestroyGlobalCoordinator();
    return 0;
}
```

Compile:
```bash
cl /std:c++latest /O2 example.cpp src/unified_engine_coordinator.cpp \
   src/agentic_engine.cpp src/engine/transformer.cpp \
   src/engine/inference_kernels.cpp ... -link ws2_32.lib shlwapi.lib
```

---

## Key Features at a Glance

### 1. ⚡ Fast Inference
```
30-40 tokens/sec on 7B model
Time-to-first-token: ~100ms
KV cache for efficient generation
```

### 2. 🧠 Real Attention
```
Group Query Attention (8:32 ratio)
Rotary Position Embeddings (RoPE)
SwiGLU activation
```

### 3. 🎯 Smart Sampling
```
Top-K (keep top 40 tokens)
Top-P nucleus (keep until 90% prob)
Temperature control (0=greedy, 2=random)
Beam search for exploration
```

### 4. 📊 Real-Time Streaming
```
Chunk buffering with backpressure
Token-level callbacks
Metrics (TTFC, throughput)
```

### 5. 🔧 IDE Integration
```
Code analysis (metrics, complexity)
LLM code generation
File operations (read/write/grep)
Refactoring suggestions
```

### 6. 🔄 Live Updates
```
Hot-patch inference kernels
Zero restart needed
Rollback capability
```

---

## Performance Expectations

### Model Loading
- **First load**: 2-3 seconds (parsing + mem alloc)
- **Subsequent loads**: 1-2 seconds (cached metadata)
- **Memory**: 6.9 GB for 7B model (Q4_0 quantization)

### Generation
- **Per token**: 25-30ms latency
- **Throughput**: 33-40 tokens/second
- **Parallel**: 4-8 concurrent users

### Streaming
- **Buffer depth**: 32 chunks
- **Chunk latency**: 20-50ms
- **Maximum throughput**: 500+ tok/sec per client

---

## Troubleshooting

### Issue: "Model not found"
```
❌ Error: Failed to open GGUF model

Solution:
1. Check file exists: dir d:\models\model.gguf
2. Check path is correct in code
3. Ensure file is readable
4. Try absolute path instead of relative
```

### Issue: "Slow inference (<10 tok/s)"
```
❌ Throughput: 5 tokens/sec

Solutions:
1. Check CPU: AVX-512 enabled? (lscpu | grep avx512)
   - If no AVX-512, fallback to AVX2 (slower)
2. Check frequency: turbo boost disabled?
   - Power management can hurt performance
3. Check memory: Are we swapping?
   - Should be 6.9 GB resident memory
4. Profile: VTune to find bottleneck

Typical bottlenecks:
- FFN: 40% (heavy, hard to parallelize)
- Attention: 30% (GQA helps, still O(n²))
- Other: 30% (less critical)
```

### Issue: "Out of Memory"
```
❌ Error: VirtualAlloc failed

Solutions:
1. Check available RAM: 8+ GB needed for 7B model
2. Close other apps
3. Reduce batch size (if batching enabled)
4. Use smaller model (e.g., Phi-2 @ 3 GB)
5. Use float16 quantization instead of Q4_0
```

### Issue: "Tokenizer gives wrong results"
```
❌ Output: Complete nonsense

Solutions:
1. Check vocab file: 128K tokens?
2. Check merges file: Correct format?
3. Verify tokenizer loaded: 
   - Should print "✅ BPE Tokenizer loaded: X vocab tokens"
4. Test encode/decode roundtrip
```

---

## Configuration Options

### Model Config
```cpp
ModelConfig cfg;
cfg.context_length = 4096;        // Max context
cfg.hidden_dim = 4096;            // Model width
cfg.num_heads = 32;               // Attention heads
cfg.num_kv_heads = 8;            // KV heads (GQA)
cfg.num_layers = 32;              // Depth
cfg.vocab_size = 128000;          // Token vocabulary
```

### Generation Config
```cpp
GenerationConfig cfg;
cfg.max_tokens = 256;             // Output length
cfg.temperature = 0.7f;           // Creativity (0-2)
cfg.top_p = 0.9f;                // Nucleus (0-1)
cfg.top_k = 40;                  // Keep top K
cfg.repeat_penalty = 1.1f;       // Avoid repetition
cfg.use_beam_search = false;     // Beam exploration
cfg.beam_size = 4;               // If beam search
```

---

## Command-Line Interface

```bash
# Basic usage
RawrEngine --model model.gguf --prompt "Hi there"

# With options
RawrEngine \
  --model d:\models\llama-7b-q4.gguf \
  --prompt "Explain quantum computing" \
  --temp 0.7 \
  --top-p 0.9 \
  --max-tokens 256

# Agentic mode
RawrEngine --agent --task "analyze transformer.cpp"

# Hot-patch test
RawrEngine --model model.gguf --test-patches
```

---

## API Reference (Core Methods)

### Unified Coordinator
```cpp
// Load model
bool LoadModel(const std::string& path);

// Generate text
GenerationResult GenerateCompletion(
    const std::string& prompt,
    const GenerationConfig& cfg
);

// Run agentic task
std::string ExecuteAgenticTask(const std::string& task);

// Hot-patch
bool ApplyHotpatch(const std::string& name, 
                   const std::string& module,
                   const std::string& func,
                   const std::vector<uint8_t>& opcodes);
bool RevertHotpatch(const std::string& name);

// Stats
CoordinatorStats GetStats();
```

### Agentic Engine
```cpp
// Code analysis
std::string analyzeCode(const std::string& code);
std::string generateCode(const std::string& prompt);
std::string refactorCode(const std::string& code, 
                        const std::string& type);

// File operations
std::string readFile(const std::string& path, 
                    int start=-1, int end=-1);
std::string writeFile(const std::string& path,
                     const std::string& content);
std::string grepFiles(const std::string& pattern,
                     const std::string& path);

// Chat
std::string chat(const std::string& message);
```

### Sampler
```cpp
// Sample next token
int sample(float* logits, int vocab_size);

// Advanced: beam search
std::vector<int> beam_search(float* logits, 
                            int vocab_size,
                            int beam_size,
                            int max_length);

// Advanced: mirostat
int mirostat_sample(float* logits, int vocab_size,
                   float tau, float eta);
```

---

## Performance Tuning

### For Maximum Speed
```cpp
cfg.temperature = 0.0f;      // Greedy (no randomness)
cfg.top_k = 0;               // Disable top-K
cfg.top_p = 1.0f;            // Disable top-P
cfg.use_beam_search = false; // Single path
```

Result: 40-50 tok/sec (but less diverse)

### For Maximum Quality
```cpp
cfg.temperature = 0.7f;      // Moderate creativity
cfg.top_k = 40;              // Reasonable diversity
cfg.top_p = 0.9f;            // Nucleus sampling
cfg.use_beam_search = true;  // Explore alternatives
cfg.beam_size = 8;           // Many hypotheses
```

Result: 5-10 tok/sec (but highest quality)

### Balanced
```cpp
cfg.temperature = 0.7f;
cfg.top_p = 0.9f;
cfg.max_tokens = 256;
```

Result: 30-40 tok/sec with good quality

---

## Next Steps

1. **Run example**: `Build → Run → Generate text`
2. **Load real model**: Get 7B GGUF from HuggingFace
3. **Try agentic**: Analyze and refactor real code
4. **Benchmark**: Compare to Cursor/Copilot
5. **Integrate**: Embed in your IDE/app
6. **Optimize**: Profile and tune for your hardware
7. **Deploy**: Use hot-patches for live updates

---

## Getting Help

### Documentation
- `PRODUCTION_IMPLEMENTATION_GUIDE.md` - Detailed architecture
- `COMPONENT_ARCHITECTURE.md` - Component integration
- `IMPLEMENTATION_COMPLETION_SUMMARY.md` - What's implemented

### Common Tasks
- **Load a model**: See "5-Minute Setup"
- **Generate text**: See "Quick Code Example"
- **Analyze code**: Use `ExecuteAgenticTask("analyze ...")`
- **Update inference**: Use `ApplyHotpatch(...)`
- **Profile**: Use VTune or perf

### Debugging
- Check logs: All components use Logger
- Profile hotspots: VTune or Linux perf
- Memory leaks: AddressSanitizer
- Validation: Run test suite (see BUILD_COMPLETE.md)

---

## Success Criteria ✅

Model loads successfully:
```
✅ GGUF Model opened in streaming mode
✅ Model loaded: 32 layers, 32 heads, 128000 vocab
```

Generation works:
```
✅ Completion finished: 256 tokens in 7500ms
✅ Throughput: 34 tokens/sec
```

Agentic tasks work:
```
✅ Code Analysis: 1024 lines, CC=12, MI=75%
✅ Improvements: Consider loop unrolling
```

---

**You're ready to go! Start coding! 🚀**

For issues or questions, check the comprehensive guides above.

---

**RawrXD v7.0.0** - The Production-Grade AI IDE
