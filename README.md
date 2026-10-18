# Deep2Engine - Universal GGUF Inference Engine

A high-performance, universal GGUF model inference engine with support for multiple model architectures (Llama, Qwen, Gemma, Phi-3, Nemotron, Granite, etc.), AVX-512 optimized kernels, lock-free thread pooling, and multi-GPU Vulkan support.

## Features

- **Universal Architecture Support**: Dynamic prefix-based metadata parsing for Llama, Qwen2, Gemma2, Phi-3, Nemotron, Granite, StarCoder2, GLM
- **AVX-512 Optimized Kernels**: High-speed Q2_K dequantization and RoPE processing using 512-bit vector registers
- **Lock-Free Thread Pool**: Asynchronous work-stealing thread pool for parallel matrix operations
- **Multi-GPU Vulkan Support**: Asymmetric memory allocation across dual GPU configurations (tested with 32GB + 16GB AMD cards)
- **RoPE Scaling**: Dynamic context window scaling up to 128k tokens with inverse-frequency adjustment
- **Ollama Integration**: Automated manifest parsing and model symlink mapping
- **Performance Telemetry**: TPS regression tracking and thread timing profiling

## Project Structure

```
Deep2Engine/
├── src/
│   ├── main.cpp              # Entry point
│   ├── Deep2Engine.hpp       # Main engine interface
│   ├── Deep2Engine.cpp       # Core engine implementation
│   ├── GGUFLoader.hpp        # GGUF metadata parsing interface
│   └── GGUFLoader.cpp        # Universal metadata loader
├── scripts/
│   ├── Map-OllamaModels.ps1      # Ollama-to-GGUF symlink mapper
│   ├── Test-ModelInventory.ps1   # Bulk model validation suite
│   ├── Track-TPSRegressions.py   # TPS regression tracking
│   └── Measure-ThreadCompletion.py # Thread timing profiler
├── build.bat                  # Windows batch build script
├── build.ps1                  # PowerShell build script
└── CMakeLists.txt             # Cross-platform CMake configuration
```

## Building

### Windows (Visual Studio)
```cmd
build.bat
```

### Windows (PowerShell)
```powershell
.\build.ps1
```

### Manual CMake
```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release
```

## Usage

### Basic Inference
```bash
./build/bin/Deep2Engine_Benchmark.exe "path/to/model.gguf"
```

### With Ollama Manifest
```bash
./build/bin/Deep2Engine_Benchmark.exe "path/to/model.gguf" "path/to/manifest.json"
```

### Verify Initialization Only
```bash
./build/bin/Deep2Engine_Benchmark.exe --verify-init-only "path/to/model.gguf"
```

## Scripts

### Map Ollama Models
```powershell
.\scripts\Map-OllamaModels.ps1
```
Maps Ollama blob storage to named `.gguf` symlinks in `G:\~dev\rawrxd\models\`

### Bulk Model Validation
```powershell
.\scripts\Test-ModelInventory.ps1
```
Tests all models in the mapped directory and generates `build/inventory_audit_report.log`

### TPS Regression Tracking
```bash
python scripts\Track-TPSRegressions.py
```
Runs inference on all models and logs throughput to `build/tps_regression_history.csv`

### Thread Timing Profiler
```bash
python scripts\Measure-ThreadCompletion.py
```
Measures thread completion latencies and outputs to `build/thread_latencies_report.csv`

## Architecture Support

The engine automatically detects and parses metadata keys for:

| Architecture | Prefix | Example Keys |
|--------------|--------|--------------|
| Llama | `llama` | `llama.embedding_length`, `llama.block_count` |
| Qwen2 | `qwen2` | `qwen2.embedding_length`, `qwen2.block_count` |
| Gemma2 | `gemma2` | `gemma2.embedding_length`, `gemma2.block_count` |
| Phi-3 | `phi3` | `phi3.embedding_length`, `phi3.block_count` |
| Nemotron | `nemotron` | `nemotron.embedding_length`, `nemotron.block_count` |
| Granite | `granite` | `granite.embedding_length`, `granite.block_count` |
| StarCoder2 | `starcoder2` | `starcoder2.embedding_length`, `starcoder2.block_count` |
| GLM | `glm` | `glm.embedding_length`, `glm.block_count` |

Fallback keys: `general.architecture.embedding_length`, `general.architecture.block_count`, etc.

## AVX-512 Requirements

- CPU with AVX-512F, AVX-512BW, AVX-512DQ, AVX-512VNNI support
- Compiler: MSVC 19.10+ (VS 2017+) or GCC/Clang with `-mavx512f` support

The CMake configuration automatically detects and enables AVX-512 when available.

## Multi-GPU Configuration

For asymmetric dual-GPU setups (e.g., 32GB R9700 + 16GB 7800 XT):

```cpp
Deep2Engine engine;
engine.InitializeMultiGPU();
size_t splitRow = engine.CalculateRowSplitIndex(totalRows);
// splitRow ≈ 66% for primary GPU
```

## License

MIT License