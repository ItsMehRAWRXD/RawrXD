# RawrXD Quick Start Guide

**Get up and running in 5 minutes**

---

## Prerequisites

- Python 3.8+
- NumPy
- GGUF model file (e.g., TinyLlama-1.1b)

---

## Installation

```bash
# Clone repository
git clone <repository-url>
cd rawrxd

# Install dependencies
pip install numpy

# Optional: For GPU support
pip install cupy-cuda11x  # Adjust for your CUDA version
```

---

## Quick Test

```bash
# Run production readiness check
cd tests
python gate15_production_ready.py

# Run all validation gates
python run_all_gates.py
```

---

## Basic Usage

### Load a Model

```python
from real_gguf_tensor_parser import GGUFParser

# Parse GGUF file
parser = GGUFParser("path/to/model.gguf")
metadata = parser.parse_header()
print(f"Model: {metadata['general.name']}")
print(f"Tensors: {metadata['tensor_count']}")
```

### Extract Tensors

```python
# Get embedding weights
token_embd = parser.get_tensor("token_embd.weight")
print(f"Shape: {token_embd.shape}")
print(f"Type: {token_embd.dtype}")
```

### Run Inference

```python
# See gate11_full_integration.py for complete example
# Basic flow:
# 1. Load model
# 2. Tokenize input
# 3. Forward pass through transformer
# 4. Sample next token
# 5. Repeat
```

---

## Validation Gates

| Gate | Test | Command |
|------|------|---------|
| 1 | GGUF Parsing | `python gate1_gguf_validation.py` |
| 2 | Quantization | `python gate2_quantization_validation.py` |
| 3 | Embeddings | `python gate3_embedding_lookup.py` |
| 4 | Inference | `python gate4_gpu_inference.py` |
| 5 | Transformer | `python gate5_transformer_layer.py` |
| 6 | Multi-Layer | `python gate6_multi_layer_fast.py` |
| 7 | Token Gen | `python gate7_token_gen_simple.py` |
| 8 | KV Cache | `python gate8_kv_cache.py` |
| 9 | Generation | `python gate9_autoregressive_gen.py` |
| 10 | Sampling | `python gate10_sampling.py` |
| 11 | Integration | `python gate11_full_integration.py` |
| 12 | Streaming | `python gate12_streaming_load.py` |
| 13 | Memory Map | `python gate13_memory_mapped.py` |
| 14 | Progress | `python gate14_progress_callbacks.py` |
| 15 | Production | `python gate15_production_ready.py` |
| 16 | Multi-Model | `python gate16_multi_model.py` |
| 17 | Errors | `python gate17_error_recovery.py` |
| 18 | Benchmarks | `python gate18_performance_bench.py` |
| 19 | Integration | `python gate19_integration_tests.py` |
| 20 | Docs | `python gate20_documentation.py` |

---

## Performance Tips

### CPU Optimization
- Use memory-mapped loading for large models
- Enable streaming for models > 1GB
- Use KV cache for generation

### Memory Management
- Monitor KV cache size: ~704MB for 22 layers
- Use chunked loading to reduce parse overhead
- Unload unused models

---

## Troubleshooting

### Import Errors
```bash
# Ensure you're in the tests directory
cd tests
python gate1_gguf_validation.py
```

### Model Not Found
```python
# Update model path in test files
model_path = r"D:\rawrxd\.archive\Full Source\build\llama_cli\models\model.gguf"
```

### Memory Issues
- Reduce batch size
- Use streaming loading
- Clear KV cache between generations

---

## Next Steps

1. **Validate Installation**: Run `python gate15_production_ready.py`
2. **Explore Code**: Start with `gate11_full_integration.py`
3. **Customize**: Modify for your use case
4. **Optimize**: Add GPU support with CuPy

---

## Documentation

- `PRODUCTION_RELEASE.md` - Release notes
- `VALIDATION_SUMMARY.md` - Detailed validation
- `VALIDATION_STATE.md` - System state
- `tests/` - All test files with examples

---

## Support

For issues or questions:
1. Check validation gates for examples
2. Review error messages in test output
3. Consult `VALIDATION_SUMMARY.md`

---

**Ready to go!** Start with `python gate15_production_ready.py` to verify everything works.

---

## Native Components (Optional)

### 1. Load a Model
```cmd
cd d:\rawrxd\compilers\native_toolchain
unified_model_streamer.exe load ..\..\bench_min.gguf
```

### 2. Test Streaming (requires Ollama running)
```cmd
unified_model_streamer.exe stream deepseek-r1:8b
```

### 3. Launch IDE
```cmd
cd d:\rawrxd\build_win32ide\bin
RawrXD-Win32IDE.exe
```

### 4. Run Model Manager
```cmd
cd d:\rawrxd\compilers\native_toolchain
model_manager.exe
```

## Build Everything
```cmd
cd d:\rawrxd
FINAL_BUILD_MASTER.bat
```

## System Components

| Component | Location | Purpose |
|-----------|----------|---------|
| Model Loader | `compilers\native_toolchain\unified_model_streamer.exe` | GGUF loading + streaming |
| IDE | `build_win32ide\bin\RawrXD-Win32IDE.exe` | Native Win32 IDE |
| Kernels | `src\asm\SwarmV29_*.obj` | PQC acceleration |
| Config | `config\agentic_config.json` | System settings |

## Status: ✅ OPERATIONAL
