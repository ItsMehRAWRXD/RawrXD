# RawrXD Agentic System - Quick Reference

## 🚀 Quick Start Commands

### Run Everything
```powershell
cd d:\rawrxd
powershell -ExecutionPolicy Bypass -File agentic_test_suite.ps1
```

### Individual Tests
```powershell
# Complete system test
.\unified_agentic_test.exe

# Ollama connectivity
.\test_ollama_simple.exe

# Chat streaming
.\test_chat_streaming.exe

# Generate streaming
.\test_deepseek_streaming.exe
```

### Performance Tools
```powershell
# Benchmark streaming performance
.\benchmark_streaming.exe deepseek-r1:8b "Explain AI" 50

# Interactive model manager
.\model_manager.exe
```

## 📊 Test Results Interpretation

### Unified Agentic Test
```
[Test 1] Native Toolchain Verification    → [PASS] All 7 components present
[Test 2] Ollama Connectivity              → [PASS] Ollama responding, model available
[Test 3] Model Streaming                  → [PASS] Received X chunks
[Test 4] Capability Probe                  → [PASS] All capabilities verified
```

### Benchmark Output
```
Throughput:
  Tokens/sec:    45.23      ← Target: ≥50 (GOOD)
  KB/sec:        12.5

Latency (ms):
  Min:           15.2
  Max:           89.4
  Avg:           22.1       ← Target: <30ms (GOOD)
  P95:           45.8

Performance Rating: GOOD (50-99 tps)
```

## 🔧 Configuration

### Edit Config
File: `d:\rawrxd\config\agentic_config.json`

Key settings:
- `ollama.default_model` - Default model to use
- `streaming.token_timeout_ms` - Token timeout
- `performance.target_tokens_per_second` - Performance target

### Available Models

| Model | Size | Context | Best For |
|-------|------|---------|----------|
| deepseek-r1:8b | 5.2 GB | 131K | General purpose, reasoning |
| gemma3:27b | 17.4 GB | 8K | Code generation |
| nemotron-3-super | 86.8 GB | 262K | Complex tasks, tools |

## 🐛 Troubleshooting

### Ollama Not Responding
```powershell
# Check if running
Get-Process ollama

# Restart
ollama serve
```

### Model Not Found
```powershell
# Pull model
ollama pull deepseek-r1:8b

# List available
ollama list
```

### Build Fails
```powershell
# Check GCC
gcc --version

# Rebuild toolchain
cd d:\rawrxd\compilers\native_toolchain
.\build_toolchain.bat
```

## 📈 Performance Targets

| Metric | Excellent | Good | Acceptable | Needs Work |
|--------|-----------|------|------------|------------|
| Tokens/sec | ≥100 | 50-99 | 20-49 | <20 |
| Latency (ms) | <15 | 15-30 | 30-50 | >50 |
| TTFT (ms) | <100 | 100-300 | 300-500 | >500 |

## 🎯 VS Code Tasks

Press `Ctrl+Shift+P` → `Tasks: Run Task`:

1. 🧪 Run Unified Agentic Test
2. 🔧 Build Native Toolchain
3. 🤖 Test Ollama Connection
4. 📡 Stream with DeepSeek-R1:8b
5. 🏗️ Build Model Streamer (ASM)
6. 📋 List Available Models
7. 🚀 Full Agentic Suite

## 📁 Key Files

| File | Purpose |
|------|---------|
| `unified_agentic_test.exe` | Complete system test |
| `agentic_test_suite.ps1` | PowerShell test suite |
| `benchmark_streaming.exe` | Performance benchmark |
| `model_manager.exe` | Interactive model manager |
| `config/agentic_config.json` | System configuration |

## 🔗 API Endpoints

- `GET /api/tags` - List models
- `POST /api/generate` - Generate text
- `POST /api/chat` - Chat completion

## 💡 Tips

1. **First run**: Always run `unified_agentic_test.exe` first
2. **Performance**: Use `benchmark_streaming.exe` to measure actual performance
3. **Models**: Use `model_manager.exe` to explore available models
4. **Config**: Edit `config/agentic_config.json` to customize behavior

## 📞 Support

- Check `AGENTIC_SYSTEM_README.md` for full documentation
- Run tests with `-Verbose` flag for detailed output
- Check Ollama logs if models fail to load

---

**Version**: 1.0.0  
**Updated**: 2026-07-08
