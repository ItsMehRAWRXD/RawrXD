# RawrXD Frequently Asked Questions

## General

### What is RawrXD?

RawrXD is a high-performance AI inference runtime designed for production workloads. It provides:
- Optimized inference for LLMs (Large Language Models)
- Multi-backend support (CPU, CUDA, Vulkan, DirectML)
- Agentic framework for autonomous AI workflows
- Production-ready observability and telemetry

### How is RawrXD different from other inference engines?

| Feature | RawrXD | Others |
|---------|--------|--------|
| Multi-backend | Native | Often single-backend |
| Agentic framework | Built-in | External tools |
| Production focus | First-class | Often research-focused |
| C++ API | Stable, documented | Varies |
| Memory efficiency | Optimized | Standard |

### What models are supported?

RawrXD supports GGUF format models, including:
- Llama/Llama 2/Llama 3 family
- Mistral/Mixtral
- Qwen
- Gemma
- Phi
- And any other GGUF-compatible model

## Installation & Setup

### Which version should I use?

- **Latest stable**: `v1.0.0-rc1` - Recommended for production
- **Nightly**: `main` branch - Latest features, less stable
- **LTS**: `v1.0.x` - Long-term support (coming soon)

### Do I need a GPU?

No, but it's recommended for larger models:
- **CPU only**: Works for models up to ~7B parameters
- **GPU recommended**: For 13B+ parameters or high throughput
- **Multi-GPU**: Supported for distributed inference

### How do I update RawrXD?

```bash
# Using package manager
# Ubuntu/Debian
sudo apt update && sudo apt upgrade rawrxd

# macOS
brew upgrade rawrxd

# Windows (Chocolatey)
choco upgrade rawrxd

# From source
git pull origin main
cmake --build build --target install
```

## Usage

### How do I load a custom model?

```bash
# Add model to registry
rawrxd model add /path/to/model.gguf --name my-model

# Use it
rawrxd chat --model my-model
```

### Can I use RawrXD as a server?

Yes, RawrXD includes an HTTP server compatible with OpenAI API:

```bash
# Start server
rawrxd serve --port 8080 --model llama2-7b-q4km

# Use with curl
curl http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "llama2-7b-q4km",
    "messages": [{"role": "user", "content": "Hello!"}]
  }'
```

### How do I optimize for my hardware?

```bash
# Auto-detect optimal settings
rawrxd benchmark --auto-tune

# Or manually configure
rawrxd config set inference.threads $(nproc)
rawrxd config set inference.gpu_layers 35
rawrxd config set quantization.q4_k_m true
```

## Performance

### What throughput can I expect?

Performance varies by hardware and model:

| Hardware | Model | Tokens/sec |
|----------|-------|------------|
| RTX 4090 | Llama 2 7B Q4 | ~120 |
| RTX 3090 | Llama 2 7B Q4 | ~100 |
| Apple M2 Max | Llama 2 7B Q4 | ~45 |
| AMD EPYC 64c | Llama 2 7B Q4 | ~25 |

Run `rawrxd benchmark` for your specific setup.

### How do I reduce memory usage?

1. **Use quantization**: Q4_K_M reduces memory by ~75%
2. **Reduce context size**: `--context-size 2048` instead of 4096
3. **Offload fewer layers**: `--gpu-layers 20` instead of 35
4. **Use memory mapping**: `--mmap` for large models

### Why is my GPU not being used?

Check:
1. CUDA/Vulkan drivers installed
2. `rawrxd config get inference.backend` returns `cuda` or `vulkan`
3. Model fits in GPU memory
4. `--gpu-layers` is set correctly

## Troubleshooting

### "Model failed to load"

Common causes:
- Corrupted GGUF file (re-download)
- Insufficient RAM/VRAM
- Wrong architecture (check model compatibility)
- Missing dependencies (install CUDA/Vulkan)

### "Out of memory" errors

Solutions:
- Reduce batch size: `--batch-size 256`
- Use quantization: `--quantize q4_k_m`
- Enable memory mapping: `--mmap`
- Reduce context size: `--context-size 2048`

### Slow inference

Check:
- CPU vs GPU: `rawrxd status` shows active backend
- Thread count: Should match physical cores
- Memory bandwidth: Check `rawrxd benchmark --memory`
- Thermal throttling: Monitor temperatures

### Build errors

See [Build Guide](Build.md) for detailed instructions. Common fixes:
- Update submodules: `git submodule update --init --recursive`
- Clear CMake cache: `rm -rf build && cmake -B build`
- Install dependencies: See [Build.md](Build.md#dependencies)

## Development

### How do I contribute?

See [CONTRIBUTING.md](../CONTRIBUTING.md) for:
- Development workflow
- Coding standards
- Testing requirements
- PR process

### Where is the API documentation?

- **C++ API**: `include/rawrxd/` directory
- **Python API**: `python/rawrxd/` directory
- **Examples**: `examples/` directory

### How do I report a bug?

1. Check [existing issues](https://github.com/ItsMehRAWRXD/RawrXD/issues)
2. Use the [bug report template](https://github.com/ItsMehRAWRXD/RawrXD/issues/new?template=bug_report.md)
3. Include:
   - RawrXD version
   - OS and hardware
   - Steps to reproduce
   - Expected vs actual behavior

### How do I request a feature?

Use the [feature request template](https://github.com/ItsMehRAWRXD/RawrXD/issues/new?template=feature_request.md) and describe:
- Use case
- Proposed solution
- Alternatives considered

## Licensing

### What license is RawrXD under?

RawrXD is licensed under the MIT License. See [LICENSE](../LICENSE) for details.

### Can I use RawrXD commercially?

Yes, the MIT License permits commercial use.

### Do I need to contribute back changes?

No, but contributions are welcome! See [CONTRIBUTING.md](../CONTRIBUTING.md).

## Still Have Questions?

- [GitHub Discussions](https://github.com/ItsMehRAWRXD/RawrXD/discussions) - Community Q&A
- [Troubleshooting Guide](Troubleshooting.md) - Detailed debugging
- [Architecture Overview](Architecture.md) - Technical deep dive
