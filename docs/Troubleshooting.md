# RawrXD Troubleshooting Guide

Common issues and their solutions.

## Table of Contents

- [Installation Issues](#installation-issues)
- [Build Issues](#build-issues)
- [Runtime Issues](#runtime-issues)
- [Performance Issues](#performance-issues)
- [Model Issues](#model-issues)
- [GPU Issues](#gpu-issues)
- [Getting Help](#getting-help)

## Installation Issues

### "Command not found: rawrxd"

**Cause**: Binary not in PATH

**Solutions**:

```bash
# Linux/macOS
export PATH="/usr/local/bin:$PATH"

# Or add to ~/.bashrc or ~/.zshrc
echo 'export PATH="/usr/local/bin:$PATH"' >> ~/.bashrc

# Windows (PowerShell)
$env:PATH = "C:\Program Files\RawrXD\bin;$env:PATH"

# Windows (permanent)
[Environment]::SetEnvironmentVariable("PATH", "C:\Program Files\RawrXD\bin;$env:PATH", "User")
```

### "Permission denied" on Linux

**Cause**: Missing execute permissions

**Solution**:
```bash
chmod +x /usr/local/bin/rawrxd
```

## Build Issues

### "CMake Error: Could not find a package configuration file"

**Cause**: Missing dependencies or submodules

**Solutions**:

```bash
# Update git submodules
git submodule update --init --recursive

# Or disable optional components
cmake -B build -DRAWRXD_ENABLE_CUDA=OFF -DRAWRXD_ENABLE_VULKAN=OFF
```

### "fatal error: 'cuda_runtime.h' file not found"

**Cause**: CUDA not properly installed or not in PATH

**Solutions**:

```bash
# Linux
export PATH="/usr/local/cuda/bin:$PATH"
export CPATH="/usr/local/cuda/include:$CPATH"
export LIBRARY_PATH="/usr/local/cuda/lib64:$LIBRARY_PATH"

# Or disable CUDA
cmake -B build -DRAWRXD_ENABLE_CUDA=OFF
```

### "LINK : fatal error LNK1181: cannot open input file"

**Cause**: Missing libraries on Windows

**Solutions**:
- Use Visual Studio Developer Command Prompt
- Install required Windows SDK
- Check that all dependencies are installed

### "undefined reference to `pthread_create'"

**Cause**: Missing pthread library on Linux

**Solution**:
```bash
sudo apt-get install libpthread-stubs0-dev
# Or
sudo yum install glibc-devel
```

### "error: no member named 'filesystem' in namespace 'std'"

**Cause**: Compiler doesn't support C++17 fully

**Solution**:
```bash
# Check compiler version
gcc --version  # Need 9.0+
clang --version  # Need 10.0+

# Update CMake to use correct standard
cmake -B build -DCMAKE_CXX_STANDARD=17
```

## Runtime Issues

### "Failed to initialize runtime"

**Causes & Solutions**:

1. **Missing system libraries**
   ```bash
   # Linux
   ldd $(which rawrxd)  # Check for missing libraries
   
   # Install missing ones
   sudo apt-get install libstdc++6
   ```

2. **Corrupted configuration**
   ```bash
   # Reset to defaults
   rm -rf ~/.config/rawrxd
   rawrxd config reset
   ```

3. **Insufficient permissions**
   ```bash
   # Check permissions on config directory
   ls -la ~/.config/
   
   # Fix if needed
   mkdir -p ~/.config/rawrxd
   chmod 755 ~/.config/rawrxd
   ```

### "Segmentation fault" or "Access violation"

**Diagnosis**:

```bash
# Enable core dumps (Linux)
ulimit -c unlimited

# Run with debugger
gdb rawrxd
gdb> run <arguments>
gdb> bt  # Get backtrace when it crashes
```

**Common Causes**:

1. **Incompatible model format**
   - Ensure model is GGUF format
   - Check model architecture matches

2. **Insufficient memory**
   - Reduce context size: `--context-size 2048`
   - Use quantization: `--quantize q4_k_m`

3. **Corrupted model file**
   - Re-download the model
   - Verify checksum if available

### "Out of memory" errors

**Solutions**:

```bash
# Reduce memory usage
rawrxd chat --model llama2-7b-q4km \
  --context-size 2048 \        # Smaller context
  --batch-size 256 \           # Smaller batches
  --gpu-layers 20              # Fewer GPU layers

# Enable memory mapping
rawrxd chat --model llama2-7b-q4km --mmap

# Use more aggressive quantization
rawrxd chat --model llama2-7b-q4km --quantize q4_0
```

### "Model failed to load"

**Checklist**:

1. **File exists and is readable**
   ```bash
   ls -la /path/to/model.gguf
   file /path/to/model.gguf  # Should show "data"
   ```

2. **Correct format**
   ```bash
   # Check magic bytes
   xxd /path/to/model.gguf | head -1
   # Should start with "GGUF"
   ```

3. **Architecture compatibility**
   ```bash
   rawrxd model info /path/to/model.gguf
   # Check architecture field
   ```

4. **Sufficient disk space**
   ```bash
   df -h /path/to/model
   ```

## Performance Issues

### "Slow inference speed"

**Diagnosis**:

```bash
# Check which backend is active
rawrxd status

# Run benchmark
rawrxd benchmark --model llama2-7b-q4km
```

**Solutions**:

1. **Enable GPU**
   ```bash
   rawrxd config set inference.backend cuda
   rawrxd config set inference.gpu_layers 35
   ```

2. **Optimize thread count**
   ```bash
   # Set to number of physical cores
   rawrxd config set inference.threads $(nproc)
   ```

3. **Use faster quantization**
   ```bash
   # Q4_0 is faster than Q4_K_M
   rawrxd chat --model llama2-7b-q4_0
   ```

4. **Check thermal throttling**
   ```bash
   # Linux
   sensors
   
   # Monitor during inference
   watch -n 1 sensors
   ```

### "High latency"

**Causes**:

1. **First token latency (TTFT)**
   - Normal for large models
   - Use flash attention if available
   - Reduce context size

2. **Inter-token latency**
   - Check GPU utilization
   - May be CPU-bound on small models
   - Enable continuous batching

**Solutions**:

```bash
# Enable flash attention
rawrxd config set inference.flash_attention true

# Reduce context for lower TTFT
rawrxd chat --context-size 1024

# Enable streaming for better perceived latency
rawrxd chat --stream
```

## Model Issues

### "Tokenizer mismatch"

**Symptoms**: Garbled output, wrong tokens

**Solutions**:

```bash
# Use model's built-in tokenizer
rawrxd chat --model llama2-7b-q4km --tokenizer auto

# Or specify explicitly
rawrxd chat --model llama2-7b-q4km --tokenizer llama
```

### "Wrong output format"

**Symptoms**: Model not following instructions

**Solutions**:

```bash
# Use chat format
rawrxd chat --model llama2-7b-q4km --format chatml

# Or specify system prompt
rawrxd chat --model llama2-7b-q4km \
  --system "You are a helpful assistant."
```

### "Model produces nonsense"

**Causes**:

1. **Corrupted download**
   - Re-download with verification
   
2. **Wrong quantization settings**
   - Some models need specific quant types
   
3. **Temperature too high**
   ```bash
   rawrxd chat --temperature 0.7  # Lower for more coherent output
   ```

## GPU Issues

### "CUDA out of memory"

**Solutions**:

```bash
# Reduce GPU layers
rawrxd chat --gpu-layers 20  # Instead of 35

# Enable memory mapping
rawrxd chat --mmap

# Use smaller batch size
rawrxd chat --batch-size 128

# Clear GPU memory
nvidia-smi  # Check usage
# Restart rawrxd if needed
```

### "CUDA driver version is insufficient"

**Solution**:
```bash
# Update NVIDIA drivers
# Linux
sudo apt-get install nvidia-driver-535  # Or latest

# Check compatibility
nvidia-smi  # Check driver version
nvcc --version  # Check CUDA version
```

### "Vulkan not found"

**Solutions**:

```bash
# Linux
sudo apt-get install vulkan-tools vulkan-validationlayers

# Check installation
vulkaninfo

# Or disable Vulkan fallback
cmake -B build -DRAWRXD_ENABLE_VULKAN=OFF
```

### "GPU not being used"

**Diagnosis**:

```bash
# Check backend
rawrxd config get inference.backend

# Check GPU detection
rawrxd status --verbose

# Monitor GPU usage
nvidia-smi dmon  # NVIDIA
intel_gpu_top    # Intel
```

**Solutions**:

```bash
# Force GPU backend
rawrxd config set inference.backend cuda

# Check GPU layers
rawrxd config set inference.gpu_layers 35

# Verify model fits in VRAM
rawrxd model info /path/to/model.gguf
```

## Getting Help

### Collecting Diagnostic Information

```bash
# System info
rawrxd --version
rawrxd status --verbose

# Build info (if built from source)
cat build/CMakeCache.txt | grep RAWRXD

# System resources
# Linux
free -h
nvidia-smi  # If NVIDIA GPU
lscpu

# macOS
system_profiler SPHardwareDataType
vm_stat

# Windows
systeminfo
```

### Reporting Issues

When reporting issues, include:

1. **RawrXD version**: `rawrxd --version`
2. **OS and version**: `uname -a` (Linux/macOS), `winver` (Windows)
3. **Hardware**: CPU, GPU, RAM
4. **Command used**: Exact command that failed
5. **Error message**: Full error output
6. **Logs**: Run with `--verbose` or check `~/.local/share/rawrxd/logs/`

### Debug Mode

```bash
# Enable debug logging
rawrxd --log-level debug chat --model llama2-7b-q4km

# Enable verbose output
rawrxd --verbose chat --model llama2-7b-q4km

# Save log to file
rawrxd --log-file rawrxd.log chat --model llama2-7b-q4km
```

### Community Resources

- [GitHub Issues](https://github.com/ItsMehRAWRXD/RawrXD/issues)
- [GitHub Discussions](https://github.com/ItsMehRAWRXD/RawrXD/discussions)
- [FAQ](FAQ.md) - Frequently asked questions
- [Build Guide](Build.md) - Build troubleshooting

## Quick Fixes

| Issue | Quick Fix |
|-------|-----------|
| Won't start | `rm -rf ~/.config/rawrxd` |
| Out of memory | Add `--context-size 1024` |
| Too slow | Add `--gpu-layers 35` |
| Wrong output | Check `--format` and `--tokenizer` |
| Build fails | `git submodule update --init --recursive` |
| CUDA errors | Update drivers or disable with `-DRAWRXD_ENABLE_CUDA=OFF` |
