# RawrXD Advanced - Troubleshooting Guide
## Diagnosing and Resolving Issues

**Version:** 1.0.0  
**Date:** 2026-07-15  
**Status:** ✅ Complete

---

## Table of Contents

1. [Overview](#overview)
2. [Installation Issues](#installation-issues)
3. [Build Issues](#build-issues)
4. [Runtime Issues](#runtime-issues)
5. [Performance Issues](#performance-issues)
6. [Model Loading Issues](#model-loading-issues)
7. [GPU Issues](#gpu-issues)
8. [Network Issues](#network-issues)
9. [Debugging Techniques](#debugging-techniques)

---

## Overview

This guide provides systematic troubleshooting procedures for common RawrXD issues.

### Diagnostic Tools

| Tool | Purpose |
|------|---------|
| `rawrxd --diagnose` | System diagnostics |
| `rawrxd --verify` | Installation verification |
| `rawrxd --benchmark` | Performance testing |
| `rawrxd --log-level=debug` | Detailed logging |

---

## Installation Issues

### Issue: Installation Fails

**Symptoms:**
- Setup wizard exits with error
- Files not extracted properly
- Registry entries missing

**Diagnosis:**
```bash
# Check system requirements
rawrxd --check-requirements

# Verify disk space
dir /w d:\

# Check permissions
icacls d:\rawrxd
```

**Solutions:**

1. **Insufficient Disk Space**
   ```bash
   # Free up space
   cleanmgr /sageset:1
   cleanmgr /sagerun:1
   ```

2. **Permission Denied**
   ```bash
   # Run as administrator
   # Right-click installer → Run as Administrator
   ```

3. **Antivirus Interference**
   ```bash
   # Add exclusion
   # Windows Security → Virus & threat protection → Exclusions
   # Add: d:\rawrxd\
   ```

### Issue: PATH Not Updated

**Symptoms:**
- `rawrxd` command not found
- Must use full path to executable

**Solution:**
```bash
# Add to PATH manually
setx PATH "%PATH%;d:\rawrxd\bin"

# Or use PowerShell
[Environment]::SetEnvironmentVariable(
    "PATH",
    $env:PATH + ";d:\rawrxd\bin",
    "User"
)
```

---

## Build Issues

### Issue: Compilation Fails

**Symptoms:**
- `ml64.exe` errors
- Link errors
- Missing symbols

**Diagnosis:**
```bash
# Check compiler version
ml64.exe /?

# Verify paths
echo %INCLUDE%
echo %LIB%

# Check for missing files
dir d:\src\asm\*.asm
dir d:\src\main\*.cpp
```

**Common Errors:**

| Error | Cause | Solution |
|-------|-------|----------|
| `A2006: undefined symbol` | Missing include | Check include paths |
| `LNK2019: unresolved external` | Missing library | Add to link command |
| `C1083: cannot open file` | Wrong path | Verify file locations |
| `fatal error LNK1104` | File in use | Close running instances |

**Solutions:**

1. **Missing Includes**
   ```bash
   # Add include path
   set INCLUDE=%INCLUDE%;d:\rawrxd\include
   ```

2. **Library Not Found**
   ```bash
   # Add library path
   set LIB=%LIB%;d:\rawrxd\lib
   ```

3. **Clean Build**
   ```bash
   # Remove object files
   del /s *.obj
   
   # Rebuild
   build_pipeline.bat
   ```

### Issue: Linker Errors

**Symptoms:**
- `LNK2001: unresolved external symbol`
- `LNK2019: unresolved external symbol`

**Diagnosis:**
```bash
# List exports from library
dumpbin /exports RawrXD_ToolExecutor_Complete.obj

# Check symbol names
dumpbin /symbols RawrXD_Main.obj | findstr "External"
```

**Solutions:**

1. **Missing Exports**
   ```asm
   ; Ensure symbols are public
   PUBLIC MyFunction
   
   MyFunction PROC
       ; ...
   MyFunction ENDP
   ```

2. **Name Mangling**
   ```cpp
   // Use extern "C" for C++
   extern "C" void MyFunction();
   ```

---

## Runtime Issues

### Issue: Crash on Startup

**Symptoms:**
- Application exits immediately
- Windows error dialog
- Event log entry

**Diagnosis:**
```bash
# Check Event Viewer
eventvwr.msc
# Windows Logs → Application

# Run with debugger
windbg -g d:\rawrxd\RawrXD_Main.exe

# Enable crash dumps
drconfig -i RawrXD_Main.exe -e
```

**Common Causes:**

1. **Missing Dependencies**
   ```bash
   # Check dependencies
dumpbin /dependents RawrXD_Main.exe
   
   # Use Dependency Walker
dependencywalker RawrXD_Main.exe
   ```

2. **Corrupted Configuration**
   ```bash
   # Reset config
   del %APPDATA%\RawrXD\config.json
   
   # Or use safe mode
   rawrxd --safe-mode
   ```

3. **Memory Issues**
   ```bash
   # Check available memory
   wmic OS get TotalVisibleMemorySize,FreePhysicalMemory
   
   # Run memory diagnostic
   mdsched.exe
   ```

### Issue: Access Violation

**Symptoms:**
- `0xC0000005: Access violation`
- Crash at specific address

**Diagnosis:**
```bash
# Get crash address from Event Viewer
# Look for "Faulting module" and "Exception code"

# Analyze dump file
windbg -z RawrXD_Main.dmp
!analyze -v
```

**Solutions:**

1. **Null Pointer**
   ```cpp
   // Add null checks
   if (!ptr) {
       LogError("Null pointer");
       return false;
   }
   ```

2. **Buffer Overflow**
   ```cpp
   // Use safe functions
   strncpy(dest, src, sizeof(dest) - 1);
   dest[sizeof(dest) - 1] = '\0';
   ```

3. **Stack Corruption**
   ```asm
   ; Check stack alignment
   sub rsp, 8          ; Align to 16 bytes
   
   ; Use canaries
   push [gs:0x28]      ; Stack canary
   ```

---

## Performance Issues

### Issue: Slow Inference

**Symptoms:**
- Low tokens/second
- High latency
- CPU/GPU underutilized

**Diagnosis:**
```bash
# Benchmark performance
rawrxd --benchmark --model model.gguf

# Monitor resources
rawrxd --perf-monitor

# Profile execution
rawrxd --profile --output profile.json
```

**Solutions:**

1. **Check GPU Utilization**
   ```bash
   # Monitor GPU
   nvidia-smi dmon
   
   # Check if GPU is being used
   rawrxd --list-devices
   ```

2. **Optimize Batch Size**
   ```cpp
   // Increase batch size for throughput
   config.batch_size = 512;  // Was: 256
   ```

3. **Enable Optimizations**
   ```bash
   # Build with optimizations
   ml64.exe /c /O2 /arch:AVX512 ...
   ```

### Issue: Memory Leaks

**Symptoms:**
- Memory usage grows over time
- System becomes sluggish
- Out of memory errors

**Diagnosis:**
```bash
# Monitor memory
rawrxd --memory-tracker

# Use Application Verifier
appverif /enable Heaps RawrXD_Main.exe

# Check for leaks
umdh -pn:RawrXD_Main.exe -f:mem1.log
# ... run application ...
umdh -pn:RawrXD_Main.exe -f:mem2.log
umdh mem1.log mem2.log
```

**Solutions:**

1. **Proper Cleanup**
   ```cpp
   // Ensure all allocations are freed
   class Resource {
       ~Resource() {
           if (data) {
               free(data);
               data = nullptr;
           }
       }
   };
   ```

2. **Use Memory Pools**
   ```cpp
   // Pre-allocate memory
   MemoryPool pool(1024 * 1024 * 1024);  // 1GB pool
   void* ptr = pool.Allocate(size);
   pool.Free(ptr);
   ```

---

## Model Loading Issues

### Issue: Model Won't Load

**Symptoms:**
- "Failed to load model" error
- Invalid format message
- Out of memory

**Diagnosis:**
```bash
# Verify model file
rawrxd --verify-model model.gguf

# Check file integrity
fciv model.gguf -sha256

# Inspect model structure
rawrxd --inspect-model model.gguf
```

**Solutions:**

1. **Corrupted File**
   ```bash
   # Re-download model
   rawrxd --download-model <url>
   
   # Verify checksum
   certutil -hashfile model.gguf SHA256
   ```

2. **Unsupported Format**
   ```bash
   # Convert model
   rawrxd --convert-model input.bin --output model.gguf
   ```

3. **Insufficient Memory**
   ```bash
   # Use quantized model
   rawrxd --quantize-model model.gguf --type Q4_0
   
   # Or enable memory mapping
   rawrxd --mmap-model model.gguf
   ```

### Issue: Wrong Model Output

**Symptoms:**
- Nonsensical responses
- Wrong token IDs
- Garbled text

**Diagnosis:**
```bash
# Test tokenizer
rawrxd --test-tokenizer model.gguf

# Check vocabulary
rawrxd --dump-vocab model.gguf
```

**Solutions:**

1. **Tokenizer Mismatch**
   ```cpp
   // Ensure tokenizer matches model
   if (tokenizer.vocab_size != model.vocab_size) {
       LogError("Tokenizer mismatch");
   }
   ```

2. **Wrong Weights**
   ```bash
   # Verify weight checksums
   rawrxd --verify-weights model.gguf
   ```

---

## GPU Issues

### Issue: GPU Not Detected

**Symptoms:**
- "No GPU found" message
- Falls back to CPU

**Diagnosis:**
```bash
# List GPUs
nvidia-smi

# Check Vulkan
vulkaninfo

# Verify drivers
rawrxd --gpu-diagnostics
```

**Solutions:**

1. **Update Drivers**
   ```bash
   # Download from NVIDIA
   # https://www.nvidia.com/drivers
   ```

2. **Enable GPU in Config**
   ```json
   {
       "gpu": {
           "enabled": true,
           "device_id": 0
       }
   }
   ```

3. **Check Permissions**
   ```bash
   # Add user to video group
   # (Linux only)
   usermod -a -G video username
   ```

### Issue: GPU Out of Memory

**Symptoms:**
- `CUDA out of memory`
- `VK_ERROR_OUT_OF_DEVICE_MEMORY`

**Solutions:**

1. **Reduce Batch Size**
   ```cpp
   config.batch_size = 128;  // Reduce from 512
   ```

2. **Use Memory Efficient Attention**
   ```cpp
   config.use_flash_attention = true;
   config.use_xformers = true;
   ```

3. **Offload to CPU**
   ```cpp
   config.offload_layers = 20;  // Keep 20 layers on GPU
   ```

---

## Network Issues

### Issue: Distributed Connection Failed

**Symptoms:**
- "Cannot connect to node"
- Timeout errors
- Cluster formation fails

**Diagnosis:**
```bash
# Test connectivity
ping node1

# Check ports
netstat -an | findstr 9999

# Test RDMA
ib_write_bw  # On server
ib_write_bw node0  # On client
```

**Solutions:**

1. **Firewall Configuration**
   ```bash
   # Open ports
   netsh advfirewall firewall add rule name="RawrXD" \
       dir=in action=allow protocol=tcp localport=9999
   ```

2. **Network Configuration**
   ```yaml
   # cluster_config.yaml
   network:
       bind_address: 0.0.0.0
       port: 9999
       transport: tcp  # Use TCP if RDMA unavailable
   ```

---

## Debugging Techniques

### Logging

```cpp
// Enable debug logging
SetLogLevel(LOG_LEVEL_DEBUG);

// Add trace points
LOG_DEBUG("Entering function: %s", __FUNCTION__);
LOG_DEBUG("Variable value: %d", value);

// Conditional logging
if (verbose) {
    LOG_TRACE("Detailed state: %s", state.ToString());
}
```

### Assertions

```cpp
// Debug assertions
ASSERT(ptr != nullptr, "Pointer is null");
ASSERT(size > 0, "Invalid size: %zu", size);
ASSERT(index < count, "Index out of bounds: %zu >= %zu", index, count);

// Soft assertions (log but continue)
SOFT_ASSERT(result == expected, "Unexpected result: %d", result);
```

### Memory Debugging

```cpp
// Detect memory corruption
void* ptr = DebugAlloc(size, __FILE__, __LINE__);
DebugFree(ptr, __FILE__, __LINE__);

// Check for leaks
DebugDumpAllocations();

// Guard pages
void* guarded = GuardedAlloc(size);
// Access beyond bounds will trigger exception
```

### Performance Profiling

```cpp
// Scoped profiling
{
    PROFILE_SCOPE("Inference");
    RunInference();
}

// Manual profiling
PROFILE_BEGIN("LoadModel");
LoadModel(path);
PROFILE_END("LoadModel");

// Dump results
ProfileDumpResults("profile.json");
```

---

## Summary

Troubleshooting coverage:

- ✅ Installation issues
- ✅ Build issues
- ✅ Runtime crashes
- ✅ Performance problems
- ✅ Model loading
- ✅ GPU issues
- ✅ Network issues
- ✅ Debugging techniques

**Status:** ✅ Complete

---

*End of Troubleshooting Guide*
