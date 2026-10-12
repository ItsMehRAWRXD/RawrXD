# MASM x64 Vulkan and Dependencies - Implementation Guide

## Overview

This directory contains a complete MASM x64 (Microsoft Macro Assembler for 64-bit) implementation of Vulkan compute APIs and related dependencies. The goal is to replace external library dependencies with pure assembly implementations for maximum control and performance.

## Architecture

### Component Structure

```
masm64/
├── vulkan/           # Vulkan compute implementation
│   ├── core/         # Instance, device, command buffers
│   ├── memory/       # Buffer and memory management
│   ├── sync/         # Fences and synchronization
│   └── compute/      # Tensor operations, matrix ops, activations
├── cuda/             # CUDA Runtime API stubs
├── rocm/             # ROCm/HIP Runtime API stubs
├── compression/      # Zlib and Zstd implementations
├── crypto/           # OpenSSL primitives (SHA256, AES, etc.)
├── include/          # Header files with structures and constants
├── lib/              # Output libraries
├── tests/            # Unit and integration tests
└── examples/         # Usage examples
```

### Key Features

1. **Vulkan Core**
   - Instance and device management
   - Command buffer recording and execution
   - Memory allocation and binding
   - Fence-based synchronization using Windows events

2. **Compute Operations**
   - Tensor memory management
   - Matrix multiplication (scalar and AVX2-optimized paths)
   - Activation functions (ReLU, GELU, Softmax, Sigmoid, Tanh)
   - Vector operations (add, scale, dot product, transpose)

3. **Dependencies**
   - **Zlib**: DEFLATE compression/decompression, CRC32, Adler32
   - **Zstd**: Zstandard compression with frame handling
   - **OpenSSL**: SHA256, AES encryption, HMAC, random number generation
   - **CUDA**: Device management, memory operations (simulated on CPU)
   - **ROCm/HIP**: AMD GPU interface (simulated on CPU)

## Building

### Prerequisites

- Windows 10/11 (x64)
- Visual Studio 2019 or later with C++ tools
- MASM64 (ml64.exe) - included with Visual Studio

### Build Steps

#### Option 1: Using the build script (Recommended)

```batch
cd masm64
build.bat
```

#### Option 2: Using nmake

```batch
cd masm64
nmake /f Makefile
```

#### Option 3: Manual compilation

```batch
cd masm64

REM Create directories
mkdir obj lib bin

REM Compile Vulkan core
ml64 /c /Cp /Cx /Zi /I"include" /Fo"obj\" vulkan\core\vk_instance.asm
ml64 /c /Cp /Cx /Zi /I"include" /Fo"obj\" vulkan\core\vk_command.asm
ml64 /c /Cp /Cx /Zi /I"include" /Fo"obj\" vulkan\memory\vk_memory.asm
ml64 /c /Cp /Cx /Zi /I"include" /Fo"obj\" vulkan\sync\vk_sync.asm

REM Compile compute operations
ml64 /c /Cp /Cx /Zi /I"include" /Fo"obj\" vulkan\compute\tensor_ops.asm
ml64 /c /Cp /Cx /Zi /I"include" /Fo"obj\" vulkan\compute\matrix_ops.asm
ml64 /c /Cp /Cx /Zi /I"include" /Fo"obj\" vulkan\compute\activation_funcs.asm

REM Compile dependencies
ml64 /c /Cp /Cx /Zi /I"include" /Fo"obj\" compression\zlib.asm
ml64 /c /Cp /Cx /Zi /I"include" /Fo"obj\" compression\zstd.asm
ml64 /c /Cp /Cx /Zi /I"include" /Fo"obj\" crypto\openssl.asm
ml64 /c /Cp /Cx /Zi /I"include" /Fo"obj\" cuda\cuda_runtime.asm
ml64 /c /Cp /Cx /Zi /I"include" /Fo"obj\" rocm\hip_runtime.asm

REM Create libraries
lib /OUT:"lib\vulkan_masm.lib" obj\vk_*.obj obj\tensor_ops.obj obj\matrix_ops.obj obj\activation_funcs.obj
lib /OUT:"lib\compression_masm.lib" obj\zlib.obj obj\zstd.obj
lib /OUT:"lib\crypto_masm.lib" obj\openssl.obj
lib /OUT:"lib\gpu_masm.lib" obj\cuda_runtime.obj obj\hip_runtime.obj
```

### Output

After building, you'll have:
- `lib/vulkan_masm.lib` - Vulkan compute library
- `lib/compression_masm.lib` - Compression algorithms
- `lib/crypto_masm.lib` - Cryptographic primitives
- `lib/gpu_masm.lib` - CUDA and ROCm interfaces

## Usage

### Linking with C/C++ Projects

```cpp
// Example C++ usage
extern "C" {
    // Vulkan functions
    int vkCreateInstanceMASM(void* pCreateInfo, void* pAllocator, void** pInstance);
    int vkCreateDeviceMASM(void* physicalDevice, void* pCreateInfo, void* pAllocator, void** pDevice);
    
    // Compute functions
    int MatMulF32(float* A, float* B, float* C, int M, int K, int N);
    int ReLU(float* input, float* output, int count);
    int GELU(float* input, float* output, int count);
    
    // Compression
    int deflate(void* src, size_t srcSize, void* dst, size_t* dstSize);
    int inflate(void* src, size_t srcSize, void* dst, size_t* dstSize);
}

// Link with: vulkan_masm.lib compression_masm.lib crypto_masm.lib gpu_masm.lib kernel32.lib
```

### Example: Matrix Multiplication

```cpp
#include <iostream>

extern "C" int MatMulF32(float* A, float* B, float* C, int M, int K, int N);

int main() {
    // 2x3 * 3x2 = 2x2
    float A[6] = {1, 2, 3, 4, 5, 6};        // 2x3
    float B[6] = {7, 8, 9, 10, 11, 12};     // 3x2
    float C[4] = {0};                        // 2x2
    
    int result = MatMulF32(A, B, C, 2, 3, 2);
    
    if (result == 0) {
        std::cout << "Result:\n";
        std::cout << C[0] << " " << C[1] << "\n";
        std::cout << C[2] << " " << C[3] << "\n";
    }
    
    return 0;
}
```

### Example: Vulkan Instance Creation

```cpp
extern "C" {
    int vkCreateInstanceMASM(void* pCreateInfo, void* pAllocator, void** pInstance);
    int vkEnumeratePhysicalDevicesMASM(void* instance, int* pCount, void** pDevices);
}

int main() {
    void* instance = nullptr;
    int result = vkCreateInstanceMASM(nullptr, nullptr, &instance);
    
    if (result == 0) {
        std::cout << "Vulkan instance created: " << instance << "\n";
        
        int deviceCount = 0;
        vkEnumeratePhysicalDevicesMASM(instance, &deviceCount, nullptr);
        std::cout << "Device count: " << deviceCount << "\n";
    }
    
    return 0;
}
```

## API Reference

### Vulkan Core API

| Function | Description | Return |
|----------|-------------|--------|
| `vkCreateInstanceMASM` | Create Vulkan instance | VkResult (0=success) |
| `vkEnumeratePhysicalDevicesMASM` | Get physical devices | VkResult |
| `vkCreateDeviceMASM` | Create logical device | VkResult |
| `vkGetDeviceQueueMASM` | Get device queue | void |
| `vkCreateCommandPoolMASM` | Create command pool | VkResult |
| `vkAllocateCommandBuffersMASM` | Allocate command buffers | VkResult |

### Memory Management API

| Function | Description | Return |
|----------|-------------|--------|
| `vkCreateBufferMASM` | Create buffer | VkResult |
| `vkAllocateMemoryMASM` | Allocate device memory | VkResult |
| `vkBindBufferMemoryMASM` | Bind memory to buffer | VkResult |
| `vkMapMemoryMASM` | Map memory to host | VkResult |
| `vkUnmapMemoryMASM` | Unmap memory | void |

### Synchronization API

| Function | Description | Return |
|----------|-------------|--------|
| `vkCreateFenceMASM` | Create fence | VkResult |
| `vkWaitForFencesMASM` | Wait for fences | VkResult |
| `vkResetFencesMASM` | Reset fences | VkResult |
| `vkGetFenceStatusMASM` | Check fence status | VkResult |

### Tensor Operations API

| Function | Description | Return |
|----------|-------------|--------|
| `TensorCreate` | Create tensor descriptor | 0=success, -1=error |
| `TensorAllocate` | Allocate tensor memory | Pointer or NULL |
| `TensorCopy` | Copy tensor data | 0=success, -1=error |
| `TensorZero` | Zero tensor data | 0=success, -1=error |
| `TensorFree` | Free tensor | void |

### Matrix Operations API

| Function | Parameters | Description |
|----------|-----------|-------------|
| `MatMulF32` | A, B, C, M, K, N | C = A * B (MxK * KxN) |
| `MatMulF32_AVX2` | A, B, C, M, K, N | AVX2-optimized matmul |
| `VectorAdd` | A, B, C, count | C = A + B |
| `VectorScale` | A, B, count, scale | B = A * scale |
| `VectorDot` | A, B, count | Returns dot product |
| `TransposeF32` | A, B, M, N | Transpose MxN matrix |

### Activation Functions API

| Function | Parameters | Description |
|----------|-----------|-------------|
| `ReLU` | input, output, count | max(0, x) |
| `ReLU6` | input, output, count | min(max(0, x), 6) |
| `GELU` | input, output, count | Gaussian Error Linear Unit |
| `Softmax` | input, output, count | Normalized exponentials |
| `Sigmoid` | input, output, count | 1/(1+exp(-x)) |
| `TanhApprox` | input, output, count | Fast tanh approximation |

## Performance Considerations

### Optimizations Implemented

1. **Register Usage**: Maximizes use of x64 registers to minimize memory access
2. **SIMD Instructions**: SSE/AVX for floating point operations
3. **Cache Locality**: Data structures designed for cache-friendly access patterns
4. **Branch Prediction**: Minimizes conditional branches in hot paths

### Known Limitations

1. **CPU Simulation**: CUDA and ROCm APIs run on CPU, not actual GPU
2. **No GPU Kernels**: Compute operations execute on CPU
3. **Simplified Algorithms**: Some algorithms use approximations for performance
4. **Windows Only**: Uses Windows-specific APIs (VirtualProtect, HeapAlloc, etc.)

### Future Optimizations

- [ ] AVX-512 support for matrix operations
- [ ] Multi-threading support for parallel tensor operations
- [ ] True GPU execution via Vulkan compute shaders
- [ ] NUMA-aware memory allocation
- [ ] Assembly-level loop unrolling and prefetching

## Testing

### Unit Tests

Located in `tests/unit/`:
- `test_vulkan_core.cpp` - Tests instance and device creation
- `test_memory.cpp` - Tests buffer and memory operations
- `test_tensors.cpp` - Tests tensor operations
- `test_matrix.cpp` - Tests matrix operations
- `test_activations.cpp` - Tests activation functions

### Integration Tests

Located in `tests/integration/`:
- `test_full_pipeline.cpp` - End-to-end Vulkan pipeline test
- `test_compute_workload.cpp` - Complete compute workload

### Running Tests

```batch
cd tests
build_tests.bat
bin\test_all.exe
```

## Troubleshooting

### Common Issues

**Issue**: `ml64.exe` not found
- **Solution**: Run from Visual Studio x64 Native Tools Command Prompt or execute `vcvarsall.bat x64`

**Issue**: Link errors with Windows APIs
- **Solution**: Ensure `kernel32.lib` is linked

**Issue**: Access violation on fence operations
- **Solution**: Verify Windows event handle creation succeeded

**Issue**: Incorrect matrix multiplication results
- **Solution**: Check matrix dimensions and memory layout (row-major assumed)

## Contributing

This implementation is part of the RawrXD cloud hosting project. Contributions should focus on:

1. Performance improvements (AVX-512, multi-threading)
2. Additional activation functions
3. More comprehensive testing
4. Linux support (replacing Windows APIs)
5. Documentation improvements

## License

MIT License - See repository root for full license text

## References

- Vulkan Specification: https://www.khronos.org/vulkan/
- MASM Reference: https://docs.microsoft.com/en-us/cpp/assembler/masm/
- Intel Intrinsics Guide: https://www.intel.com/content/www/us/en/docs/intrinsics-guide/
- x64 ABI: https://docs.microsoft.com/en-us/cpp/build/x64-calling-convention
