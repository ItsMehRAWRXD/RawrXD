# Integration Guide - MASM x64 Vulkan Implementation

## Quick Start

This guide explains how to integrate the MASM x64 Vulkan and dependencies implementation into your existing projects.

## Prerequisites

### Development Environment
- Windows 10/11 (x64)
- Visual Studio 2019 or later
- MASM64 (ml64.exe) - included with VS C++ tools
- Windows SDK

### Knowledge Requirements
- C/C++ programming
- Basic understanding of Vulkan concepts
- Familiarity with linking libraries

## Installation

### Step 1: Build the Libraries

```batch
cd masm64
build.bat
```

This creates four libraries in the `lib/` directory:
- `vulkan_masm.lib` - Vulkan compute + tensor operations
- `compression_masm.lib` - Zlib + Zstd compression
- `crypto_masm.lib` - OpenSSL cryptographic primitives
- `gpu_masm.lib` - CUDA + ROCm interfaces

### Step 2: Copy Libraries to Your Project

```batch
# Option 1: Copy to your project's lib directory
copy masm64\lib\*.lib your_project\lib\

# Option 2: Add to Visual Studio library path
# Project Properties → Linker → General → Additional Library Directories
# Add: $(SolutionDir)\..\masm64\lib
```

### Step 3: Include Header (Optional)

Create a C/C++ header file with function declarations:

```cpp
// masm_vulkan.h
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Vulkan Core API
int vkCreateInstanceMASM(void* pCreateInfo, void* pAllocator, void** pInstance);
int vkEnumeratePhysicalDevicesMASM(void* instance, int* pCount, void** pDevices);
int vkCreateDeviceMASM(void* physicalDevice, void* pCreateInfo, 
                       void* pAllocator, void** pDevice);
void vkGetDeviceQueueMASM(void* device, int queueFamilyIndex, 
                         int queueIndex, void** pQueue);
int vkCreateCommandPoolMASM(void* device, void* pCreateInfo, 
                            void* pAllocator, void** pCommandPool);

// Memory Management
int vkCreateBufferMASM(void* device, void* pCreateInfo, 
                       void* pAllocator, void** pBuffer);
int vkAllocateMemoryMASM(void* device, void* pAllocateInfo, 
                         void* pAllocator, void** pMemory);
int vkBindBufferMemoryMASM(void* device, void* buffer, 
                           void* memory, size_t offset);
int vkMapMemoryMASM(void* device, void* memory, size_t offset, 
                    size_t size, int flags, void** ppData);
void vkUnmapMemoryMASM(void* device, void* memory);

// Synchronization
int vkCreateFenceMASM(void* device, void* pCreateInfo, 
                      void* pAllocator, void** pFence);
int vkWaitForFencesMASM(void* device, int fenceCount, void** pFences, 
                        int waitAll, unsigned long long timeout);
int vkResetFencesMASM(void* device, int fenceCount, void** pFences);
int vkGetFenceStatusMASM(void* device, void* fence);

// Compute Operations - Matrix
int MatMulF32(float* A, float* B, float* C, int M, int K, int N);
int MatMulF32_AVX2(float* A, float* B, float* C, int M, int K, int N);
int VectorAdd(float* A, float* B, float* C, int count);
int VectorScale(float* A, float* B, int count, float scale);
float VectorDot(float* A, float* B, int count);  // Returns in XMM0
int TransposeF32(float* A, float* B, int M, int N);

// Compute Operations - Activations
int ReLU(float* input, float* output, int count);
int ReLU6(float* input, float* output, int count);
int TanhApprox(float* input, float* output, int count);
int GELU(float* input, float* output, int count);
int Softmax(float* input, float* output, int count);
int Sigmoid(float* input, float* output, int count);

// CUDA Runtime API
int cudaGetDeviceCount(int* count);
int cudaSetDevice(int device);
int cudaGetDevice(int* device);
int cudaMalloc(void** devPtr, size_t size);
int cudaFree(void* devPtr);
int cudaMemcpy(void* dst, const void* src, size_t count, int kind);
int cudaMemset(void* devPtr, int value, size_t count);
int cudaDeviceSynchronize(void);

// ROCm/HIP Runtime API
int hipGetDeviceCount(int* count);
int hipSetDevice(int device);
int hipGetDevice(int* device);
int hipMalloc(void** devPtr, size_t size);
int hipFree(void* devPtr);
int hipMemcpy(void* dst, const void* src, size_t count, int kind);
int hipMemset(void* devPtr, int value, size_t count);
int hipDeviceSynchronize(void);

// Compression
int deflate(void* src, size_t srcSize, void* dst, size_t* dstSize);
int inflate(void* src, size_t srcSize, void* dst, size_t* dstSize);
unsigned int crc32(unsigned int crc, const void* buf, size_t len);
unsigned int adler32(unsigned int adler, const void* buf, size_t len);

int ZSTD_compress(void* dst, size_t dstCapacity, const void* src, size_t srcSize);
int ZSTD_decompress(void* dst, size_t dstCapacity, const void* src, size_t srcSize);
size_t ZSTD_compressBound(size_t srcSize);

// Cryptography
int SHA256_Init(void* ctx);
int SHA256_Update(void* ctx, const void* data, size_t len);
int SHA256_Final(unsigned char* hash, void* ctx);
int AES_set_encrypt_key(const unsigned char* userKey, int bits, void* key);
void AES_encrypt(const unsigned char* in, unsigned char* out, const void* key);
int RAND_bytes(unsigned char* buf, int num);

#ifdef __cplusplus
}
#endif
```

## Usage Examples

### Example 1: Simple Matrix Multiplication

```cpp
#include "masm_vulkan.h"
#include <iostream>

int main() {
    // 2×3 matrix
    float A[6] = {1, 2, 3, 4, 5, 6};
    
    // 3×2 matrix
    float B[6] = {7, 8, 9, 10, 11, 12};
    
    // Result: 2×2 matrix
    float C[4];
    
    // Perform: C = A * B
    int result = MatMulF32(A, B, C, 2, 3, 2);
    
    if (result == 0) {
        std::cout << "Result:\n";
        std::cout << C[0] << " " << C[1] << "\n";
        std::cout << C[2] << " " << C[3] << "\n";
    }
    
    return 0;
}

// Compile:
// cl /EHsc example1.cpp /link vulkan_masm.lib kernel32.lib
```

### Example 2: Neural Network Layer

```cpp
#include "masm_vulkan.h"
#include <vector>
#include <iostream>

class DenseLayer {
    std::vector<float> weights;
    std::vector<float> bias;
    int in_size, out_size;
    
public:
    DenseLayer(int in, int out) : in_size(in), out_size(out) {
        weights.resize(in * out);
        bias.resize(out);
        // Initialize weights...
    }
    
    void forward(const float* input, float* output) {
        // Linear: output = weights * input + bias
        MatMulF32(const_cast<float*>(input), weights.data(), 
                  output, 1, in_size, out_size);
        VectorAdd(output, bias.data(), output, out_size);
        
        // Activation: ReLU
        ReLU(output, output, out_size);
    }
};
```

### Example 3: CUDA-Compatible Code

```cpp
#include "masm_vulkan.h"
#include <iostream>

int main() {
    int deviceCount;
    cudaGetDeviceCount(&deviceCount);
    std::cout << "CUDA devices: " << deviceCount << "\n";
    
    // Allocate device memory
    float* d_data;
    size_t size = 1024 * sizeof(float);
    cudaMalloc((void**)&d_data, size);
    
    // Initialize to zero
    cudaMemset(d_data, 0, size);
    
    // Copy data
    float h_data[1024];
    // ... fill h_data ...
    cudaMemcpy(d_data, h_data, size, 1);  // 1 = cudaMemcpyHostToDevice
    
    // Synchronize
    cudaDeviceSynchronize();
    
    // Copy back
    cudaMemcpy(h_data, d_data, size, 2);  // 2 = cudaMemcpyDeviceToHost
    
    // Free
    cudaFree(d_data);
    
    return 0;
}
```

### Example 4: Compression

```cpp
#include "masm_vulkan.h"
#include <vector>
#include <iostream>

int main() {
    std::vector<char> input_data(1024);
    // Fill with data...
    
    std::vector<char> compressed(2048);
    size_t compressed_size = compressed.size();
    
    // Compress
    deflate(input_data.data(), input_data.size(), 
            compressed.data(), &compressed_size);
    
    std::cout << "Compressed: " << input_data.size() 
              << " → " << compressed_size << " bytes\n";
    
    // Calculate checksum
    unsigned int crc = crc32(0, input_data.data(), input_data.size());
    std::cout << "CRC32: 0x" << std::hex << crc << "\n";
    
    return 0;
}
```

## Visual Studio Integration

### Method 1: Property Sheets

1. Create `masm_vulkan.props`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <PropertyGroup Label="UserMacros">
    <MASMVulkanPath>$(SolutionDir)\..\masm64</MASMVulkanPath>
  </PropertyGroup>
  <ItemDefinitionGroup>
    <Link>
      <AdditionalLibraryDirectories>$(MASMVulkanPath)\lib;%(AdditionalLibraryDirectories)</AdditionalLibraryDirectories>
      <AdditionalDependencies>vulkan_masm.lib;compression_masm.lib;crypto_masm.lib;gpu_masm.lib;kernel32.lib;%(AdditionalDependencies)</AdditionalDependencies>
    </Link>
  </ItemDefinitionGroup>
</Project>
```

2. Add to project: View → Property Manager → Add Existing Property Sheet

### Method 2: Project Settings

1. Right-click project → Properties
2. Configuration: All Configurations
3. Linker → General → Additional Library Directories:
   ```
   $(SolutionDir)\..\masm64\lib
   ```
4. Linker → Input → Additional Dependencies:
   ```
   vulkan_masm.lib;compression_masm.lib;crypto_masm.lib;gpu_masm.lib;kernel32.lib
   ```

## CMake Integration

```cmake
# CMakeLists.txt
cmake_minimum_required(VERSION 3.15)
project(MyProject)

# Set MASM Vulkan path
set(MASM_VULKAN_DIR "${CMAKE_SOURCE_DIR}/../masm64")

# Add library directories
link_directories("${MASM_VULKAN_DIR}/lib")

# Create executable
add_executable(myapp main.cpp)

# Link libraries
target_link_libraries(myapp
    vulkan_masm
    compression_masm
    crypto_masm
    gpu_masm
    kernel32
)

# Windows-specific settings
if(WIN32)
    set_target_properties(myapp PROPERTIES
        WIN32_EXECUTABLE TRUE
    )
endif()
```

## Troubleshooting

### Issue: Unresolved external symbols

**Symptom:**
```
error LNK2019: unresolved external symbol MatMulF32
```

**Solution:**
- Ensure `vulkan_masm.lib` is in Additional Dependencies
- Check library path is correct
- Verify libraries are built (run build.bat)

### Issue: Access violation at runtime

**Symptom:**
```
Exception thrown at 0x... Access violation reading location 0x...
```

**Solution:**
- Check pointer parameters are not NULL
- Verify array sizes match function expectations
- Ensure output buffers are allocated

### Issue: Incorrect results from matrix operations

**Symptom:**
Matrix multiplication produces wrong values

**Solution:**
- Verify matrices are in row-major order
- Check dimensions: C(MxN) = A(MxK) * B(KxN)
- Ensure K dimension matches between A and B

## Performance Optimization

### Enable Optimizations

```cpp
// Compile with optimizations
// cl /O2 /EHsc /fp:fast myapp.cpp /link vulkan_masm.lib kernel32.lib
```

### Use AVX2 (When Available)

```cpp
// Check CPU capabilities first
if (supports_avx2()) {
    MatMulF32_AVX2(A, B, C, M, K, N);
} else {
    MatMulF32(A, B, C, M, K, N);
}
```

### Memory Alignment

```cpp
// Align data to 32-byte boundaries for AVX
alignas(32) float A[1024];
alignas(32) float B[1024];
alignas(32) float C[1024];
```

## Best Practices

1. **Error Checking**
   ```cpp
   int result = MatMulF32(A, B, C, M, K, N);
   if (result != 0) {
       // Handle error
   }
   ```

2. **Resource Management**
   ```cpp
   void* buffer;
   cudaMalloc(&buffer, size);
   // ... use buffer ...
   cudaFree(buffer);  // Always free
   ```

3. **Initialization**
   ```cpp
   void* instance;
   vkCreateInstanceMASM(nullptr, nullptr, &instance);
   // ... use instance ...
   vkDestroyInstanceMASM(instance, nullptr);
   ```

4. **Batch Operations**
   ```cpp
   // Process multiple operations together
   for (int i = 0; i < batch_size; ++i) {
       ReLU(inputs[i], outputs[i], size);
   }
   ```

## Migration from Standard Libraries

### From Vulkan SDK

```cpp
// Before (Vulkan SDK)
VkInstance instance;
vkCreateInstance(&createInfo, nullptr, &instance);

// After (MASM Vulkan)
void* instance;
vkCreateInstanceMASM(nullptr, nullptr, &instance);
```

### From CUDA

```cpp
// Before (NVIDIA CUDA)
cudaMalloc(&ptr, size);

// After (MASM CUDA stub)
cudaMalloc(&ptr, size);  // Same API, different implementation
```

### From OpenSSL

```cpp
// Before (OpenSSL)
SHA256_Init(&ctx);
SHA256_Update(&ctx, data, len);
SHA256_Final(hash, &ctx);

// After (MASM OpenSSL)
SHA256_Init(&ctx);       // Same API
SHA256_Update(&ctx, data, len);
SHA256_Final(hash, &ctx);
```

## Support and Contributions

- **Documentation**: See `masm64/README.md`
- **Examples**: See `masm64/examples/` and `masm64/tests/`
- **Issues**: Report in GitHub repository
- **Contributions**: Follow project coding standards

## License

MIT License - See repository root for full license text
