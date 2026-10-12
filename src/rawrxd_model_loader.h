#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#ifdef RAWR_ENABLE_VULKAN
#include <vulkan/vulkan.h>
#else
// Standard Win32/CPU build - Vulkan handles not needed
#ifndef VK_NULL_HANDLE
#define VK_NULL_HANDLE 0
#endif
typedef void* VkBuffer;
typedef void* VkDeviceMemory;
typedef void* VkDevice;
typedef void* VkPhysicalDevice;
typedef struct { uint32_t memoryTypeCount; } VkPhysicalDeviceMemoryProperties;
typedef uint32_t VkMemoryPropertyFlags;
#endif
#include <windows.h>

struct Tensor {
    std::string name;
    std::vector<uint64_t> dims;
    uint32_t type;
    uint64_t offset;
    void* data; // Mapped pointer (Raw)
    
    // Vulkan
    VkBuffer gpuBuffer = VK_NULL_HANDLE;
    VkDeviceMemory gpuMemory = VK_NULL_HANDLE;
    bool onGPU = false;
    
    // CPU Float cache for reference implementation
    std::vector<float> cpuFloatData;
};

// struct GGUFHeader removed - use definition in RawrXD_Interfaces.h via gguf_loader.h if needed
// Or rely on the fact that RawrXD_Interfaces.h is the source of truth.

// GGUF Q4_0 block structure
struct Q4_0_Block {
    uint16_t d; // float16 scale
    uint8_t qs[16]; // 32 nibbles
};

class RawrXDModelLoader {
public:
    bool Load(const wchar_t* path, VkDevice device, VkPhysicalDevice physDevice);
    float* GetTensor(const std::string& name);

    // Fetch ONE row (of `dim` floats) from a named tensor into `out`.
    //
    // The tensor's row length is its first GGUF dimension (dims[0]); `dim` is the
    // caller's expectation and is validated against it, so a mismatch is a hard
    // error rather than a silently truncated copy. `row` is the row index.
    //
    // Used by the embedding lookup, where copying the whole embedding table to
    // pull one row would be both slow and pointless.
    bool GetTensorRow(const std::string& name, size_t row, float* out, size_t dim);

    // Const access to a tensor's metadata (dims/type), or nullptr if absent.
    // Lets callers validate a weight's shape before feeding it to a kernel
    // instead of trusting the name and hoping.
    const Tensor* FindTensor(const std::string& name) const;
    
private:
    VkDevice device;
    VkPhysicalDeviceMemoryProperties memProps;
    HANDLE hFile, hMapping;
    void* mappedView;
    uint64_t fileSize;
    
    // Metadata
    int n_embd = 4096;
    int n_layers = 32;
    int n_heads = 32;
    int n_heads_kv = 32;
    int n_ctx = 4096;
    int vocab_size = 32000;

public:
    int getDim() const { return n_embd; }
    int getLayers() const { return n_layers; }
    int getHeads() const { return n_heads; }
    int getKVHeads() const { return n_heads_kv; }
    int getCtx() const { return n_ctx; }
    int getVocabSize() const { return vocab_size; }
    
    std::unordered_map<std::string, Tensor> tensors;
    
    // Helpers
    uint8_t* ParseMetadata(uint8_t* ptr, uint64_t count);
    uint8_t* ParseTensorInfo(uint8_t* ptr, Tensor& t);
    void LoadTensorAsync(Tensor& t);
    void DequantAndUploadQ4_0(Tensor& t, void* blocks, size_t N);
    void UploadF32(Tensor& t, void* data, size_t N);
    void CreateGPUBuffer(Tensor& t, void* data, size_t size);
    void UploadViaStaging(void* data, size_t size, VkBuffer dstBuffer);
    uint32_t FindMemoryType(uint32_t typeFilter, VkMemoryPropertyFlags properties);
    int64_t CalculateVRAMUsage();
};
