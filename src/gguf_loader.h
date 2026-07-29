<<<<<<< HEAD
#pragma once
#include "RawrXD_Interfaces.h"
#include <cstdint>
#include <fstream>
#include <map>
#include <mutex>
#include <string>
#include <unordered_map>
#include <variant>
#include <vector>


// We need windows.h for Handles in the Loader
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

// Phase 46: Vulkan support with graceful fallback for dual GPU testing
// Include vulkan_compute.h from include directory for consistent Vulkan type definitions
#include "../include/vulkan_compute.h"

// Basic types for GGUF (defined in RawrXD_Interfaces.h)
using RawrXD::GGMLType;
using RawrXD::GGUFHeader;
using RawrXD::GGUFMetadata;
using RawrXD::TensorInfo;


/*
class GGUFLoaderVulkan {
public:
    GGUFLoaderVulkan();
    ~GGUFLoaderVulkan();

    bool Open(const std::string& filepath);
    void Close();

    // Original API
    bool ParseHeader();

    // New API from user request (adapted)
    bool Load(VkDevice vkDevice, VkPhysicalDevice vkPhysDevice);

    // Helpers
    uint64_t GetMetadata(const std::string& key);
    TensorInfo& GetTensor(const std::string& name);

private:
    std::ifstream file_;
    std::string filepath_;
    bool is_open_;

    GGUFHeader header_val; // Renamed to avoid collision with struct type

    // Handles for Memory Mapping
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE hMapping = nullptr;
    void* mappedView = nullptr;
    size_t fileSize = 0;

    // Vulkan Context
    VkDevice device;
    VkPhysicalDevice physDevice;
    VkQueue transferQueue;
    VkCommandPool cmdPool;
    VkCommandBuffer cmdBuffer;

    std::mutex tensorMutex;
    std::unordered_map<std::string, TensorInfo> tensors;

    // Internal loading methods
    void CreateVulkanResources();
    void LoadTensorAsync(TensorInfo& info);
    void UploadF32(TensorInfo& info, void* src, size_t count);
    void DequantAndUploadQ4_0(TensorInfo& info, void* src, size_t count);
    // ... Add others as needed, simplified for this integration

    void BeginCommandBuffer();
    void EndCommandBuffer();
    uint32_t FindMemoryType(uint32_t typeFilter, uint32_t props);
    uint32_t FindQueueFamilyIndex(VkPhysicalDevice device, uint32_t queueFlags);
};
*/

// Interface for GGUF Loaders
// Deprecated in favor of RawrXD::IGGUFLoader, keeping for local compatibility if needed
// but directing everything to the RawrXD namespace versions.
typedef RawrXD::IGGUFLoader IGGUFLoader;

class GGUFLoader : public RawrXD::IGGUFLoader
{
  public:
    GGUFLoader();
    virtual ~GGUFLoader();

    static uint64_t AlignTo32Bytes(uint64_t offset) { return (offset + 31ULL) & ~31ULL; }

    bool Open(const std::string& filepath) override;
    bool Close() override;

    bool ParseHeader() override;
    RawrXD::GGUFHeader GetHeader() const override { return header_; }

    bool ParseMetadata() override;
    RawrXD::GGUFMetadata GetMetadata() const override { return metadata_; }

    // Lane E: lightweight integrity checks and trivial repair path.
    bool VerifyIntegrity(std::string* reason = nullptr);
    bool RepairTrivialIssues(std::string* report = nullptr);

    std::vector<RawrXD::TensorInfo> GetTensorInfo() const override { return tensors_; }
    bool LoadTensorRange(size_t start_idx, size_t count, std::vector<uint8_t>& data) override;

    // Implementation of new methods to avoid abstract class issues
    size_t GetTensorByteSize(const RawrXD::TensorInfo& tensor) const override { return tensor.size; }
    std::string GetTypeString(RawrXD::GGMLType type) const override { return "f32"; }
    bool BuildTensorIndex() override { return true; }
    bool LoadZone(const std::string& zone_name, uint64_t max_memory_mb = 512) override { return true; }
    bool UnloadZone(const std::string& zone_name) override { return true; }
    bool LoadTensorZone(const std::string& tensor_name, std::vector<uint8_t>& data) override;
    uint64_t GetFileSize() const override;
    uint64_t GetCurrentMemoryUsage() const override { return 0; }
    std::vector<std::string> GetLoadedZones() const override { return {}; }
    std::vector<std::string> GetAllZones() const override { return {}; }
    std::vector<RawrXD::TensorInfo> GetAllTensorInfo() const override { return tensors_; }

    virtual bool Load(VkDevice vkDevice, VkPhysicalDevice vkPhysDevice);
    virtual void CreateVulkanResources();

    enum class CompressionType
    {
        NONE,
        BRUTAL_GZIP,
        ZLIB,
        DEFLATE
    };
    virtual bool SetCompressionType(CompressionType type);
    virtual bool IsCompressed() const { return false; }
    virtual bool DecompressData(const std::vector<uint8_t>& in, std::vector<uint8_t>& out);
    virtual bool CompressData(const std::vector<uint8_t>& in, std::vector<uint8_t>& out);

    const void* GetBaseAddress() const { return mappedView; }

    struct UnsupportedTypeInfo
    {
        uint32_t type_value;
        std::string type_name;
        std::vector<std::string> tensor_names;
    };

    virtual bool HasUnsupportedQuantizationTypes() const;
    virtual std::vector<UnsupportedTypeInfo> GetUnsupportedQuantizationTypes() const;
    virtual std::string GetRecommendedConversionType() const;

    std::vector<UnsupportedTypeInfo> unsupported_types_structs_;
    std::map<std::string, RawrXD::TensorInfo*> tensor_index_map_;

    VkDevice device = nullptr;
    VkPhysicalDevice physDevice = nullptr;
    VkQueue transferQueue = nullptr;
    VkCommandPool cmdPool = nullptr;
    VkCommandBuffer cmdBuffer = nullptr;

    // Windows Handles for MappedView
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE hMapping = nullptr;
    uint64_t fileSize = 0;

    CompressionType compression_type_ = CompressionType::NONE;
    std::mutex tensorMutex;

    template <typename T> bool ReadValue(T& val);
    bool ReadString(std::string& str);
    size_t CalculateTensorSize(const std::vector<uint64_t>& shape, RawrXD::GGMLType type) const;

  protected:
    std::string filepath_;
    std::ifstream file_;
    bool is_open_;

    RawrXD::GGUFHeader header_;
    RawrXD::GGUFMetadata metadata_;
    std::vector<RawrXD::TensorInfo> tensors_;
    std::vector<std::string> unsupported_types_;

    void* mappedView = nullptr;

    void LoadTensorAsync(RawrXD::TensorInfo& info);
    void UploadF32(RawrXD::TensorInfo& info, void* src, size_t count);
    void DequantAndUploadQ4_0(RawrXD::TensorInfo& info, void* src, size_t count);
    void BeginCommandBuffer();
    void EndCommandBuffer();
    uint32_t FindMemoryType(uint32_t typeFilter, uint32_t props);
    uint32_t FindQueueFamilyIndex(VkPhysicalDevice device, uint32_t queueFlags);
};
=======
#pragma once

#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <cstdint>
#include <variant>
#include <unordered_map>
#include <mutex>

// We need windows.h for Handles in the Loader
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// Vulkan Forward Declares to avoid full include in header
typedef struct VkDevice_T* VkDevice;
typedef struct VkPhysicalDevice_T* VkPhysicalDevice;
typedef struct VkBuffer_T* VkBuffer;
typedef struct VkDeviceMemory_T* VkDeviceMemory;
typedef struct VkQueue_T* VkQueue;
typedef struct VkCommandPool_T* VkCommandPool;
typedef struct VkCommandBuffer_T* VkCommandBuffer;


// Basic types for GGUF
enum class GGMLType : uint32_t {
    F32  = 0,
    F16  = 1,
    Q4_0 = 2,
    Q4_1 = 3,
    Q5_0 = 6,
    Q5_1 = 7,
    Q8_0 = 8,
    Q8_1 = 9,
    // K-Quants
    Q2_K = 10,
    Q3_K = 11,
    Q4_K = 12,
    Q5_K = 13,
    Q6_K = 14,
    Q8_K = 15,
    I8,
    I16,
    I32,
    COUNT 
};

struct GGUFHeader {
    uint32_t magic;
    uint32_t version;
    uint64_t tensor_count;
    uint64_t metadata_kv_count;
};

struct TensorInfo {
    std::string name;
    std::vector<uint64_t> shape; // dims
    GGMLType type;
    uint64_t offset;
    size_t size;
    
    // GPU Resources
    void* cpuData = nullptr;
    VkBuffer gpuBuffer = nullptr; // VK_NULL_HANDLE
    VkDeviceMemory gpuMemory = nullptr; // VK_NULL_HANDLE
    bool onGPU = false;
};

struct GGUFMetadata {
    // ...existing code...
    uint32_t type;
    uint32_t length;
    uint64_t offset;
};

class GGUFLoader {
public:
    GGUFLoader();
    ~GGUFLoader();

    bool Open(const std::string& filepath);
    void Close();
    
    // Original API
    bool ParseHeader();
    
    // New API from user request (adapted)
    bool Load(VkDevice vkDevice, VkPhysicalDevice vkPhysDevice);
    
    // Helpers
    uint64_t GetMetadata(const std::string& key);
    TensorInfo& GetTensor(const std::string& name);

private:
    std::ifstream file_;
    std::string filepath_;
    bool is_open_;
    
    GGUFHeader header_val; // Renamed to avoid collision with struct type
    
    // Handles for Memory Mapping
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE hMapping = nullptr;
    void* mappedView = nullptr;
    size_t fileSize = 0;

    // Vulkan Context
    VkDevice device;
    VkPhysicalDevice physDevice;
    VkQueue transferQueue;
    VkCommandPool cmdPool;
    VkCommandBuffer cmdBuffer;

    std::mutex tensorMutex;
    std::unordered_map<std::string, TensorInfo> tensors;
    
    // Internal loading methods
    void CreateVulkanResources();
    void LoadTensorAsync(TensorInfo& info);
    void UploadF32(TensorInfo& info, void* src, size_t count);
    void DequantAndUploadQ4_0(TensorInfo& info, void* src, size_t count);
    // ... Add others as needed, simplified for this integration
    
    void BeginCommandBuffer();
    void EndCommandBuffer();
    uint32_t FindMemoryType(uint32_t typeFilter, uint32_t props);
    uint32_t FindQueueFamilyIndex(VkPhysicalDevice device, uint32_t queueFlags);
};

    std::map<std::string, std::string> kv_pairs; 
    
    // Structured data extracted from KV pairs
    uint32_t architecture_type = 0;
    uint32_t layer_count = 0;
    uint32_t context_length = 0;
    uint32_t embedding_dim = 0;
    uint32_t vocab_size = 0;
    uint32_t head_count = 0;

    // Tokenizer data
    std::vector<std::string> tokens;
    std::vector<float> token_scores;
    std::vector<uint32_t> token_types;
    int32_t tokenizer_model_id = -1; // -1 for unknown/default
};

// Interface for GGUF Loaders
struct IGGUFLoader {
    virtual ~IGGUFLoader() = default;
    
    virtual bool Open(const std::string& filepath) = 0;
    virtual bool Close() = 0;
    
    virtual bool ParseHeader() = 0;
    virtual GGUFHeader GetHeader() const = 0;
    
    virtual bool ParseMetadata() = 0;
    virtual GGUFMetadata GetMetadata() const = 0;
    
    virtual std::vector<TensorInfo> GetTensorInfo() const = 0;
    virtual bool LoadTensorRange(size_t start_idx, size_t count, std::vector<uint8_t>& data) = 0;

    // Enhanced / Streaming Methods
    virtual size_t GetTensorByteSize(const TensorInfo& tensor) const { return 0; }
    virtual std::string GetTypeString(GGMLType type) const { return "unknown"; }
    virtual bool BuildTensorIndex() { return false; }
    virtual bool LoadZone(const std::string& zone_name, uint64_t max_memory_mb = 512) { return false; }
    virtual bool UnloadZone(const std::string& zone_name) { return false; }
    virtual bool LoadTensorZone(const std::string& tensor_name, std::vector<uint8_t>& data) { return false; }
    virtual uint64_t GetFileSize() const { return 0; }
    virtual uint64_t GetCurrentMemoryUsage() const { return 0; }
    virtual std::vector<std::string> GetLoadedZones() const { return {}; }
    virtual std::vector<std::string> GetAllZones() const { return {}; }
    virtual std::vector<TensorInfo> GetAllTensorInfo() const { return GetTensorInfo(); }
};

class GGUFLoader : public IGGUFLoader {
public:
    GGUFLoader();
    virtual ~GGUFLoader();
    
    bool Open(const std::string& filepath) override;
    bool Close() override;
    
    bool ParseHeader() override;
    GGUFHeader GetHeader() const override { return header_; }
    
    bool ParseMetadata() override; // Implemented in cpp
    GGUFMetadata GetMetadata() const override { return metadata_; }
    
    std::vector<TensorInfo> GetTensorInfo() const override { return tensors_; }
    bool LoadTensorRange(size_t start_idx, size_t count, std::vector<uint8_t>& data) override;

    // Helper for subclasses or internal use
    const void* GetBaseAddress() const { return mappedView; }

    template<typename T>
    bool ReadValue(T& val) {
        if (!file_.is_open()) return false;
        file_.read(reinterpret_cast<char*>(&val), sizeof(T));
        return file_.good();
    }

protected:
    std::string filepath_;
    std::ifstream file_;
    bool is_open_;
    
    GGUFHeader header_;
    GGUFMetadata metadata_;
    std::vector<TensorInfo> tensors_;
    std::vector<std::string> unsupported_types_;
};
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
