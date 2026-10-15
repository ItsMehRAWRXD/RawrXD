#pragma once
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <cstdint>
#include <fstream>
#include <unordered_map>
#include "brutal_gzip.h"
// This header owns std::unordered_map<std::string, VulkanTensor> members and
// VulkanCompute* calls, so the full VulkanTensor type is required here. The
// forward-declaration-only variant (dangling autostash 46eace849f, which assumed
// pointer-only members) does not compile on this branch: restoring the include.
// The Vulkan SDK ships in this workspace's build include paths.
#include "vulkan_compute.h"
#if defined(__has_include)
#  if __has_include(<QtCore/QByteArray>)
#    include "deflate_brutal_qt.hpp"
#  endif
#else
#  include "deflate_brutal_qt.hpp"
#endif

// Compression type enumeration for GGUF tensors
enum class CompressionType : uint32_t {
    NONE = 0,
    DEFLATE = 1,
    BRUTAL_GZIP = 2,
    ZLIB = 3,
};

enum class GGMLType : uint32_t {
    // Canonical ggml_type IDs (matches 3rdparty/ggml/include/ggml.h and
    // src/deep2/QuantTypeTable.hpp). These values are the on-disk GGUF tensor
    // type tags, so they MUST stay in sync with llama.cpp/ggml. The previous
    // enum had several K-quant and Q8_0/Q5_1 values swapped (e.g. Q4_K was 10
    // instead of 12, Q8_0 was 7 instead of 8), which caused on-disk tensors to
    // be mislabeled and mis-sized.
    F32 = 0,
    F16 = 1,
    Q4_0 = 2,
    Q4_1 = 3,
    // 4,5 removed in ggml (Q4_2/Q4_3 support dropped)
    Q5_0 = 6,
    Q5_1 = 7,
    Q8_0 = 8,
    Q8_1 = 9,
    Q2_K = 10,
    Q3_K = 11,
    Q4_K = 12,
    Q5_K = 13,
    Q6_K = 14,
    Q8_K = 15,
    IQ2_XXS = 16,
    IQ2_XS = 17,
    IQ3_XXS = 18,
    IQ1_S = 19,
    IQ4_NL = 20,
    IQ3_S = 21,
    IQ2_S = 22,
    IQ4_XS = 23,
    I8 = 24,
    I16 = 25,
    I32 = 26,
    I64 = 27,
    F64 = 28,
    IQ1_M = 29,
    BF16 = 30,
    // 31-33 removed (Q4_0_x_x variants)
    TQ1_0 = 34,
    TQ2_0 = 35,
    // 36-38 removed (IQ4_NL_x_x variants)
    MXFP4 = 39,
    NVFP4 = 40,
    Q1_0 = 41,
    Q2_0 = 42,
    COUNT = 43,
};

struct GGUFHeader {
    uint32_t magic;
    uint32_t version;
    uint64_t tensor_count;
    uint64_t metadata_kv_count;
    uint64_t metadata_offset;
};

struct TensorInfo {
    std::string name;
    std::vector<uint64_t> shape;
    GGMLType type;
    uint64_t offset;
    uint64_t size_bytes;
};

struct GGUFMetadata {
    std::map<std::string, std::string> kv_pairs;
    uint32_t architecture_type;
    uint32_t layer_count;
    uint32_t context_length;
    uint32_t embedding_dim;
    uint32_t vocab_size;
    std::vector<std::string> tokens;
    std::vector<float> token_scores;
    std::vector<uint32_t> token_types;
};

class IGGUFLoader {
public:
    virtual ~IGGUFLoader() = default;
    virtual bool Open(const std::string& filepath) = 0;
    virtual bool Close() = 0;
    virtual bool ParseHeader() = 0;
    virtual GGUFHeader GetHeader() const = 0;
    virtual bool ParseMetadata() = 0;
    virtual GGUFMetadata GetMetadata() const = 0;
    virtual std::vector<TensorInfo> GetTensorInfo() const = 0;
    virtual bool LoadTensorZone(const std::string& tensor_name, std::vector<uint8_t>& data) = 0;
    virtual bool LoadTensorRange(size_t start_idx, size_t count, std::vector<uint8_t>& data) = 0;
    virtual size_t GetTensorByteSize(const TensorInfo& tensor) const = 0;
    virtual std::string GetTypeString(GGMLType type) const = 0;
    virtual uint64_t GetFileSize() const = 0;
    // Streaming friendly methods (no-op for non-streaming loader)
    virtual bool BuildTensorIndex() = 0;
    virtual bool LoadZone(const std::string& zone_name, uint64_t max_memory_mb = 512) = 0;
    virtual bool UnloadZone(const std::string& zone_name) = 0;
    virtual std::vector<std::string> GetLoadedZones() const = 0;
    virtual std::vector<std::string> GetAllZones() const = 0;
    virtual std::vector<TensorInfo> GetAllTensorInfo() const = 0;
    virtual uint64_t GetCurrentMemoryUsage() const = 0;
};

class GGUFLoader : public IGGUFLoader {
public:
    GGUFLoader();
    ~GGUFLoader();

    bool Open(const std::string& filepath) override;
    bool Close() override;
    
    // Header operations
    bool ParseHeader() override;
    GGUFHeader GetHeader() const override { return header_; }
    
    // Metadata operations
    bool ParseMetadata() override;
    GGUFMetadata GetMetadata() const override { return metadata_; }
    const std::vector<std::string>& GetVocabulary() const { return metadata_.tokens; }
    
    // Tensor operations
    std::vector<TensorInfo> GetTensorInfo() const override { return tensors_; }
    bool LoadTensorZone(const std::string& tensor_name, std::vector<uint8_t>& data) override;
    bool LoadTensorRange(size_t start_idx, size_t count, std::vector<uint8_t>& data) override;
    void AttachVulkanEngine(VulkanCompute* engine) { vulkan_engine_ = engine; }
    
    // Compression support for MASM-optimized decompression
    bool IsCompressed() const { return compression_type_ != CompressionType::NONE; }
    CompressionType GetCompressionType() const { return compression_type_; }
    bool SetCompressionType(CompressionType type);
    bool DecompressData(const std::vector<uint8_t>& compressed, std::vector<uint8_t>& decompressed);
    bool CompressData(const std::vector<uint8_t>& raw_data, std::vector<uint8_t>& compressed);
    
    // GGUF Alignment Helpers (tensor data section is 32-byte aligned per spec)
    static constexpr uint64_t GGUF_TENSOR_ALIGNMENT = 32;
    inline uint64_t AlignTo32Bytes(uint64_t offset) const {
        return (offset + GGUF_TENSOR_ALIGNMENT - 1) & ~(GGUF_TENSOR_ALIGNMENT - 1);
    }
    inline uint64_t GetAlignedTensorDataStart() const {
        // Tensor data section starts after metadata + tensor info, aligned to 32 bytes
        return AlignTo32Bytes(static_cast<uint64_t>(file_.tellg()));
    }
    bool UploadAllTensorsToVulkan();
    bool UploadTensorToVulkan(const std::string& tensor_name);
    const std::unordered_map<std::string, VulkanTensor>& GetVulkanTensors() const { return vulkan_tensors_; }
    
    // Utility functions
    size_t GetTensorByteSize(const TensorInfo& tensor) const override;
    std::string GetTypeString(GGMLType type) const override;
    uint64_t GetFileSize() const override;
    
    // Quantization type validation (for IDE conversion workflow)
    bool HasUnsupportedQuantizationTypes() const;
    struct UnsupportedTypeInfo {
        uint32_t type_value;
        std::string type_name;
        std::vector<std::string> tensor_names;  // Tensors using this type
    };
    std::vector<UnsupportedTypeInfo> GetUnsupportedQuantizationTypes() const;
    std::string GetRecommendedConversionType() const;
    
    // Streaming interface stubs (non-streaming loader - minimal implementations).
    // Parameter names are omitted deliberately: these are unused stubs, and
    // naming them invites future confusion about whether the arguments matter.
    bool BuildTensorIndex() override { return true; }  // Already built during ParseHeader
    bool LoadZone(const std::string&, uint64_t = 512) override { return true; }
    bool UnloadZone(const std::string&) override { return true; }
    std::vector<std::string> GetLoadedZones() const override { return {"all"}; }
    std::vector<std::string> GetAllZones() const override { return {"all"}; }
    std::vector<TensorInfo> GetAllTensorInfo() const override { return tensors_; }
    uint64_t GetCurrentMemoryUsage() const override { return 0; }

    /// Human-readable reason the last Open() failed. Empty on success.
    /// Populated when Open() returns false so callers/UI can show a real
    /// diagnosis instead of a generic "failed to open".
    const std::string& GetLastOpenError() const { return last_open_error_; }

private:
    std::string filepath_;
    mutable std::ifstream file_;
    GGUFHeader header_;
    GGUFMetadata metadata_;
    std::vector<TensorInfo> tensors_;
    // O(1) tensor lookup index (Bottleneck #14 fix - eliminates std::find_if O(n) search)
    std::unordered_map<std::string, const TensorInfo*> tensor_index_;
    bool is_open_;
    VulkanCompute* vulkan_engine_{nullptr};
    std::unordered_map<std::string, VulkanTensor> vulkan_tensors_;
    bool use_dummy_mode_{false};  // Skip tensor loading for huge files
    uint64_t file_size_{0};

    /// Reason Open() most recently failed (empty when the last Open succeeded).
    std::string last_open_error_;
    
    // Unsupported type tracking (for IDE conversion workflow)
    std::vector<UnsupportedTypeInfo> unsupported_types_;
    
    // Memory-mapped file support (Windows)
    void* mmap_base_{nullptr};
    void* file_handle_{nullptr};  // HANDLE on Windows
    void* map_handle_{nullptr};   // HANDLE on Windows
    bool use_mmap_{false};
    
    // Compression support (optimized with existing brutal_gzip)
    CompressionType compression_type_ = CompressionType::NONE;
    
    // Internal parsing helpers
    template<typename T>
    bool ReadValue(T& value);
    bool ReadString(std::string& value);
    bool ReadMetadataKV(const std::string& key, std::string& value);
    uint64_t CalculateTensorSize(const std::vector<uint64_t>& shape, GGMLType type) const;
    bool CreateDummyModel();
    bool InitializeMemoryMap();
    void CleanupMemoryMap();
    const void* GetMappedSlice(uint64_t offset, uint64_t size) const;
};
