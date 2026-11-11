#pragma once
// This header deliberately includes RawrXD_Interfaces.h, NOT the
// include/gguf_loader.h pair. include/gguf_loader.h declares a *second*,
// divergent global-namespace IGGUFLoader / TensorInfo / GGMLType / GGUFMetadata
// quartet with different enum values (its Q4_K = 10 and Q6_K = 13, where ggml's
// real values are 12 and 14). Which quartet you got depended purely on
// #include order, so StreamingGGUFLoader silently derived from the wrong
// IGGUFLoader and could not be handed to the executor.
//
// Every interface type is qualified with RawrXD:: so this header parses the
// same whether it is included from a global-scope translation unit
// (src/streaming_gguf_loader.cpp) or from inside namespace RawrXD
// (src/cpu_inference_engine_impl.cpp). An earlier version used
// `using RawrXD::GGMLType;` at file scope, which triggers C2874
// "multiple declaration" when the header is reached from inside the namespace.
// Target namespace resolution follows.
#include "RawrXD_Interfaces.h"
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <cstdint>
#include <fstream>

// Target the resolver: this header is reached both at global scope and from
// inside namespace RawrXD, so the namespace-qualified spelling must be uniform.
#ifdef RAWRXD_STREAMING_GGUF_LOADER_TARGET_RAWRXD
// Resolved into the RawrXD namespace by the including translation unit; types
// still qualify explicitly so no using-declaration is needed.
#endif

// ============================================================================// STREAMING GGUF LOADER - Memory-efficient tensor loading with zone-based
// streaming (game engine style)
// ============================================================================

struct TensorZoneInfo {
    std::string zone_name;              // "embedding", "layers_0", "layers_1", etc.
    std::vector<std::string> tensors;   // Tensor names in this zone
    uint64_t total_bytes;               // Total size of all tensors in zone
    bool is_loaded;                     // Currently in RAM?
    std::vector<uint8_t> data;          // Actual tensor data (when loaded)
};

struct TensorRef {
    std::string name;
    std::string zone_name;              // Which zone does this belong to?
    uint64_t offset;                    // Byte offset in file
    uint64_t size;                      // Size of this tensor
    RawrXD::GGMLType type;
    std::vector<uint64_t> shape;
};

class StreamingGGUFLoader : public RawrXD::IGGUFLoader {
public:
    StreamingGGUFLoader();
    ~StreamingGGUFLoader();

    // ---- File Opening (streams header, not data) ----
    bool Open(const std::string& filepath) override;
    bool Close() override;

    // ---- Header & Metadata (always in RAM) ----
    bool ParseHeader() override;
    RawrXD::GGUFHeader GetHeader() const override;
    bool ParseMetadata() override;
    RawrXD::GGUFMetadata GetMetadata() const override;

    // ---- Required interface methods ----
    std::vector<RawrXD::TensorInfo> GetTensorInfo() const override;
    bool LoadTensorRange(size_t start_idx, size_t count, std::vector<uint8_t>& data) override;
    size_t GetTensorByteSize(const RawrXD::TensorInfo& tensor) const override;
    std::string GetTypeString(RawrXD::GGMLType type) const override;

    // ---- Index Building (builds offset map, no tensor data loaded) ----
    bool BuildTensorIndex() override;   // Read all tensor info, calculate offsets
    std::vector<TensorRef> GetTensorIndex() const;  // Just metadata!

    // ---- ZONE-BASED LOADING (the core innovation) ----

    // Get which zone a tensor belongs to
    std::string GetTensorZone(const std::string& tensor_name) const;

    // Load a zone into RAM (unloads other zones if needed)
    bool LoadZone(const std::string& zone_name, uint64_t max_memory_mb = 512) override;

    // Unload a zone from RAM
    bool UnloadZone(const std::string& zone_name) override;

    // Access tensor data (loads zone if needed) - implements base class LoadTensorZone
    bool LoadTensorZone(const std::string& tensor_name, std::vector<uint8_t>& data) override;
    bool GetTensorData(const std::string& tensor_name, std::vector<uint8_t>& data) override;

    // Get zone info (what's loaded, what's not)
    TensorZoneInfo GetZoneInfo(const std::string& zone_name) const;

    // ---- Utility ----
    uint64_t GetFileSize() const override;
    uint64_t GetTotalFileSize() const; // Non-virtual alias for compatibility
    uint64_t GetCurrentMemoryUsage() const override;
    std::vector<std::string> GetLoadedZones() const override;
    std::vector<std::string> GetAllZones() const override;

    // For compatibility with old loader
    std::vector<RawrXD::TensorInfo> GetAllTensorInfo() const override;

    // ---- Random-access lookup (RawrXD::IGGUFLoader) -------------------------
    const RawrXD::TensorInfo* GetTensorInfo(const std::string& name) const override;
    const std::vector<std::string>& GetVocabulary() const override;
    bool LoadTensorSlice(const std::string& name,
                         uint64_t byte_offset,
                         uint64_t byte_count,
                         std::vector<uint8_t>& data) override;

private:
    // ---- File Handle (kept open for streaming) ----
    std::string filepath_;
    mutable std::ifstream file_;
    bool is_open_;

    // ---- Metadata (always in RAM, ~50-100 MB) ----
    RawrXD::GGUFHeader header_;
    RawrXD::GGUFMetadata metadata_;

    // ---- Tensor Index (always in RAM, ~40 MB) ----
    // Maps tensor_name -> {offset, size, type, shape}
    std::map<std::string, TensorRef> tensor_index_;

    // GGUF tensor offsets are relative to the aligned tensor-data section,
    // not to the beginning of the file.  Keep the computed absolute base so
    // all streaming reads use one unambiguous coordinate system.
    uint64_t data_start_ = 0;

    // ---- Zone Information ----
    // Maps zone_name -> {tensors, total_bytes, is_loaded, data}
    std::map<std::string, TensorZoneInfo> zones_;

    // Currently loaded zones (can have multiple active zones for pre-loading)
    std::map<std::string, bool> active_zones_;
    std::string current_zone_;
    uint64_t current_zone_memory_;

    // ---- Configuration ----
    uint64_t max_zone_memory_mb_;       // How much RAM per zone? (512 MB default)

    // ---- Internal Helpers ----

    // Assign tensors to zones based on name patterns
    void AssignTensorsToZones();

    // Load zone data from disk
    bool StreamZoneFromDisk(const std::string& zone_name);

    // Calculate which layer a tensor belongs to
    int32_t ExtractLayerNumber(const std::string& tensor_name) const;

    // Get zone for tensor name
    std::string GetZoneForTensor(const std::string& tensor_name) const;

    // Template reading
    template<typename T>
    bool ReadValue(T& value);
    bool ReadString(std::string& value);
    bool SkipMetadataValue(uint32_t value_type);
    uint64_t CalculateTensorSize(const std::vector<uint64_t>& shape, RawrXD::GGMLType type) const;
};
