#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <cstddef>
#include <fstream>
#include <map>
#include <set>

/**
 * GGUF Model Metadata Structure
 */
struct GGUFMetadata
{
    std::string modelName;
    std::string architecture;
    uint32_t contextLength = 0;
    uint32_t layerCount = 0;
    uint32_t headCount = 0;
    uint32_t headCountKV = 0;
    float ropeFrequencyBase = 10000.0f;
    std::string ropeScalingType;
    float ropeScalingFactor = 1.0f;
};

/**
 * @brief Streaming GGUF model loader for memory-efficient zone-based loading.
 *
 * Loads GGUF model files in zones (embedding, attention, feedforward) to minimize
 * peak memory usage. Supports lazy loading and unloading of zones as needed.
 */
class StreamingGGUFLoader
{
public:
    StreamingGGUFLoader();
    ~StreamingGGUFLoader();

    /**
     * Open and validate a GGUF file.
     * @param filepath Path to the .gguf file.
     * @return true if file is valid GGUF, false otherwise.
     */
    bool Open(const std::string& filepath);

    /**
     * Close the currently open GGUF file.
     */
    void Close();

    /**
     * Parse GGUF file header to validate magic number and version.
     * @return true on success, false on format error.
     */
    bool ParseHeader();

    /**
     * Parse GGUF metadata (model name, architecture, dimensions, etc.).
     * @return true on success, false on parse error.
     */
    bool ParseMetadata();

    /**
     * Build an index of all tensors in the file for fast lookup.
     * @return true on success, false on error.
     */
    bool BuildTensorIndex();

    /**
     * Load a specific zone (embedding, attention, feedforward, output) into memory.
     * @param zoneName Name of the zone to load.
     * @return true on success, false on error.
     */
    bool LoadZone(const std::string& zoneName);

    /**
     * Unload a specific zone from memory.
     * @param zoneName Name of the zone to unload.
     */
    void UnloadZone(const std::string& zoneName);

    /**
     * Get metadata extracted from the model.
     */
    [[nodiscard]] GGUFMetadata GetMetadata() const;

    /**
     * Get list of all tensor names in the model.
     */
    [[nodiscard]] std::vector<std::string> GetTensorNames() const;

    /**
     * Get the shape (dimensions) of a specific tensor.
     */
    [[nodiscard]] std::vector<size_t> GetTensorShape(const std::string& tensorName) const;

    /**
     * Get current memory usage of loaded zones (in bytes).
     */
    [[nodiscard]] size_t GetCurrentMemoryUsage() const;

    /**
     * Get total file size (in bytes).
     */
    [[nodiscard]] size_t GetTotalFileSize() const;

    /**
     * Check if a specific zone is currently loaded.
     */
    [[nodiscard]] bool IsZoneLoaded(const std::string& zoneName) const;

private:
    void* m_fileHandle = nullptr;
    std::string m_filepath;
    GGUFMetadata m_metadata;
    std::vector<std::string> m_tensorNames;
    std::vector<std::vector<size_t>> m_tensorShapes;
    size_t m_currentMemoryUsage = 0;
    size_t m_totalFileSize = 0;
    bool m_headerParsed = false;
    bool m_metadataParsed = false;
    bool m_indexBuilt = false;
    
    // Internal implementation members
    bool is_open_ = false;
    std::ifstream file_;
    std::string filepath_;
    std::string model_name_;
    std::string architecture_;
    uint32_t context_length_ = 0;
    uint32_t layer_count_ = 0;
    uint32_t head_count_ = 0;
    uint32_t head_count_kv_ = 0;
    float rope_freq_base_ = 10000.0f;
    std::string rope_scaling_type_;
    float rope_scaling_factor_ = 1.0f;
    
    struct GGUFHeader {
        uint32_t magic = 0;
        uint32_t version = 0;
        uint64_t tensor_count = 0;
        uint64_t metadata_kv_count = 0;
        uint64_t metadata_offset = 0;
    } header_;
    
    struct TensorInfo {
        std::string name;
        std::vector<size_t> shape;
        int type = 0;
    };
    
    std::vector<TensorInfo> tensor_index_;
    std::map<std::string, std::vector<uint8_t>> zones_;
    std::set<std::string> active_zones_;
    std::set<std::string> loaded_zones_;
    std::string current_zone_;
    size_t current_zone_memory_ = 0;
    size_t max_zone_memory_mb_ = 512;
};
