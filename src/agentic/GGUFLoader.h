/**
 * @file GGUFLoader.h
 * @brief Real GGUF model loader using GGML
 * 
 * Loads actual GGUF files and initializes GGML context.
 * 
 * @copyright RawrXD 2026
 */

#pragma once

#include "ErrorHandling.h"
#include "InferenceEngine.h"
#include <memory>
#include <vector>
#include <unordered_map>

// Forward declarations for GGML
struct ggml_rxd_context;
struct ggml_rxd_tensor;

namespace RawrXD {
namespace Agentic {

/**
 * @brief GGUF file header
 */
struct GGUFHeader {
    uint32_t magic;
    uint32_t version;
    uint64_t tensorCount;
    uint64_t metadataCount;
};

/**
 * @brief GGUF tensor info
 */
struct GGUFTensorInfo {
    std::string name;
    int n_dims;
    std::vector<uint64_t> dims;
    uint32_t type;
    uint64_t offset;
    size_t size;
};

/**
 * @brief Loaded model data
 */
struct LoadedModel {
    std::string path;
    GGUFHeader header;
    std::unordered_map<std::string, std::string> metadata;
    std::vector<GGUFTensorInfo> tensors;
    
    // GGML state
    ggml_rxd_context* ctx = nullptr;
    std::unordered_map<std::string, ggml_rxd_tensor*> tensorMap;
    
    // Model architecture
    int vocabSize = 0;
    int hiddenSize = 0;
    int numLayers = 0;
    int numHeads = 0;
    int contextLength = 0;
    std::string architecture;
};

/**
 * @brief Real GGUF loader
 */
class GGUFLoader {
public:
    GGUFLoader();
    ~GGUFLoader();
    
    // Disable copy, enable move
    GGUFLoader(const GGUFLoader&) = delete;
    GGUFLoader& operator=(const GGUFLoader&) = delete;
    GGUFLoader(GGUFLoader&&) noexcept;
    GGUFLoader& operator=(GGUFLoader&&) noexcept;
    
    /**
     * @brief Load a GGUF file
     * @param path Path to GGUF file
     * @return Result with loaded model or error
     */
    Result<std::unique_ptr<LoadedModel>> Load(const std::string& path);
    
    /**
     * @brief Check if a file is a valid GGUF
     */
    static bool IsValidGGUF(const std::string& path);
    
    /**
     * @brief Get last error message
     */
    const std::string& GetLastError() const { return m_lastError; }

private:
    std::string m_lastError;
    
    bool ParseHeader(FILE* file, GGUFHeader& header);
    bool ParseMetadata(FILE* file, const GGUFHeader& header, LoadedModel& model);
    bool ParseTensors(FILE* file, const GGUFHeader& header, LoadedModel& model);
    bool LoadTensorsIntoGGML(LoadedModel& model, FILE* file);
    
    void SetError(const std::string& msg);
};

} // namespace Agentic
} // namespace RawrXD
