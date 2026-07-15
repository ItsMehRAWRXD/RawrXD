/**
 * @file ModelLoader.cpp
 * @brief Implementation of ModelLoader
 * 
 * Provides robust GGUF model loading with validation and error handling.
 * 
 * @copyright RawrXD 2026
 */

#include "ModelLoader.h"
#include "GGMLBackend.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <fstream>
#include <mutex>
#include <sstream>

// GGML includes
extern "C" {
#include "../../3rdparty/ggml/include/ggml.h"
#include "../../3rdparty/ggml/include/gguf.h"
}

namespace RawrXD {
namespace Inference {

// GGUF magic number (avoid conflict with macro)
static constexpr uint32_t GGUF_MAGIC_LE = 0x46554747;  // "GGUF" in little-endian

// ============================================================================
// Private Implementation
// ============================================================================

class ModelLoader::Impl {
public:
    Impl() = default;
    ~Impl() = default;
    
    mutable std::mutex m_mutex;
    std::string m_lastError;
    
    // Helper methods
    bool ValidateFileExists(const std::string& path);
    bool ValidateFileSize(const std::string& path, size_t maxSize);
    bool ValidateGGUFHeader(const std::string& path);
    ModelArchitecture ExtractArchitecture(struct gguf_context* ctx);
    std::string GetErrorContext(const std::string& operation, const std::string& details);
};

bool ModelLoader::Impl::ValidateFileExists(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    return file.good();
}

bool ModelLoader::Impl::ValidateFileSize(const std::string& path, size_t maxSize) {
    if (maxSize == 0) {
        return true;  // No limit
    }
    
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.good()) {
        return false;
    }
    
    size_t fileSize = static_cast<size_t>(file.tellg());
    return fileSize <= maxSize;
}

bool ModelLoader::Impl::ValidateGGUFHeader(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.good()) {
        return false;
    }
    
    // Read magic number
    uint32_t magic = 0;
    file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    
    return magic == GGUF_MAGIC_LE;
}

ModelArchitecture ModelLoader::Impl::ExtractArchitecture(struct gguf_context* ctx) {
    ModelArchitecture arch;
    
    if (!ctx) {
        return arch;
    }
    
    // Extract metadata from GGUF
    // Try to get common architecture fields
    
    // Get architecture name
    int archKeyIdx = gguf_find_key(ctx, "general.architecture");
    if (archKeyIdx >= 0) {
        const char* archName = gguf_get_val_str(ctx, archKeyIdx);
        if (archName) {
            arch.name = archName;
        }
    }
    
    // Get vocab size
    std::string vocabKey = arch.name + ".vocab_size";
    int vocabKeyIdx = gguf_find_key(ctx, vocabKey.c_str());
    if (vocabKeyIdx < 0) {
        vocabKeyIdx = gguf_find_key(ctx, "tokenizer.ggml.tokens");
    }
    if (vocabKeyIdx >= 0) {
        arch.vocabSize = static_cast<int>(gguf_get_arr_n(ctx, vocabKeyIdx));
    }
    
    // Get number of layers
    std::string layersKey = arch.name + ".block_count";
    int layersKeyIdx = gguf_find_key(ctx, layersKey.c_str());
    if (layersKeyIdx >= 0) {
        arch.numLayers = static_cast<int>(gguf_get_val_u32(ctx, layersKeyIdx));
    }
    
    // Get embedding dimension
    std::string embdKey = arch.name + ".embedding_length";
    int embdKeyIdx = gguf_find_key(ctx, embdKey.c_str());
    if (embdKeyIdx >= 0) {
        arch.embeddingDim = static_cast<int>(gguf_get_val_u32(ctx, embdKeyIdx));
    }
    
    // Get feed-forward dimension
    std::string ffnKey = arch.name + ".feed_forward_length";
    int ffnKeyIdx = gguf_find_key(ctx, ffnKey.c_str());
    if (ffnKeyIdx >= 0) {
        arch.hiddenDim = static_cast<int>(gguf_get_val_u32(ctx, ffnKeyIdx));
    }
    
    // Get attention heads
    std::string headsKey = arch.name + ".attention.head_count";
    int headsKeyIdx = gguf_find_key(ctx, headsKey.c_str());
    if (headsKeyIdx >= 0) {
        arch.numHeads = static_cast<int>(gguf_get_val_u32(ctx, headsKeyIdx));
    }
    
    // Get KV heads
    std::string kvHeadsKey = arch.name + ".attention.head_count_kv";
    int kvHeadsKeyIdx = gguf_find_key(ctx, kvHeadsKey.c_str());
    if (kvHeadsKeyIdx >= 0) {
        arch.numKVHeads = static_cast<int>(gguf_get_val_u32(ctx, kvHeadsKeyIdx));
    } else {
        arch.numKVHeads = arch.numHeads;  // Default to same as heads
    }
    
    // Get context length
    std::string ctxKey = arch.name + ".context_length";
    int ctxKeyIdx = gguf_find_key(ctx, ctxKey.c_str());
    if (ctxKeyIdx >= 0) {
        arch.contextLength = static_cast<int>(gguf_get_val_u32(ctx, ctxKeyIdx));
    }
    
    // Get RoPE parameters
    std::string ropeFreqKey = arch.name + ".rope.freq_base";
    int ropeFreqKeyIdx = gguf_find_key(ctx, ropeFreqKey.c_str());
    if (ropeFreqKeyIdx >= 0) {
        arch.ropeFreqBase = gguf_get_val_f32(ctx, ropeFreqKeyIdx);
    }
    
    std::string ropeScaleKey = arch.name + ".rope.scale_linear";
    int ropeScaleKeyIdx = gguf_find_key(ctx, ropeScaleKey.c_str());
    if (ropeScaleKeyIdx >= 0) {
        arch.ropeFreqScale = gguf_get_val_f32(ctx, ropeScaleKeyIdx);
    }
    
    return arch;
}

std::string ModelLoader::Impl::GetErrorContext(const std::string& operation, 
                                                const std::string& details) {
    return operation + ": " + details;
}

// ============================================================================
// Factory
// ============================================================================

std::unique_ptr<ModelLoader> ModelLoader::Create() {
    return std::unique_ptr<ModelLoader>(new ModelLoader());
}

// ============================================================================
// Constructor / Destructor
// ============================================================================

ModelLoader::ModelLoader()
    : m_impl(std::make_unique<Impl>()) {
}

ModelLoader::~ModelLoader() = default;

// ============================================================================
// Model Loading
// ============================================================================

ModelLoadResult ModelLoader::Load(const ModelLoadConfig& config) {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    
    ModelLoadResult result;
    auto startTime = std::chrono::steady_clock::now();
    
    // Report initial progress
    if (config.progressCallback) {
        config.progressCallback(0.0f, "Starting load");
    }
    
    // Validate file exists
    if (!m_impl->ValidateFileExists(config.modelPath)) {
        result.errorMessage = "Model file not found: " + config.modelPath;
        return result;
    }
    
    if (config.progressCallback) {
        config.progressCallback(0.1f, "File exists");
    }
    
    // Validate file size
    if (!m_impl->ValidateFileSize(config.modelPath, config.maxModelSize)) {
        result.errorMessage = "Model file exceeds maximum size limit";
        return result;
    }
    
    if (config.progressCallback) {
        config.progressCallback(0.2f, "Size validated");
    }
    
    // Validate GGUF header
    if (!m_impl->ValidateGGUFHeader(config.modelPath)) {
        result.errorMessage = "Invalid GGUF file format";
        return result;
    }
    
    if (config.progressCallback) {
        config.progressCallback(0.3f, "Header validated");
    }
    
    // Load GGUF file
    struct gguf_init_params ggufParams = {
        .no_alloc = !config.useMemoryMapping,
        .ctx = nullptr,
    };
    
    struct gguf_context* ctx = gguf_init_from_file(config.modelPath.c_str(), ggufParams);
    if (!ctx) {
        result.errorMessage = "Failed to load GGUF file";
        return result;
    }
    
    if (config.progressCallback) {
        config.progressCallback(0.5f, "GGUF loaded");
    }
    
    // Extract architecture
    result.architecture = m_impl->ExtractArchitecture(ctx);
    
    // Count tensors
    result.tensorCount = static_cast<size_t>(gguf_get_n_tensors(ctx));
    
    // Calculate model size
    result.modelSize = 0;
    for (int i = 0; i < static_cast<int>(result.tensorCount); i++) {
        const char* tensorName = gguf_get_tensor_name(ctx, i);
        // Note: We can't get exact size without loading tensors, estimate from file size
    }
    
    // Get file size as approximation
    std::ifstream file(config.modelPath, std::ios::binary | std::ios::ate);
    if (file.good()) {
        result.modelSize = static_cast<size_t>(file.tellg());
    }
    
    if (config.progressCallback) {
        config.progressCallback(0.7f, "Metadata extracted");
    }
    
    // Validate tensors if requested
    if (config.verifyTensors) {
        auto validationStart = std::chrono::steady_clock::now();
        
        // Basic validation: check all tensors are present
        for (int i = 0; i < static_cast<int>(result.tensorCount); i++) {
            const char* tensorName = gguf_get_tensor_name(ctx, i);
            if (!tensorName || strlen(tensorName) == 0) {
                result.warnings.push_back("Tensor " + std::to_string(i) + " has no name");
            }
        }
        
        auto validationEnd = std::chrono::steady_clock::now();
        result.validationTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            validationEnd - validationStart).count();
        
        if (config.progressCallback) {
            config.progressCallback(0.9f, "Tensors validated");
        }
    }
    
    // Clean up
    gguf_free(ctx);
    
    auto endTime = std::chrono::steady_clock::now();
    result.loadTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        endTime - startTime).count();
    
    result.success = true;
    
    if (config.progressCallback) {
        config.progressCallback(1.0f, "Load complete");
    }
    
    return result;
}

// ============================================================================
// Validation
// ============================================================================

ValidationResult ModelLoader::Validate(const std::string& path) {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    
    ValidationResult result;
    
    // Check file exists
    if (!m_impl->ValidateFileExists(path)) {
        result.errors.push_back("File not found: " + path);
        return result;
    }
    
    // Check GGUF header
    std::ifstream file(path, std::ios::binary);
    if (!file.good()) {
        result.errors.push_back("Cannot open file: " + path);
        return result;
    }
    
    uint32_t magic = 0;
    file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    if (magic != GGUF_MAGIC_LE) {
        result.errors.push_back("Invalid GGUF magic number");
        return result;
    }
    
    // Try to load metadata
    struct gguf_init_params params = {
        .no_alloc = true,  // Don't allocate tensors
        .ctx = nullptr,
    };
    
    struct gguf_context* ctx = gguf_init_from_file(path.c_str(), params);
    if (!ctx) {
        result.errors.push_back("Failed to parse GGUF file");
        return result;
    }
    
    // Check version
    uint32_t version = gguf_get_version(ctx);
    if (version < 2 || version > 3) {
        result.warnings.push_back("Unusual GGUF version: " + std::to_string(version));
    }
    
    // Check for required metadata
    int archIdx = gguf_find_key(ctx, "general.architecture");
    if (archIdx < 0) {
        result.warnings.push_back("Missing architecture metadata");
    }
    
    // Validate tensors
    int tensorCount = gguf_get_n_tensors(ctx);
    result.checkedTensors = static_cast<size_t>(tensorCount);
    
    for (int i = 0; i < tensorCount; i++) {
        const char* name = gguf_get_tensor_name(ctx, i);
        if (!name || strlen(name) == 0) {
            result.errors.push_back("Tensor " + std::to_string(i) + " has invalid name");
            result.failedTensors++;
        }
    }
    
    gguf_free(ctx);
    
    result.valid = result.errors.empty();
    return result;
}

// ============================================================================
// Static Methods
// ============================================================================

bool ModelLoader::IsValidGGUF(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.good()) {
        return false;
    }
    
    uint32_t magic = 0;
    file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    
    return magic == GGUF_MAGIC_LE;
}

uint32_t ModelLoader::GetGGUFVersion(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.good()) {
        return 0;
    }
    
    // Skip magic (4 bytes)
    file.seekg(4);
    
    uint32_t version = 0;
    file.read(reinterpret_cast<char*>(&version), sizeof(version));
    
    return version;
}

ModelArchitecture ModelLoader::PeekMetadata(const std::string& path) {
    ModelArchitecture arch;
    
    if (!IsValidGGUF(path)) {
        return arch;
    }
    
    struct gguf_init_params params = {
        .no_alloc = true,
        .ctx = nullptr,
    };
    
    struct gguf_context* ctx = gguf_init_from_file(path.c_str(), params);
    if (!ctx) {
        return arch;
    }
    
    // Create temporary loader to extract architecture
    Impl tempImpl;
    arch = tempImpl.ExtractArchitecture(ctx);
    
    gguf_free(ctx);
    
    return arch;
}

// ============================================================================
// Error Handling
// ============================================================================

std::string ModelLoader::GetLastError() const {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    return m_impl->m_lastError;
}

void ModelLoader::ClearError() {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    m_impl->m_lastError.clear();
}

} // namespace Inference
} // namespace RawrXD
