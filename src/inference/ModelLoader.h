/**
 * @file ModelLoader.h
 * @brief Robust GGUF model loader with validation and error handling
 * 
 * Part of Phase 3: Real GGML Integration
 * Provides safe, validated model loading with comprehensive error reporting.
 * 
 * @copyright RawrXD 2026
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

// Include ModelArchitecture definition
#include "GGMLBackend.h"

namespace RawrXD {
namespace Inference {

// ModelArchitecture is now included from GGMLBackend.h

/**
 * @brief Model loading configuration
 */
struct ModelLoadConfig {
    // Path settings
    std::string modelPath;           ///< Path to GGUF file
    std::string cachePath;           ///< Optional cache directory
    
    // Loading options
    bool useMemoryMapping = true;    ///< Use mmap for loading
    bool validateChecksums = false;  ///< Validate SHA256 checksums
    bool verifyTensors = true;       ///< Verify tensor integrity
    
    // Resource limits
    size_t maxModelSize = 0;         ///< 0 = unlimited (bytes)
    size_t maxTensorSize = 0;        ///< 0 = unlimited (bytes)
    int maxLayers = 0;                 ///< 0 = unlimited
    
    // Progress callback
    std::function<void(float progress, const std::string& stage)> progressCallback;
};

/**
 * @brief Model load result
 */
struct ModelLoadResult {
    bool success = false;            ///< Loading succeeded
    std::string errorMessage;        ///< Error details if failed
    
    // Loaded model info
    ModelArchitecture architecture;  ///< Model architecture
    size_t modelSize = 0;            ///< Total model size in bytes
    size_t tensorCount = 0;        ///< Number of tensors loaded
    
    // Timing
    int64_t loadTimeMs = 0;          ///< Total load time
    int64_t validationTimeMs = 0;    ///< Validation time
    
    // Warnings
    std::vector<std::string> warnings; ///< Non-fatal warnings
};

/**
 * @brief Model validation result
 */
struct ValidationResult {
    bool valid = false;              ///< Model is valid
    std::vector<std::string> errors;   ///< Validation errors
    std::vector<std::string> warnings; ///< Validation warnings
    
    // Details
    size_t checkedTensors = 0;
    size_t failedTensors = 0;
};

/**
 * @brief Robust GGUF model loader
 * 
 * Handles safe loading of GGUF models with:
 * - File validation and integrity checks
 * - Memory-mapped or buffered loading
 * - Progress reporting
 * - Comprehensive error handling
 */
class ModelLoader {
public:
    /**
     * @brief Create a new model loader
     * @return Unique pointer to loader instance
     */
    static std::unique_ptr<ModelLoader> Create();
    
    /**
     * @brief Destructor
     */
    ~ModelLoader();
    
    /**
     * @brief Load a model from file
     * @param config Load configuration
     * @return Load result with status and metadata
     */
    ModelLoadResult Load(const ModelLoadConfig& config);
    
    /**
     * @brief Validate a model file without loading
     * @param path Path to GGUF file
     * @return Validation result
     */
    ValidationResult Validate(const std::string& path);
    
    /**
     * @brief Get the last error message
     * @return Error string (empty if no error)
     */
    std::string GetLastError() const;
    
    /**
     * @brief Clear the last error
     */
    void ClearError();
    
    /**
     * @brief Check if a file is a valid GGUF
     * @param path File path to check
     * @return true if valid GGUF file
     */
    static bool IsValidGGUF(const std::string& path);
    
    /**
     * @brief Get GGUF version from file
     * @param path File path
     * @return Version number (0 if invalid)
     */
    static uint32_t GetGGUFVersion(const std::string& path);
    
    /**
     * @brief Get model metadata without loading tensors
     * @param path File path
     * @return Architecture info (empty if failed)
     */
    static ModelArchitecture PeekMetadata(const std::string& path);

private:
    ModelLoader();
    
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace Inference
} // namespace RawrXD
