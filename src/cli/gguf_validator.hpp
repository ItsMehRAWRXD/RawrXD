// ============================================================================
// RawrXD GGUF Validator - Phase 6
// ============================================================================
// Pre-hotpatch validation for GGUF model files
// - Magic number verification
// - Version compatibility check
// - Tensor metadata validation
// - Architecture detection
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <expected>

namespace RawrXD {

// Validation error types
enum class GGUFValidationError {
    Success = 0,
    FileNotFound,
    FileNotReadable,
    InvalidMagic,
    UnsupportedVersion,
    CorruptedHeader,
    MissingTensors,
    InvalidTensorMetadata,
    ArchitectureMismatch,
    InsufficientFileSize
};

// Validation result
struct GGUFValidationResult {
    bool valid = false;
    GGUFValidationError error = GGUFValidationError::Success;
    std::string errorMessage;
    
    // File info (if valid)
    uint32_t version = 0;
    uint64_t tensorCount = 0;
    uint64_t metadataKVCount = 0;
    std::string architecture;
    std::string modelName;
    uint64_t totalFileSize = 0;
    uint64_t tensorDataSize = 0;
    
    // Tensor summary
    struct TensorInfo {
        std::string name;
        uint64_t size;
        uint32_t type;
    };
    std::vector<TensorInfo> tensors;
};

// GGUF Validator class
class GGUFValidator {
public:
    // Quick validation - just header/magic (fast)
    static std::expected<bool, GGUFValidationError> QuickValidate(const std::string& filepath);
    
    // Full validation - complete file analysis (slower)
    static GGUFValidationResult FullValidate(const std::string& filepath);
    
    // Validation with size limits (for large files)
    static GGUFValidationResult ValidateWithLimits(
        const std::string& filepath,
        uint64_t maxMetadataSize = 10 * 1024 * 1024,  // 10MB
        uint64_t maxTensorCount = 10000
    );
    
    // Error to string
    static const char* ErrorToString(GGUFValidationError error);
    
    // Version compatibility check
    static bool IsVersionSupported(uint32_t version);
    
    // Phase 6.6: Architecture extraction and compatibility
    static std::string ExtractArchitecture(const std::string& filepath);
    static bool ValidateArchitectureCompatibility(const std::string& incomingArch, const std::string& activeArch);
    
private:
    static constexpr uint32_t GGUF_MAGIC = 0x46554747; // "GGUF" in little-endian
    static constexpr uint32_t GGUF_VERSION_MIN = 2;
    static constexpr uint32_t GGUF_VERSION_MAX = 3;
    
    // Internal validation helpers
    static bool ValidateMagic(const uint8_t* data, size_t len);
    static bool ValidateVersion(uint32_t version);
    static GGUFValidationResult ParseHeader(const uint8_t* data, size_t len);
};

// C API for MASM/bridge integration
extern "C" {
    // Returns 1 if valid, 0 if invalid
    int RawrXD_ValidateGGUFFile(const char* filepath);
    
    // Get validation error message
    const char* RawrXD_GetValidationError(const char* filepath);
    
    // Phase 6.6: Extract architecture string from GGUF
    // Returns architecture string (e.g., "llama", "mistral") or empty string on error
    // Caller must copy the result - pointer is to thread-local buffer
    const char* RawrXD_ExtractGGUFArchitecture(const char* filepath);
}

} // namespace RawrXD
