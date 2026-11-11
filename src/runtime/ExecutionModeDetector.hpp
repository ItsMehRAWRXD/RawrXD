/*===========================================================================
 * ExecutionModeDetector.hpp
 * 
 * Detects whether the runtime is using synthetic weights or real GGUF model.
 * 
 * Detection Strategy:
 *   1. Check GGUF magic bytes (0x46554747 = "GGUF")
 *   2. Validate GGUF version (must be >= 3 for compatibility)
 *   3. Verify tensor weights are non-zero (active)
 *   4. Query model loader state (active signal)
 * 
 * This is a header-only design for easy integration into the shared memory
 * server without adding dependencies.
 *===========================================================================*/

#pragma once

#include <cstdint>
#include <cstring>

namespace RawrXD {
namespace Runtime {

// GGUF Header Constants
constexpr uint32_t GGUF_MAGIC = 0x46554747;  // "GGUF" in little-endian
constexpr uint32_t GGUF_VERSION_MIN = 3;     // Minimum supported version
constexpr uint32_t GGUF_VERSION_MAX = 3;     // Maximum supported version

// Execution mode types
enum class ExecutionMode : uint32_t {
    Unknown = 0,
    Synthetic = 1,      // Using synthetic/random weights
    GgufBacked = 2,     // Using real GGUF model weights
    Hybrid = 3          // Mixed mode (some layers synthetic, some real)
};

// Backend capability flags
enum class BackendFlags : uint32_t {
    None = 0,
    AVX2 = 1 << 0,
    AVX512 = 1 << 1,
    Quantized = 1 << 2,     // Using Q4/Q8 quantization
    GPU = 1 << 3,           // GPU acceleration active
    Distributed = 1 << 4    // Multi-node execution
};

// Detection result
struct ExecutionModeInfo {
    ExecutionMode mode;
    BackendFlags backend;
    char modelName[128];
    char quantization[16];   // "F32", "F16", "Q4_0", "Q8_0", etc.
    uint32_t layerCount;
    uint64_t modelSizeBytes;
    bool isValid;            // Detection succeeded
};

// Interface for execution mode detection
class IExecutionModeDetector {
public:
    virtual ~IExecutionModeDetector() = default;
    
    // Detect current execution mode
    virtual ExecutionModeInfo Detect() = 0;
    
    // Check if mode changed since last detection
    virtual bool HasModeChanged() = 0;
    
    // Get last detection result
    virtual const ExecutionModeInfo& GetLastResult() const = 0;
};

// Concrete implementation
class ExecutionModeDetector : public IExecutionModeDetector {
public:
    ExecutionModeDetector();
    ~ExecutionModeDetector() override = default;
    
    ExecutionModeInfo Detect() override;
    bool HasModeChanged() override;
    const ExecutionModeInfo& GetLastResult() const override { return lastResult_; }
    
    // Register callbacks for mode transitions
    using ModeChangeCallback = void(*)(ExecutionMode oldMode, ExecutionMode newMode);
    void SetModeChangeCallback(ModeChangeCallback callback);
    
private:
    ExecutionModeInfo lastResult_;
    ModeChangeCallback callback_;
    
    // Detection helpers
    bool CheckGgufFileMapped();
    bool VerifyTensorWeightsNonZero();
    ExecutionModeInfo QueryModelLoaderState();
    BackendFlags DetectBackendCapabilities();
};

// Helper to convert mode to string
inline const char* ExecutionModeToString(ExecutionMode mode) {
    switch (mode) {
        case ExecutionMode::Synthetic: return "synthetic";
        case ExecutionMode::GgufBacked: return "gguf-backed";
        case ExecutionMode::Hybrid: return "hybrid";
        default: return "unknown";
    }
}

// Helper to convert backend to string
inline const char* BackendToString(BackendFlags flags) {
    if ((uint32_t)flags & (uint32_t)BackendFlags::AVX512) return "Sovereign CPU AVX512";
    if ((uint32_t)flags & (uint32_t)BackendFlags::AVX2) return "Sovereign CPU AVX2";
    if ((uint32_t)flags & (uint32_t)BackendFlags::GPU) return "Sovereign GPU";
    return "Sovereign CPU Scalar";
}

// ============================================================================
// GGUF Header Probe - Zero-dependency detection
// ============================================================================

// GGUF Header structure (first 8 bytes)
// magic (4 bytes) + version (4 bytes)
struct GgufHeaderProbe {
    uint32_t magic;
    uint32_t version;
};

// Probe result
struct GgufProbeResult {
    bool isGguf;           // Magic bytes match
    bool isSupported;      // Version is supported
    uint32_t version;      // Detected version
    const char* error;     // Error message if not supported
};

// Probe a memory-mapped file for GGUF format
// Returns true if the file appears to be a valid GGUF
inline GgufProbeResult ProbeGgufHeader(const void* fileMappingBase, size_t minSize = 8) {
    GgufProbeResult result = {};
    result.isGguf = false;
    result.isSupported = false;
    result.error = nullptr;
    
    if (!fileMappingBase || minSize < sizeof(GgufHeaderProbe)) {
        result.error = "Invalid mapping or size too small";
        return result;
    }
    
    const GgufHeaderProbe* header = static_cast<const GgufHeaderProbe*>(fileMappingBase);
    result.version = header->version;
    
    // Check magic bytes
    if (header->magic != GGUF_MAGIC) {
        result.error = "Magic bytes do not match GGUF";
        return result;
    }
    
    result.isGguf = true;
    
    // Validate version
    if (header->version < GGUF_VERSION_MIN || header->version > GGUF_VERSION_MAX) {
        result.error = "GGUF version not supported";
        return result;
    }
    
    result.isSupported = true;
    return result;
}

// Quick check - just validates magic bytes
inline bool IsGgufFile(const void* fileMappingBase) {
    if (!fileMappingBase) return false;
    const uint32_t* magic = static_cast<const uint32_t*>(fileMappingBase);
    return *magic == GGUF_MAGIC;
}

// ============================================================================
// Static Detection Helper
// ============================================================================

struct ExecutionModeDetector {
    // Probes the model file header for GGUF magic bytes and version
    // Returns GgufBacked if valid GGUF v3, Synthetic otherwise
    static ExecutionMode Detect(const void* fileMappingBase) {
        GgufProbeResult result = ProbeGgufHeader(fileMappingBase);
        if (result.isGguf && result.isSupported) {
            return ExecutionMode::GgufBacked;
        }
        return ExecutionMode::Synthetic;
    }
    
    // Get detailed info about the detection
    static ExecutionModeInfo DetectDetailed(const void* fileMappingBase) {
        ExecutionModeInfo info = {};
        info.mode = ExecutionMode::Synthetic;
        info.isValid = false;
        
        GgufProbeResult result = ProbeGgufHeader(fileMappingBase);
        
        if (result.isGguf && result.isSupported) {
            info.mode = ExecutionMode::GgufBacked;
            info.isValid = true;
            strncpy_s(info.modelName, sizeof(info.modelName), "GGUF-v3-Model", _TRUNCATE);
        } else if (result.isGguf) {
            // GGUF but unsupported version
            info.mode = ExecutionMode::Unknown;
            info.isValid = false;
            strncpy_s(info.modelName, sizeof(info.modelName), "GGUF-Unsupported", _TRUNCATE);
        }
        
        return info;
    }
};

} // namespace Runtime
} // namespace RawrXD
