#pragma once
#ifndef HOTPATCH_CAPABILITY_HPP
#define HOTPATCH_CAPABILITY_HPP

/**
 * @file hotpatch_capability.hpp
 * @brief Model capability detection for hotpatch support
 * 
 * Some models support real-time output correction (hotpatching) while others don't.
 * This module provides feature detection to determine if hotpatching should be
 * attempted for a given model.
 * 
 * Models that DON'T support hotpatching:
 * - External API models (OpenAI, Anthropic, etc.) with strict output formats
 * - Models with signed responses that can't be modified
 * - Streaming-only models that don't buffer complete outputs
 * - Models running in read-only or sandboxed environments
 * 
 * Models that DO support hotpatching:
 * - Local GGUF models loaded through RawrXD's loader
 * - Models with interceptable output pipelines
 * - Models supporting the correction protocol
 */

#include <string>
#include <vector>
#include <cstdint>

namespace RawrXD::Hotpatch {

/// Hotpatch capability flags
enum class HotpatchCapability : uint32_t {
    NONE = 0,
    OUTPUT_INTERCEPTION = 1 << 0,       // Can intercept model output
    OUTPUT_MODIFICATION = 1 << 1,       // Can modify/correct output
    HALLUCINATION_DETECTION = 1 << 2,   // Supports hallucination detection
    NAVIGATION_CORRECTION = 1 << 3,     // Supports navigation path correction
    BEHAVIOR_PATCHING = 1 << 4,         // Supports behavior patches
    REAL_TIME_CORRECTION = 1 << 5,      // Supports real-time corrections
    STREAMING_PATCHES = 1 << 6,         // Can patch streaming outputs
    CORRECTION_FEEDBACK = 1 << 7,       // Model can receive correction feedback
    
    // Common capability combinations
    BASIC = OUTPUT_INTERCEPTION | OUTPUT_MODIFICATION,
    STANDARD = BASIC | HALLUCINATION_DETECTION | NAVIGATION_CORRECTION,
    FULL = STANDARD | BEHAVIOR_PATCHING | REAL_TIME_CORRECTION | STREAMING_PATCHES | CORRECTION_FEEDBACK
};

/// Model type classification for hotpatch support
enum class ModelHotpatchType {
    UNKNOWN,            // Not yet classified
    UNSUPPORTED,        // Known to not support hotpatching
    LOCAL_GGUF,         // Local GGUF model - full support
    LOCAL_OTHER,        // Other local model - partial support
    EXTERNAL_API,       // External API - no support
    PROXY_INTERCEPT,    // Proxied through intercept layer
    SANDBOXED,          // Sandboxed - limited support
    READ_ONLY           // Read-only mode - no modifications allowed
};

/// Model hotpatch metadata
struct ModelHotpatchInfo {
    std::string modelId;                    // Unique model identifier
    std::string modelName;                  // Human-readable name
    ModelHotpatchType type{ModelHotpatchType::UNKNOWN};
    uint32_t capabilities{0};               // Bitfield of HotpatchCapability
    
    // Feature limits
    size_t maxPatchSize{0};                 // Maximum patch size in bytes
    size_t maxPatchesPerSession{0};        // Maximum patches per session
    std::chrono::milliseconds patchTimeout{0}; // Timeout for patch operations
    
    // Status
    bool isAvailable{false};                // Hotpatch service available
    bool isEnabled{false};                  // Hotpatching enabled for this model
    std::string lastError;                  // Last error message
    
    // Statistics
    uint32_t patchesApplied{0};
    uint32_t patchesFailed{0};
    uint32_t correctionsMade{0};
};

/// Capability checker for model hotpatch support
class HotpatchCapabilityChecker {
public:
    HotpatchCapabilityChecker();
    ~HotpatchCapabilityChecker();
    
    // Check if a model supports hotpatching
    static bool supportsHotpatching(const std::string& modelId);
    static bool supportsHotpatching(const std::string& modelId, HotpatchCapability capability);
    
    // Get full capability info for a model
    static ModelHotpatchInfo getModelInfo(const std::string& modelId);
    
    // Classify model type based on ID/path
    static ModelHotpatchType classifyModel(const std::string& modelId);
    
    // Check specific capabilities
    static bool canInterceptOutput(const std::string& modelId);
    static bool canModifyOutput(const std::string& modelId);
    static bool supportsHallucinationDetection(const std::string& modelId);
    static bool supportsNavigationCorrection(const std::string& modelId);
    static bool supportsBehaviorPatching(const std::string& modelId);
    static bool supportsRealtimeCorrection(const std::string& modelId);
    
    // Enable/disable hotpatching for a model
    static void setHotpatchEnabled(const std::string& modelId, bool enabled);
    static bool isHotpatchEnabled(const std::string& modelId);
    
    // Get list of models that support hotpatching
    static std::vector<std::string> getHotpatchableModels();
    
    // Register a model's capabilities
    static void registerModelCapabilities(const std::string& modelId, 
                                           ModelHotpatchType type,
                                           uint32_t capabilities);
    
    // Clear cached info
    static void clearCache();
    
private:
    static std::unordered_map<std::string, ModelHotpatchInfo> s_modelCache;
    static std::mutex s_cacheMutex;
    
    // Detection helpers
    static bool isLocalGGUFModel(const std::string& modelId);
    static bool isExternalAPIModel(const std::string& modelId);
    static bool isProxiedModel(const std::string& modelId);
    static uint32_t detectCapabilities(const std::string& modelId, ModelHotpatchType type);
};

/// RAII guard for conditional hotpatching
class ConditionalHotpatchGuard {
public:
    explicit ConditionalHotpatchGuard(const std::string& modelId);
    ~ConditionalHotpatchGuard();
    
    bool canHotpatch() const { return m_canHotpatch; }
    operator bool() const { return m_canHotpatch; }
    
    const ModelHotpatchInfo& getInfo() const { return m_info; }
    
private:
    std::string m_modelId;
    bool m_canHotpatch;
    ModelHotpatchInfo m_info;
};

/// Helper to conditionally apply hotpatching
template<typename Func>
auto withHotpatchCheck(const std::string& modelId, Func&& func) -> decltype(func()) {
    ConditionalHotpatchGuard guard(modelId);
    if (guard) {
        return func();
    }
    // Return default-constructed result if hotpatching not supported
    using ReturnType = decltype(func());
    if constexpr (!std::is_void_v<ReturnType>) {
        return ReturnType{};
    }
}

} // namespace RawrXD::Hotpatch

#endif // HOTPATCH_CAPABILITY_HPP
