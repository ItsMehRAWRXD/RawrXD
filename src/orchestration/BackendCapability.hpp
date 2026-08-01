// src/orchestration/BackendCapability.hpp
// Backend feature negotiation — each driver declares what it supports,
// and the BackendManager negotiates the best match for any given task.

#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>

// ---------------------------------------------------------------------------
// Individual feature flags (bitmask)
// ---------------------------------------------------------------------------
enum class BackendFeature : uint64_t {
    None          = 0x0000000000000000,
    BUILD_CPP     = 0x0000000000000001,  // cl.exe / MSVC C++ compilation
    BUILD_ASM     = 0x0000000000000002,  // ml64.exe MASM assembly
    GPU_VULKAN    = 0x0000000000000004,  // Vulkan compute dispatch
    GPU_HIP       = 0x0000000000000008,  // AMD HIP dispatch
    TELEMETRY     = 0x0000000000000010,  // Live CPU/GPU/VRAM metrics
    AUDIT         = 0x0000000000000020,  // Static analysis / code audit
    REMOTE        = 0x0000000000000040,  // Remote build farm connectivity
    SANDBOX       = 0x0000000000000080,  // Isolated execution sandbox
    INFERENCE     = 0x0000000000000100,  // Model inference execution
    TOKENIZER     = 0x0000000000000200,  // BPE / tokenizer operations
    AGENT_PIPELINE= 0x0000000000000400,  // Planner→Coder→Reflector loop
    CERTIFICATION = 0x0000000000000800,  // Build certification / signing
    NETWORK       = 0x0000000000001000,  // Outbound network access
    FILESYSTEM    = 0x0000000000002000,  // Full filesystem access
    ADMIN        = 0x0000000000004000,  // Administrator elevation
    All           = 0xFFFFFFFFFFFFFFFF
};

inline BackendFeature operator|(BackendFeature a, BackendFeature b) {
    return static_cast<BackendFeature>(
        static_cast<uint64_t>(a) | static_cast<uint64_t>(b));
}
inline BackendFeature operator&(BackendFeature a, BackendFeature b) {
    return static_cast<BackendFeature>(
        static_cast<uint64_t>(a) & static_cast<uint64_t>(b));
}
inline bool HasFeature(BackendFeature flags, BackendFeature feature) {
    return (static_cast<uint64_t>(flags) & static_cast<uint64_t>(feature)) != 0;
}

// ---------------------------------------------------------------------------
// Capability set — what a backend can do
// ---------------------------------------------------------------------------
struct BackendCapabilitySet {
    BackendFeature features = BackendFeature::None;
    std::string    label;       // Human-readable summary
    int            priority;    // 0=fallback, 1=preferred, 2=primary

    bool Supports(BackendFeature f) const { return HasFeature(features, f); }

    std::vector<std::string> SupportedFeatures() const {
        std::vector<std::string> out;
        if (Supports(BackendFeature::BUILD_CPP))      out.push_back("BUILD_CPP");
        if (Supports(BackendFeature::BUILD_ASM))      out.push_back("BUILD_ASM");
        if (Supports(BackendFeature::GPU_VULKAN))     out.push_back("GPU_VULKAN");
        if (Supports(BackendFeature::GPU_HIP))        out.push_back("GPU_HIP");
        if (Supports(BackendFeature::TELEMETRY))      out.push_back("TELEMETRY");
        if (Supports(BackendFeature::AUDIT))          out.push_back("AUDIT");
        if (Supports(BackendFeature::REMOTE))         out.push_back("REMOTE");
        if (Supports(BackendFeature::SANDBOX))        out.push_back("SANDBOX");
        if (Supports(BackendFeature::INFERENCE))      out.push_back("INFERENCE");
        if (Supports(BackendFeature::TOKENIZER))      out.push_back("TOKENIZER");
        if (Supports(BackendFeature::AGENT_PIPELINE)) out.push_back("AGENT_PIPELINE");
        if (Supports(BackendFeature::CERTIFICATION))  out.push_back("CERTIFICATION");
        if (Supports(BackendFeature::NETWORK))        out.push_back("NETWORK");
        if (Supports(BackendFeature::FILESYSTEM))     out.push_back("FILESYSTEM");
        if (Supports(BackendFeature::ADMIN))          out.push_back("ADMIN");
        return out;
    }
};

// ---------------------------------------------------------------------------
// Negotiation result — returned when selecting a backend for a task
// ---------------------------------------------------------------------------
struct CapabilityNegotiationResult {
    bool                compatible = false;
    BackendCapabilitySet negotiatedCapabilities;
    std::vector<BackendFeature> missingFeatures;
    std::string         reason;
};

// ---------------------------------------------------------------------------
// Predefined capability profiles for each backend type
// ---------------------------------------------------------------------------
struct BackendCapabilityProfiles {
    static BackendCapabilitySet ForPowerShell() {
        BackendCapabilitySet caps;
        caps.features = BackendFeature::BUILD_CPP
                      | BackendFeature::BUILD_ASM
                      | BackendFeature::AUDIT
                      | BackendFeature::TELEMETRY
                      | BackendFeature::NETWORK;
        caps.label    = "Script-driven automation with Win32 pipe bridge";
        caps.priority = 1;
        return caps;
    }

    static BackendCapabilitySet ForBareMetal() {
        BackendCapabilitySet caps;
        caps.features = BackendFeature::BUILD_CPP
                      | BackendFeature::BUILD_ASM
                      | BackendFeature::GPU_VULKAN
                      | BackendFeature::INFERENCE
                      | BackendFeature::TOKENIZER
                      | BackendFeature::AGENT_PIPELINE
                      | BackendFeature::CERTIFICATION
                      | BackendFeature::FILESYSTEM;
        caps.label    = "Direct Win32 process execution, zero-dependency";
        caps.priority = 2;
        return caps;
    }

    static BackendCapabilitySet ForRemoteAgent() {
        BackendCapabilitySet caps;
        caps.features = BackendFeature::BUILD_CPP
                      | BackendFeature::BUILD_ASM
                      | BackendFeature::REMOTE
                      | BackendFeature::CERTIFICATION;
        caps.label    = "Remote build farm with artifact signing";
        caps.priority = 1;
        return caps;
    }

    static BackendCapabilitySet ForSandbox() {
        BackendCapabilitySet caps;
        caps.features = BackendFeature::BUILD_CPP
                      | BackendFeature::BUILD_ASM
                      | BackendFeature::SANDBOX
                      | BackendFeature::AUDIT;
        caps.label    = "Isolated sandbox with rollback capability";
        caps.priority = 0;
        return caps;
    }
};

// ---------------------------------------------------------------------------
// Capability matrix — maps backend names to their capability sets
// ---------------------------------------------------------------------------
class BackendCapabilityMatrix {
public:
    std::unordered_map<std::string, BackendCapabilitySet> backendFeatures;

    static BackendCapabilityMatrix BuildDefault() {
        BackendCapabilityMatrix matrix;
        matrix.backendFeatures["PowerShell"]  = BackendCapabilityProfiles::ForPowerShell();
        matrix.backendFeatures["BareMetal"]   = BackendCapabilityProfiles::ForBareMetal();
        matrix.backendFeatures["RemoteAgent"] = BackendCapabilityProfiles::ForRemoteAgent();
        matrix.backendFeatures["Sandbox"]     = BackendCapabilityProfiles::ForSandbox();
        return matrix;
    }

    BackendFeature Get(const std::string& backendName) const {
        auto it = backendFeatures.find(backendName);
        if (it != backendFeatures.end()) return it->second.features;
        return BackendFeature::None;
    }

    std::string Negotiate(BackendFeature required, const std::vector<std::string>& priorityOrder) const {
        for (const auto& name : priorityOrder) {
            auto it = backendFeatures.find(name);
            if (it != backendFeatures.end() && HasFeature(it->second.features, required)) {
                return name;
            }
        }
        return "";
    }
};
