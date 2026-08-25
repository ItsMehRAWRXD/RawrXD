// ============================================================================
// ExecutionContract.hpp — Unified Sovereign Execution Contract
// ============================================================================
// War Room: One request format, one result format. No subsystem talks directly.
//
// ExecutionRequest ──→ SovereignRuntime ──→ ExecutionResult
//                           │
//     ┌─────────────┬───────┼───────┬─────────────┐
//     ↓             ↓       ↓       ↓             ↓
//   GGUF Loader  Tokenizer  Tensor  Kernel Registry  Sampler
//     │             │        │       │                │
//     └─────────────┴───────┼───────┴────────────────┘
//                           ↓
//                    Agentic Controller
//                           │
//              ┌────────────┼────────────┐
//              ↓            ↓            ↓
//          Planner      Recovery      Evidence
//              │        System        Engine
//              └────────────┼────────────┘
//                           ↓
//                    Certification Bundle
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <optional>
#include <variant>
#include <memory>
#include <functional>

#include "nlohmann/json.hpp"

namespace RawrXD {
namespace Sovereign {

// ============================================================================
// Execution Request — Single Entry Point
// ============================================================================
struct ExecutionRequest {
    // Model configuration
    std::string modelPath;
    std::string modelFormat = "GGUF";  // GGUF, ONNX, etc.
    
    // Input
    std::string prompt;
    std::vector<uint32_t> tokenizedInput;  // Optional: pre-tokenized
    
    // Generation parameters
    uint32_t maxTokens = 512;
    float temperature = 0.7f;
    float topP = 0.9f;
    uint32_t topK = 40;
    float repeatPenalty = 1.1f;
    uint32_t seed = 0;               // 0 = random (non-deterministic)
    bool deterministic = false;      // true = greedy argmax, ignores temperature/topP/topK
    
    // Backend selection
    enum class Backend {
        AUTO,           // Detect best available
        CPU_AVX2,       // x86 AVX2
        CPU_AVX512,     // x86 AVX512
        VULKAN_AMD,     // AMD Vulkan/ROCm
        VULKAN_NVIDIA,  // NVIDIA Vulkan
        CUDA,           // NVIDIA CUDA
        METAL           // Apple Metal
    };
    Backend backend = Backend::AUTO;
    
    // Execution mode
    enum class Mode {
        INFERENCE,      // Single generation
        AGENTIC,        // Autonomous agent loop
        VALIDATED       // Full validation + evidence
    };
    Mode mode = Mode::INFERENCE;
    
    // Validation settings (for VALIDATED mode)
    bool validateKernels = true;
    bool validateNumerics = true;
    bool captureTelemetry = true;
    bool enableRecovery = true;
    std::string evidenceDirectory = "validation/runs";
    
    // Agentic settings (for AGENTIC mode)
    uint32_t maxAgentIterations = 10;
    std::string agentGoal;  // If empty, uses prompt
    bool enableCodeExecution = false;

    // B009: benchmark override for prefill token count (0 = disabled)
    int benchmarkT = 0;
    
    // Metadata
    std::string runId;  // Auto-generated if empty
    std::string userTag;
    std::map<std::string, std::string> metadata;
    
    // Serialization
    nlohmann::json toJson() const;
    static ExecutionRequest fromJson(const nlohmann::json& j);
    std::string toJsonString() const;
    static ExecutionRequest fromJsonString(const std::string& s);
};

// ============================================================================
// Execution Result — Single Exit Point
// ============================================================================
struct ExecutionResult {
    // Status
    enum class Status {
        SUCCESS,
        PARTIAL_SUCCESS,  // Completed with warnings
        FAILED_SETUP,     // Failed before execution
        FAILED_RUNTIME,   // Failed during execution
        FAILED_RECOVERY,  // Failed, recovery attempted but failed
        ABORTED           // User/system abort
    };
    Status status = Status::FAILED_SETUP;
    std::string statusMessage;
    
    // Output
    std::string generatedText;
    std::vector<uint32_t> generatedTokens;
    std::vector<float> tokenLogProbs;
    
    // Timing
    struct TimingInfo {
        std::chrono::milliseconds totalMs{0};
        std::chrono::milliseconds loadMs{0};
        std::chrono::milliseconds tokenizeMs{0};
        std::chrono::milliseconds inferenceMs{0};
        std::chrono::milliseconds samplingMs{0};
        std::chrono::milliseconds agenticMs{0};
        std::chrono::milliseconds recoveryMs{0};
        
        float tokensPerSecond = 0.0f;
        float timeToFirstToken = 0.0f;
        
        nlohmann::json toJson() const;
    };
    TimingInfo timing;
    
    // Telemetry
    struct TelemetryInfo {
        uint32_t tokensGenerated = 0;
        uint32_t tokensPrompt = 0;
        uint64_t memoryPeakBytes = 0;
        uint64_t memoryCurrentBytes = 0;
        uint32_t kernelCalls = 0;
        uint32_t cacheHits = 0;
        uint32_t cacheMisses = 0;
        
        // Agentic telemetry
        uint32_t agentIterations = 0;
        uint32_t codeBlocksGenerated = 0;
        uint32_t testsExecuted = 0;
        
        // Recovery telemetry
        uint32_t faultsDetected = 0;
        uint32_t recoveriesAttempted = 0;
        uint32_t recoveriesSuccessful = 0;
        float mttdMs = 0.0f;  // Mean Time To Detect
        float mttrMs = 0.0f;   // Mean Time To Recover
        
        nlohmann::json toJson() const;
    };
    TelemetryInfo telemetry;
    
    // Cryptographic Evidence
    struct EvidenceInfo {
        std::string runId;
        std::string modelHash;      // SHA256 of model file
        std::string executionHash;  // Hash of execution trace
        std::string outputHash;     // Hash of generated output
        std::string certificateId;  // Sovereign certificate ID
        
        // Component hashes
        std::map<std::string, std::string> kernelHashes;
        std::map<std::string, std::string> tensorManifest;
        
        // Validation results
        bool kernelValidationPassed = false;
        bool numericValidationPassed = false;
        bool recoveryValidationPassed = false;
        
        nlohmann::json toJson() const;
    };
    EvidenceInfo evidence;
    
    // Artifact paths (for VALIDATED mode)
    std::map<std::string, std::string> artifactPaths;
    
    // Error details (if failed)
    struct ErrorInfo {
        std::string category;      // "SETUP", "RUNTIME", "RECOVERY", "VALIDATION"
        std::string component;     // Which subsystem failed
        std::string message;
        std::string stackTrace;
        nlohmann::json context;    // Additional context
        
        nlohmann::json toJson() const;
    };
    std::optional<ErrorInfo> error;
    
    // Full serialization
    nlohmann::json toJson() const;
    std::string toJsonString() const;
    
    // Quick checks
    bool success() const { return status == Status::SUCCESS; }
    bool failed() const { return status == Status::FAILED_SETUP || 
                                  status == Status::FAILED_RUNTIME ||
                                  status == Status::FAILED_RECOVERY; }
    bool hasEvidence() const { return !evidence.certificateId.empty(); }
};

// ============================================================================
// Sovereign Runtime — The Spine
// ============================================================================
class SovereignRuntime {
public:
    static SovereignRuntime& instance();
    
    // Main entry point
    ExecutionResult execute(const ExecutionRequest& request);
    
    // Async execution
    using ProgressCallback = std::function<void(const std::string& stage, float progress)>;
    using TokenCallback = std::function<void(const std::string& token)>;
    
    ExecutionResult executeAsync(const ExecutionRequest& request,
                                  ProgressCallback progress = nullptr,
                                  TokenCallback tokenOut = nullptr);
    
    // Configuration
    void setDefaultBackend(ExecutionRequest::Backend backend);
    void setValidationEnabled(bool enabled);
    void setRecoveryEnabled(bool enabled);
    
    // Status
    bool isReady() const;
    std::vector<ExecutionRequest::Backend> availableBackends() const;
    
    // Evidence bundle generation
    bool generateEvidenceBundle(const ExecutionResult& result, 
                                 const std::string& directory);
    
private:
    SovereignRuntime() = default;
    ~SovereignRuntime() = default;
    
    // Subsystem execution phases
    ExecutionResult executeSetup(const ExecutionRequest& req);
    ExecutionResult executeLoad(const ExecutionRequest& req);
    ExecutionResult executeTokenize(const ExecutionRequest& req);
    ExecutionResult executeInference(const ExecutionRequest& req);
    ExecutionResult executeSampling(const ExecutionRequest& req);
    ExecutionResult executeAgentic(const ExecutionRequest& req);
    ExecutionResult executeValidation(const ExecutionRequest& req);
    
    // Recovery
    ExecutionResult attemptRecovery(const ExecutionRequest& req, 
                                     const ExecutionResult& failed);
    
    // Evidence
    void collectEvidence(ExecutionResult& result);
    void generateCertificate(ExecutionResult& result);
    
    bool m_validationEnabled = true;
    bool m_recoveryEnabled = true;
    ExecutionRequest::Backend m_defaultBackend = ExecutionRequest::Backend::AUTO;
};

// ============================================================================
// Convenience API
// ============================================================================
inline ExecutionResult RunInference(const std::string& modelPath, 
                                     const std::string& prompt,
                                     uint32_t maxTokens = 512,
                                     int benchmarkT = 0) {
    ExecutionRequest req;
    req.modelPath = modelPath;
    req.prompt = prompt;
    req.maxTokens = maxTokens;
    req.benchmarkT = benchmarkT;
    req.mode = ExecutionRequest::Mode::INFERENCE;
    return SovereignRuntime::instance().execute(req);
}

inline ExecutionResult RunAgentic(const std::string& modelPath,
                                   const std::string& goal,
                                   uint32_t maxIterations = 10) {
    ExecutionRequest req;
    req.modelPath = modelPath;
    req.prompt = goal;
    req.agentGoal = goal;
    req.maxAgentIterations = maxIterations;
    req.mode = ExecutionRequest::Mode::AGENTIC;
    return SovereignRuntime::instance().execute(req);
}

inline ExecutionResult RunValidated(const std::string& modelPath,
                                     const std::string& prompt,
                                     const std::string& evidenceDir = "validation/runs") {
    ExecutionRequest req;
    req.modelPath = modelPath;
    req.prompt = prompt;
    req.mode = ExecutionRequest::Mode::VALIDATED;
    req.evidenceDirectory = evidenceDir;
    req.validateKernels = true;
    req.validateNumerics = true;
    req.captureTelemetry = true;
    req.enableRecovery = true;
    return SovereignRuntime::instance().execute(req);
}

} // namespace Sovereign
} // namespace RawrXD
