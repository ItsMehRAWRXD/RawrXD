#pragma once
// ============================================================================
// ExecutionContract.hpp — Sovereign Execution Contract Types
// Defines ExecutionRequest, ExecutionResult, and SovereignRuntime interface.
// ============================================================================
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace RawrXD {
namespace Sovereign {

// ============================================================================
// ExecutionRequest — describes an inference session request
// ============================================================================
struct ExecutionRequest {
    enum class Backend : int {
        AUTO = 0,
        CPU_AVX2 = 1,
        CPU_AVX512 = 2,
        VULKAN_AMD = 3,
        VULKAN_NVIDIA = 4,
        CUDA = 5,
        METAL = 6,
    };

    enum class Mode : int {
        INFERENCE = 0,
        AGENTIC = 1,
        VALIDATED = 2,
    };

    // Model / session
    std::string modelPath;
    std::string modelFormat;
    std::string prompt;

    // Generation
    int32_t maxTokens = 512;
    float temperature = 0.7f;
    float topP = 0.9f;
    int32_t topK = 40;
    float repeatPenalty = 1.1f;

    // Execution
    Backend backend = Backend::AUTO;
    Mode mode = Mode::INFERENCE;

    // Validation / evidence
    bool validateKernels = true;
    bool validateNumerics = true;
    bool captureTelemetry = true;
    bool enableRecovery = true;
    std::string evidenceDirectory = "validation/runs";

    // Agentic (used only when mode == AGENTIC)
    int32_t maxAgentIterations = 10;
    std::string agentGoal;
    bool enableCodeExecution = false;

    // Metadata / identity
    std::string runId;
    std::string userTag;
    std::map<std::string,std::string> metadata;
    std::vector<int32_t> tokenizedInput;

    // Serialization
    nlohmann::json toJson() const;
    static ExecutionRequest fromJson(const nlohmann::json& j);
    std::string toJsonString() const;
    static ExecutionRequest fromJsonString(const std::string& s);
};

// ============================================================================
// ExecutionResult — describes the result of an execution session
// ============================================================================
struct ExecutionResult {
    // Nested info structs
    struct TimingInfo {
        std::chrono::milliseconds totalMs{0};
        std::chrono::milliseconds loadMs{0};
        std::chrono::milliseconds tokenizeMs{0};
        std::chrono::milliseconds inferenceMs{0};
        std::chrono::milliseconds samplingMs{0};
        std::chrono::milliseconds agenticMs{0};
        std::chrono::milliseconds recoveryMs{0};
        double tokensPerSecond = 0.0;
        double timeToFirstToken = 0.0;

        nlohmann::json toJson() const;
    };

    struct TelemetryInfo {
        uint32_t tokensGenerated = 0;
        uint32_t tokensPrompt = 0;
        uint64_t memoryPeakBytes = 0;
        uint64_t memoryCurrentBytes = 0;
        uint64_t kernelCalls = 0;
        uint64_t cacheHits = 0;
        uint64_t cacheMisses = 0;
        uint32_t agentIterations = 0;
        uint32_t codeBlocksGenerated = 0;
        uint32_t testsExecuted = 0;
        uint32_t faultsDetected = 0;
        uint32_t recoveriesAttempted = 0;
        uint32_t recoveriesSuccessful = 0;
        double mttdMs = 0.0;  // mean time to detection
        double mttrMs = 0.0;  // mean time to recovery

        nlohmann::json toJson() const;
    };

    struct EvidenceInfo {
        std::string runId;
        std::string modelHash;
        std::string executionHash;
        std::string outputHash;
        std::string certificateId;
        std::map<std::string,std::string> kernelHashes;
        std::map<std::string,std::string> tensorManifest;
        bool kernelValidationPassed = false;
        bool numericValidationPassed = false;
        bool recoveryValidationPassed = false;

        nlohmann::json toJson() const;
    };

    struct ErrorInfo {
        std::string category;
        std::string component;
        std::string message;
        std::string stackTrace;
        nlohmann::json context;

        nlohmann::json toJson() const;
    };

    enum class Status : int {
        SUCCESS = 0,
        PARTIAL_SUCCESS = 1,
        FAILED_SETUP = 2,
        FAILED_RUNTIME = 3,
        FAILED_RECOVERY = 4,
        ABORTED = 5,
    };

    // Core
    Status status = Status::SUCCESS;
    std::string statusMessage;

    // Output
    std::string generatedText;
    std::vector<uint32_t> generatedTokens;
    std::vector<float> tokenLogProbs;

    // Instrumentation
    TimingInfo timing;
    TelemetryInfo telemetry;
    EvidenceInfo evidence;
    std::map<std::string,std::string> artifactPaths;

    // Error (optional — set only on failure)
    std::optional<ErrorInfo> error;

    // Helpers
    bool failed() const { return status != Status::SUCCESS; }
    bool success() const { return status == Status::SUCCESS; }

    nlohmann::json toJson() const;
    std::string toJsonString() const;
};

// ============================================================================
// SovereignRuntime — the sovereign execution spine
// ============================================================================

using ProgressCallback = std::function<void(const std::string&, float)>;
using TokenCallback    = std::function<void(int32_t)>;

class SovereignRuntime {
public:
    static SovereignRuntime& instance();

    // Configuration
    void setDefaultBackend(ExecutionRequest::Backend backend);
    void setValidationEnabled(bool enabled);
    void setRecoveryEnabled(bool enabled);

    // Status
    bool isReady() const;
    std::vector<ExecutionRequest::Backend> availableBackends() const;

    // Synchronous execution
    ExecutionResult execute(const ExecutionRequest& request);

    // Asynchronous execution (delegates to execute with progress reporting)
    ExecutionResult executeAsync(const ExecutionRequest& request,
                                 ProgressCallback progress = nullptr,
                                 TokenCallback tokenOut = nullptr);

    // Evidence bundle
    bool generateEvidenceBundle(const ExecutionResult& result,
                                const std::string& directory);

private:
    // Phase implementations (private — called by execute())
    ExecutionResult executeSetup(const ExecutionRequest& req);
    ExecutionResult executeLoad(const ExecutionRequest& req);
    ExecutionResult executeTokenize(const ExecutionRequest& req);
    ExecutionResult executeInference(const ExecutionRequest& req);
    ExecutionResult executeSampling(const ExecutionRequest& req);
    ExecutionResult executeAgentic(const ExecutionRequest& req);
    ExecutionResult executeValidation(const ExecutionRequest& req);
    ExecutionResult attemptRecovery(const ExecutionRequest& req,
                                    const ExecutionResult& failed);

    // Evidence
    void collectEvidence(ExecutionResult& result);
    void generateCertificate(ExecutionResult& result);
    void generateEvidenceBundleImpl(const ExecutionResult& result,
                                    const std::string& directory,
                                    bool& ok);

    // State
    ExecutionRequest::Backend m_defaultBackend = ExecutionRequest::Backend::CPU_AVX2;
    bool m_validationEnabled = true;
    bool m_recoveryEnabled = true;
};

} // namespace Sovereign
} // namespace RawrXD
