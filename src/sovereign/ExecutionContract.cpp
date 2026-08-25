// ============================================================================
// ExecutionContract.cpp — Sovereign Execution Contract Implementation
// ============================================================================

// VAL-051.2.B: Real inference integration ENABLED
// swarm_scheduler.hpp dependency resolved - include path fixed in rawrxd_inference.h

#include "sovereign/ExecutionContract.hpp"
#include "cpu_inference_engine.h"  // VAL-051.2.B: Real inference facade
#include "Deep2InferenceWrapper.hpp" // Phase A: isolated Deep2Engine wrapper
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <random>
#include <chrono>

namespace RawrXD {
namespace Sovereign {

// ============================================================================
// ExecutionRequest Implementation
// ============================================================================
nlohmann::json ExecutionRequest::toJson() const {
    nlohmann::json j;
    j["model_path"] = modelPath;
    j["model_format"] = modelFormat;
    j["prompt"] = prompt;
    j["max_tokens"] = maxTokens;
    j["temperature"] = temperature;
    j["top_p"] = topP;
    j["top_k"] = topK;
    j["repeat_penalty"] = repeatPenalty;
    
    // Backend enum
    switch (backend) {
        case Backend::CPU_AVX2: j["backend"] = "CPU_AVX2"; break;
        case Backend::CPU_AVX512: j["backend"] = "CPU_AVX512"; break;
        case Backend::VULKAN_AMD: j["backend"] = "VULKAN_AMD"; break;
        case Backend::VULKAN_NVIDIA: j["backend"] = "VULKAN_NVIDIA"; break;
        case Backend::CUDA: j["backend"] = "CUDA"; break;
        case Backend::METAL: j["backend"] = "METAL"; break;
        default: j["backend"] = "AUTO"; break;
    }
    
    // Mode enum
    switch (mode) {
        case Mode::AGENTIC: j["mode"] = "AGENTIC"; break;
        case Mode::VALIDATED: j["mode"] = "VALIDATED"; break;
        default: j["mode"] = "INFERENCE"; break;
    }
    
    j["validate_kernels"] = validateKernels;
    j["validate_numerics"] = validateNumerics;
    j["capture_telemetry"] = captureTelemetry;
    j["enable_recovery"] = enableRecovery;
    j["evidence_directory"] = evidenceDirectory;
    j["max_agent_iterations"] = maxAgentIterations;
    j["agent_goal"] = agentGoal;
    j["enable_code_execution"] = enableCodeExecution;
    j["run_id"] = runId;
    j["user_tag"] = userTag;
    
    // Convert metadata map to JSON
    nlohmann::json metadataJson;
    for (const auto& pair : metadata) {
        metadataJson[pair.first] = pair.second;
    }
    j["metadata"] = metadataJson;
    
    return j;
}

ExecutionRequest ExecutionRequest::fromJson(const nlohmann::json& j) {
    ExecutionRequest req;
    req.modelPath = j.value("model_path", "");
    req.modelFormat = j.value("model_format", "GGUF");
    req.prompt = j.value("prompt", "");
    req.maxTokens = j.value("max_tokens", 512);
    req.temperature = j.value("temperature", 0.7f);
    req.topP = j.value("top_p", 0.9f);
    req.topK = j.value("top_k", 40);
    req.repeatPenalty = j.value("repeat_penalty", 1.1f);
    
    // Parse backend
    std::string backendStr = j.value("backend", "AUTO");
    if (backendStr == "CPU_AVX2") req.backend = Backend::CPU_AVX2;
    else if (backendStr == "CPU_AVX512") req.backend = Backend::CPU_AVX512;
    else if (backendStr == "VULKAN_AMD") req.backend = Backend::VULKAN_AMD;
    else if (backendStr == "VULKAN_NVIDIA") req.backend = Backend::VULKAN_NVIDIA;
    else if (backendStr == "CUDA") req.backend = Backend::CUDA;
    else if (backendStr == "METAL") req.backend = Backend::METAL;
    else req.backend = Backend::AUTO;
    
    // Parse mode
    std::string modeStr = j.value("mode", "INFERENCE");
    if (modeStr == "AGENTIC") req.mode = Mode::AGENTIC;
    else if (modeStr == "VALIDATED") req.mode = Mode::VALIDATED;
    else req.mode = Mode::INFERENCE;
    
    req.validateKernels = j.value("validate_kernels", true);
    req.validateNumerics = j.value("validate_numerics", true);
    req.captureTelemetry = j.value("capture_telemetry", true);
    req.enableRecovery = j.value("enable_recovery", true);
    req.evidenceDirectory = j.value("evidence_directory", "validation/runs");
    req.maxAgentIterations = j.value("max_agent_iterations", 10);
    req.agentGoal = j.value("agent_goal", "");
    req.enableCodeExecution = j.value("enable_code_execution", false);
    req.runId = j.value("run_id", "");
    req.userTag = j.value("user_tag", "");
    req.metadata = j.value("metadata", nlohmann::json::object()).get<std::map<std::string, std::string>>();
    
    return req;
}

std::string ExecutionRequest::toJsonString() const {
    return toJson().dump(2);
}

ExecutionRequest ExecutionRequest::fromJsonString(const std::string& s) {
    return fromJson(nlohmann::json::parse(s));
}

// ============================================================================
// ExecutionResult::TimingInfo Implementation
// ============================================================================
nlohmann::json ExecutionResult::TimingInfo::toJson() const {
    nlohmann::json j;
    j["total_ms"] = totalMs.count();
    j["load_ms"] = loadMs.count();
    j["tokenize_ms"] = tokenizeMs.count();
    j["inference_ms"] = inferenceMs.count();
    j["sampling_ms"] = samplingMs.count();
    j["agentic_ms"] = agenticMs.count();
    j["recovery_ms"] = recoveryMs.count();
    j["tokens_per_second"] = tokensPerSecond;
    j["time_to_first_token_ms"] = timeToFirstToken;
    return j;
}

// ============================================================================
// ExecutionResult::TelemetryInfo Implementation
// ============================================================================
nlohmann::json ExecutionResult::TelemetryInfo::toJson() const {
    nlohmann::json j;
    j["tokens_generated"] = tokensGenerated;
    j["tokens_prompt"] = tokensPrompt;
    j["memory_peak_bytes"] = memoryPeakBytes;
    j["memory_current_bytes"] = memoryCurrentBytes;
    j["kernel_calls"] = kernelCalls;
    j["cache_hits"] = cacheHits;
    j["cache_misses"] = cacheMisses;
    j["agent_iterations"] = agentIterations;
    j["code_blocks_generated"] = codeBlocksGenerated;
    j["tests_executed"] = testsExecuted;
    j["faults_detected"] = faultsDetected;
    j["recoveries_attempted"] = recoveriesAttempted;
    j["recoveries_successful"] = recoveriesSuccessful;
    j["mttd_ms"] = mttdMs;
    j["mttr_ms"] = mttrMs;
    return j;
}

// ============================================================================
// ExecutionResult::EvidenceInfo Implementation
// ============================================================================
nlohmann::json ExecutionResult::EvidenceInfo::toJson() const {
    nlohmann::json j;
    j["run_id"] = runId;
    j["model_hash"] = modelHash;
    j["execution_hash"] = executionHash;
    j["output_hash"] = outputHash;
    j["certificate_id"] = certificateId;
    
    // Convert maps to JSON
    nlohmann::json kernelHashesJson;
    for (const auto& pair : kernelHashes) {
        kernelHashesJson[pair.first] = pair.second;
    }
    j["kernel_hashes"] = kernelHashesJson;
    
    nlohmann::json tensorManifestJson;
    for (const auto& pair : tensorManifest) {
        tensorManifestJson[pair.first] = pair.second;
    }
    j["tensor_manifest"] = tensorManifestJson;
    
    j["kernel_validation_passed"] = kernelValidationPassed;
    j["numeric_validation_passed"] = numericValidationPassed;
    j["recovery_validation_passed"] = recoveryValidationPassed;
    return j;
}

// ============================================================================
// ExecutionResult::ErrorInfo Implementation
// ============================================================================
nlohmann::json ExecutionResult::ErrorInfo::toJson() const {
    nlohmann::json j;
    j["category"] = category;
    j["component"] = component;
    j["message"] = message;
    j["stack_trace"] = stackTrace;
    j["context"] = context;
    return j;
}

// ============================================================================
// ExecutionResult Implementation
// ============================================================================
nlohmann::json ExecutionResult::toJson() const {
    nlohmann::json j;
    
    // Status
    switch (status) {
        case Status::SUCCESS: j["status"] = "SUCCESS"; break;
        case Status::PARTIAL_SUCCESS: j["status"] = "PARTIAL_SUCCESS"; break;
        case Status::FAILED_SETUP: j["status"] = "FAILED_SETUP"; break;
        case Status::FAILED_RUNTIME: j["status"] = "FAILED_RUNTIME"; break;
        case Status::FAILED_RECOVERY: j["status"] = "FAILED_RECOVERY"; break;
        case Status::ABORTED: j["status"] = "ABORTED"; break;
    }
    j["status_message"] = statusMessage;
    
    // Output
    j["generated_text"] = generatedText;
    j["generated_tokens"] = generatedTokens;
    j["token_log_probs"] = tokenLogProbs;
    
    // Timing
    j["timing"] = timing.toJson();
    
    // Telemetry
    j["telemetry"] = telemetry.toJson();
    
    // Evidence
    j["evidence"] = evidence.toJson();
    
    // Artifacts
    nlohmann::json artifactsJson;
    for (const auto& pair : artifactPaths) {
        artifactsJson[pair.first] = pair.second;
    }
    j["artifact_paths"] = artifactsJson;
    
    // Error
    if (error) {
        j["error"] = error->toJson();
    }
    
    return j;
}

std::string ExecutionResult::toJsonString() const {
    return toJson().dump(2);
}

} // namespace Sovereign
} // namespace RawrXD
