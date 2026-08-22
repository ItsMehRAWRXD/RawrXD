// =============================================================================
// OrchestratorBridge.cpp — Agent Runtime Bridge (IModelRuntime-backed)
// =============================================================================
// Replaces direct Ollama dependency with the authoritative IModelRuntime contract.
// All inference calls route through m_runtime (Deep2 by default).
//
// Migration notes:
//   - ChatMessage history is preserved for tool-calling loops
//   - OllamaConfig removed; temperature/maxTokens live in GenerationRequest
//   - Tool schemas are passed through GenerationRequest::toolSchemas
// =============================================================================

#include "OrchestratorBridge.h"
#include "ToolCallResult.h"
#include "../logging/Logger.h"
#include "../security/InputSanitizer.h"
#include "../core/ConfigurationValidator.h"
#include "../inference/PerformanceMonitor.h"
#include "ErrorRecoveryManager.h"
#include "../agent/agentic_hotpatch_orchestrator.hpp"
#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstring>
#include <sstream>
#include <thread>
#include <stdexcept>
#include <unordered_set>

using RawrXD::Agent::OrchestratorBridge;
using RawrXD::Agent::ToolCallResult;
namespace Prediction = RawrXD::Prediction;
using json = nlohmann::json;

namespace {

std::string ToLowerCopy(const std::string& value) {
    std::string lowered = value;
    std::transform(lowered.begin(), lowered.end(), lowered.begin(),
        [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return lowered;
}

bool ContainsInsensitive(const std::string& haystack, const std::string& needle) {
    if (needle.empty()) {
        return true;
    }
    return ToLowerCopy(haystack).find(ToLowerCopy(needle)) != std::string::npos;
}

std::string BuildToolMessageContent(const ToolCallResult& result) {
    if (result.isSuccess()) {
        if (!result.output.empty()) {
            return result.output;
        }
        return "Tool completed successfully.";
    }
    if (!result.error.empty()) {
        return "Error: " + result.error;
    }
    if (!result.output.empty()) {
        return "Error: " + result.output;
    }
    return "Error: Tool execution failed.";
}

RawrXD::Logging::Logger& GetLogger() {
    return RawrXD::Logging::Logger::instance();
}

// Parse tool calls from model response (simple heuristic for now)
// TODO: replace with structured JSON parsing when model supports it
std::vector<std::pair<std::string, std::string>> ParseToolCalls(const std::string& response) {
    std::vector<std::pair<std::string, std::string>> calls;
    size_t pos = 0;
    while (true) {
        size_t toolPos = response.find("TOOL_CALL:", pos);
        if (toolPos == std::string::npos) break;
        size_t nameStart = toolPos + 10;
        while (nameStart < response.size() && std::isspace(static_cast<unsigned char>(response[nameStart]))) ++nameStart;
        size_t nameEnd = nameStart;
        while (nameEnd < response.size() && !std::isspace(static_cast<unsigned char>(response[nameEnd]))) ++nameEnd;
        std::string name = response.substr(nameStart, nameEnd - nameStart);
        size_t braceStart = response.find('{', nameEnd);
        if (braceStart == std::string::npos) break;
        int depth = 1;
        size_t braceEnd = braceStart + 1;
        while (braceEnd < response.size() && depth > 0) {
            if (response[braceEnd] == '{') ++depth;
            else if (response[braceEnd] == '}') --depth;
            ++braceEnd;
        }
        std::string args = response.substr(braceStart, braceEnd - braceStart);
        calls.emplace_back(name, args);
        pos = braceEnd;
    }
    return calls;
}

} // namespace

namespace {

int WriteInteropOutput(const std::string& out,
                       char* out_buf,
                       unsigned int out_buf_size,
                       unsigned int* out_required) {
    const unsigned int required = static_cast<unsigned int>(out.size() + 1);
    if (out_required) {
        *out_required = required;
    }
    if (out_buf && out_buf_size > 0) {
        const size_t copyLen = std::min<size_t>(out.size(), static_cast<size_t>(out_buf_size - 1));
        if (copyLen > 0) {
            std::memcpy(out_buf, out.data(), copyLen);
        }
        out_buf[copyLen] = '\0';
    }
    return (required <= out_buf_size) ? 0 : 1;
}

} // namespace

// ---------------------------------------------------------------------------
// Singleton
// ---------------------------------------------------------------------------

OrchestratorBridge& OrchestratorBridge::Instance() {
    static OrchestratorBridge instance;
    return instance;
}

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

bool OrchestratorBridge::Initialize(const std::string& workingDir,
                                     const std::string& backend,
                                     const std::string& modelPath)
{
    auto& logger = GetLogger();
    auto& sanitizer = RawrXD::Security::InputSanitizer::instance();
    RawrXD::Security::SanitizationResult pathSan = sanitizer.sanitizePath(workingDir);
    m_workingDir = pathSan.sanitized;
    if (pathSan.wasModified) {
        logger.warning("OrchestratorBridge", "Working directory sanitized: " + m_workingDir);
    }

    m_backendName = backend.empty() ? "deep2" : backend;
    m_modelPath = modelPath;

    SetWorkingDirectory(m_workingDir);

    // Create runtime via factory
    m_runtime = RawrXD::Runtime::CreateModelRuntime(m_backendName);
    if (!m_runtime) {
        logger.error("OrchestratorBridge", "Failed to create runtime for backend: " + m_backendName);
        return false;
    }

    // Load model if path provided
    if (!m_modelPath.empty()) {
        std::string loadError;
        if (!m_runtime->LoadModel(m_modelPath, loadError)) {
            logger.error("OrchestratorBridge", "Failed to load model: " + loadError);
            return false;
        }
        logger.info("OrchestratorBridge", "Loaded model: " + m_modelPath);
    }

    m_initialized = EnsureRuntimeReady();
    return m_initialized;
}

void OrchestratorBridge::SetRuntime(std::unique_ptr<RawrXD::Runtime::IModelRuntime> runtime) {
    m_runtime = std::move(runtime);
    m_initialized = EnsureRuntimeReady();
}

// ---------------------------------------------------------------------------
// Agent Execution
// ---------------------------------------------------------------------------

std::string OrchestratorBridge::RunAgent(const std::string& userPrompt) {
    (void)EnsureRuntimeReady();

    auto& logger = GetLogger();
    auto& sanitizer = RawrXD::Security::InputSanitizer::instance();
    auto sanitizedPrompt = sanitizer.sanitizePrompt(userPrompt);
    if (sanitizedPrompt.wasModified) {
        logger.warning("OrchestratorBridge", "Prompt sanitized before dispatch");
    }

    // Build generation request
    RawrXD::Runtime::GenerationRequest genReq = BuildGenerationRequest(sanitizedPrompt.sanitized);

    auto& perf = RawrXD::Inference::PerformanceMonitor::instance();
    auto& recovery = RawrXD::Agentic::ErrorRecoveryManager::instance();
    RawrXD::Agentic::ErrorRecoveryManager::RecoveryConfig recoveryCfg{};
    recoveryCfg.maxRetries = 3;
    recoveryCfg.baseDelay = std::chrono::milliseconds(500);
    recoveryCfg.maxDelay = std::chrono::milliseconds(5000);

    std::string latestResponse;
    std::unordered_set<std::string> seenToolCalls;
    const int stepLimit = std::max(1, m_maxSteps);

    // Simple tool-calling loop: generate -> parse tools -> execute -> iterate
    for (int step = 0; step < stepLimit; ++step) {
        perf.startOperation("agent.generate");

        RawrXD::Runtime::GenerationResult result;
        try {
            result = recovery.executeWithRecovery([&]() {
                return m_runtime->Generate(genReq);
            }, recoveryCfg);
            perf.endOperation("agent.generate");
        } catch (const std::exception& ex) {
            perf.recordError("agent.generate");
            perf.endOperation("agent.generate");
            logger.error("OrchestratorBridge", std::string("Generation failed: ") + ex.what());
            return "[ERROR] " + std::string(ex.what());
        }

        if (!result.success) {
            return "[ERROR] " + result.errorMessage;
        }

        latestResponse = result.text;

        // Parse tool calls from response
        auto toolCalls = ParseToolCalls(result.text);
        if (toolCalls.empty()) {
            return latestResponse;
        }

        // Execute tool calls and append results to prompt for next iteration
        std::string toolResults;
        for (size_t i = 0; i < toolCalls.size(); ++i) {
            const std::string callId = "call_" + std::to_string(step) + "_" + std::to_string(i);
            if (!seenToolCalls.insert(callId).second) {
                logger.warning("OrchestratorBridge", "Duplicate tool call suppressed: " + callId);
                continue;
            }

            ToolCallResult toolResult = RawrXD::Agent::AgentToolHandlers::Instance().Execute(
                toolCalls[i].first, toolCalls[i].second);

            toolResults += "Tool '" + toolCalls[i].first + "' result: " +
                          BuildToolMessageContent(toolResult) + "\n";
        }

        // Append tool results to prompt for next generation
        genReq.prompt = sanitizedPrompt.sanitized + "\n\n" +
                       "Previous response: " + latestResponse + "\n\n" +
                       toolResults + "\nContinue:";
    }

    if (latestResponse.empty()) {
        return "[ERROR] Agent stopped after reaching the step limit without a final answer";
    }
    return latestResponse + "\n\n[INFO] Agent step limit reached.";
}

void OrchestratorBridge::RunAgentAsync(const std::string& userPrompt) {
    std::thread([this, userPrompt]() {
        (void)RunAgent(userPrompt);
    }).detach();
}

// ---------------------------------------------------------------------------
// Ghost Text / FIM
// ---------------------------------------------------------------------------

Prediction::PredictionResult OrchestratorBridge::RequestGhostText(
    const Prediction::PredictionContext& ctx)
{
    (void)EnsureRuntimeReady();

    auto& perf = RawrXD::Inference::PerformanceMonitor::instance();
    auto& recovery = RawrXD::Agentic::ErrorRecoveryManager::instance();
    RawrXD::Agentic::ErrorRecoveryManager::RecoveryConfig recoveryCfg{};
    recoveryCfg.maxRetries = 2;
    recoveryCfg.baseDelay = std::chrono::milliseconds(300);
    recoveryCfg.maxDelay = std::chrono::milliseconds(2500);

    RawrXD::Runtime::FIMRequest fimReq = BuildFIMRequest(ctx);

    perf.startOperation("agent.fim");
    try {
        RawrXD::Runtime::GenerationResult result = recovery.executeWithRecovery([&]() {
            return m_runtime->GenerateFIM(fimReq);
        }, recoveryCfg);
        perf.endOperation("agent.fim");
        if (!result.success) {
            return Prediction::PredictionResult::Error(result.errorMessage);
        }
        return Prediction::PredictionResult::Ok(
            result.text,
            static_cast<int>(result.tokensGenerated),
            static_cast<int64_t>(result.latencyMs));
    } catch (const std::exception& ex) {
        perf.recordError("agent.fim");
        perf.endOperation("agent.fim");
        GetLogger().error("OrchestratorBridge", std::string("FIM failed: ") + ex.what());
        return Prediction::PredictionResult::Error(ex.what());
    }
}

void OrchestratorBridge::RequestGhostTextStream(
    const Prediction::PredictionContext& ctx,
    Prediction::StreamTokenCallback onToken)
{
    (void)EnsureRuntimeReady();

    if (!m_runtime) {
        if (onToken) {
            onToken("", true);
        }
        return;
    }

    RawrXD::Runtime::FIMRequest fimReq = BuildFIMRequest(ctx);
    m_runtime->GenerateFIMStream(fimReq, [onToken](const std::string& token, bool done) {
        if (onToken) {
            onToken(token, done);
        }
        return true; // don't cancel
    });
}

// ---------------------------------------------------------------------------
// Configuration helpers
// ---------------------------------------------------------------------------

bool OrchestratorBridge::EnsureRuntimeReady() {
    if (!m_runtime) {
        m_runtime = RawrXD::Runtime::CreateModelRuntime(m_backendName);
    }
    m_initialized = (m_runtime != nullptr);
    return m_initialized;
}

void OrchestratorBridge::RefreshAvailableModels() {
    // Deep2 runtime doesn't list models; they are loaded by path
    // For Ollama backend, this would call ListModels()
    m_availableModels.clear();
}

void OrchestratorBridge::ApplyConfig() {
    // Config is now per-request via GenerationRequest; no global state to apply
}

std::string OrchestratorBridge::SelectPreferredModel(bool preferCoder) const {
    (void)preferCoder;
    // With local Deep2 runtime, model is loaded by path, not selected from list
    return m_modelPath;
}

void OrchestratorBridge::SetModel(const std::string& model) {
    auto sanitized = RawrXD::Security::InputSanitizer::instance().sanitizeModelName(model);
    if (sanitized.wasModified) {
        GetLogger().warning("OrchestratorBridge", "Model path sanitized from user input");
    }
    m_modelPath = sanitized.sanitized;
    if (m_runtime && !m_modelPath.empty()) {
        std::string loadError;
        if (!m_runtime->LoadModel(m_modelPath, loadError)) {
            GetLogger().error("OrchestratorBridge", "Failed to load model: " + loadError);
        }
    }
    m_initialized = m_initialized || !m_modelPath.empty();
}

void OrchestratorBridge::SetFIMModel(const std::string& model) {
    // In unified runtime, FIM uses the same loaded model
    SetModel(model);
}

void OrchestratorBridge::SetTemperature(float temperature) {
    if (temperature < 0.0f) temperature = 0.0f;
    if (temperature > 2.0f) temperature = 2.0f;
    AgenticHotpatchOrchestrator::instance().setModelTemperature(temperature);
}

void OrchestratorBridge::SetMaxSteps(int steps) {
    if (steps > 0) {
        m_maxSteps = steps;
    }
}

void OrchestratorBridge::SetWorkingDirectory(const std::string& dir) {
    auto sanitized = RawrXD::Security::InputSanitizer::instance().sanitizePath(dir);
    if (sanitized.wasModified) {
        GetLogger().warning("OrchestratorBridge", "Working directory sanitized");
    }
    m_workingDir = sanitized.sanitized;

    RawrXD::Agent::ToolGuardrails guards = RawrXD::Agent::AgentToolHandlers::GetGuardrails();
    guards.allowedRoots.clear();
    if (!m_workingDir.empty()) {
        guards.allowedRoots.push_back(m_workingDir);
    }
    RawrXD::Agent::AgentToolHandlers::SetGuardrails(guards);
}

// ---------------------------------------------------------------------------
// Request builders
// ---------------------------------------------------------------------------

RawrXD::Runtime::GenerationRequest OrchestratorBridge::BuildGenerationRequest(
    const std::string& prompt) const
{
    RawrXD::Runtime::GenerationRequest req;
    req.prompt = prompt;
    req.systemPrompt = RawrXD::Agent::AgentToolHandlers::GetSystemPrompt(m_workingDir, {});
    req.maxTokens = 4096;
    req.temperature = AgenticHotpatchOrchestrator::instance().getModelTemperature();
    req.topP = 0.9f;
    req.topK = 40;
    req.repeatPenalty = 1.0f;

    // Add tool schemas if runtime supports tool calling
    if (m_runtime && m_runtime->SupportsToolCalling()) {
        const json tools = RawrXD::Agent::AgentToolHandlers::GetAllSchemas();
        for (const auto& tool : tools) {
            req.toolSchemas.push_back(tool.dump());
        }
    }

    return req;
}

RawrXD::Runtime::FIMRequest OrchestratorBridge::BuildFIMRequest(
    const Prediction::PredictionContext& ctx) const
{
    RawrXD::Runtime::FIMRequest req;
    req.prefix = ctx.prefix;
    req.suffix = ctx.suffix;
    req.filePath = ctx.filePath;
    req.language = ctx.language;
    req.maxTokens = 256;
    req.temperature = 0.2f;
    return req;
}

// ---------------------------------------------------------------------------
// C interop surface (unchanged ABI)
// ---------------------------------------------------------------------------

extern "C" __declspec(dllexport) int RawrXD_AgentRunSync(const char* prompt,
                                                          char* out_buf,
                                                          unsigned int out_buf_size,
                                                          unsigned int* out_required)
{
    if (!prompt) {
        return -1;
    }
    try {
        std::string result = OrchestratorBridge::Instance().RunAgent(prompt);
        return WriteInteropOutput(result, out_buf, out_buf_size, out_required);
    } catch (...) {
        return -2;
    }
}

extern "C" __declspec(dllexport) int RawrXD_AgentRequestFIMSync(const char* prefix,
                                                                  const char* suffix,
                                                                  const char* file_path,
                                                                  char* out_buf,
                                                                  unsigned int out_buf_size,
                                                                  unsigned int* out_required)
{
    if (!prefix || !suffix) {
        return -1;
    }
    try {
        Prediction::PredictionContext ctx;
        ctx.prefix = prefix;
        ctx.suffix = suffix;
        ctx.filePath = file_path ? file_path : "";
        auto result = OrchestratorBridge::Instance().RequestGhostText(ctx);
        return WriteInteropOutput(result.completion, out_buf, out_buf_size, out_required);
    } catch (...) {
        return -2;
    }
}

extern "C" __declspec(dllexport) int RawrXD_AgentSetTemperature(float temperature) {
    try {
        OrchestratorBridge::Instance().SetTemperature(temperature);
        return 0;
    } catch (...) {
        return -1;
    }
}
