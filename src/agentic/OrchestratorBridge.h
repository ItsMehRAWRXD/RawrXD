// =============================================================================
// OrchestratorBridge.h — Agent Runtime Bridge (IModelRuntime-backed)
// =============================================================================
// Replaces direct Ollama dependency with the authoritative IModelRuntime
// contract. Supports Deep2 (local), Ollama (remote), and future backends.
// =============================================================================
#pragma once

#include "AgentToolHandlers.h"
#include "PredictionProvider.h"
#include "../runtime/IModelRuntime.hpp"
#include <memory>
#include <string>
#include <vector>

namespace RawrXD {
namespace Agent {

// ---------------------------------------------------------------------------
// OrchestratorBridge — Agent entry point, backend-agnostic
// ---------------------------------------------------------------------------
class OrchestratorBridge {
public:
    static OrchestratorBridge& Instance();

    // ---- Initialization ----
    // Creates a Deep2ModelRuntime by default. Pass backend="ollama" for
    // legacy Ollama compatibility.
    bool Initialize(const std::string& workingDir,
                    const std::string& backend = "deep2",
                    const std::string& modelPath = "");

    bool IsInitialized() const { return m_initialized; }

    // ---- Runtime access (for advanced callers) ----
    Runtime::IModelRuntime* GetRuntime() const { return m_runtime.get(); }
    void SetRuntime(std::unique_ptr<Runtime::IModelRuntime> runtime);

    // ---- Agent Execution ----
    std::string RunAgent(const std::string& userPrompt);
    void RunAgentAsync(const std::string& userPrompt);

    // ---- Ghost Text / FIM ----
    Prediction::PredictionResult RequestGhostText(
        const Prediction::PredictionContext& ctx);
    void RequestGhostTextStream(
        const Prediction::PredictionContext& ctx,
        Prediction::StreamTokenCallback onToken);

    // ---- Configuration ----
    void SetModel(const std::string& model);
    void SetFIMModel(const std::string& model);
    void SetTemperature(float temperature);
    void SetMaxSteps(int steps);
    void SetWorkingDirectory(const std::string& dir);
    OrchestratorBridge() = default;
    ~OrchestratorBridge() = default;

private:
    bool EnsureRuntimeReady();
    void RefreshAvailableModels();
    void ApplyConfig();
    std::string SelectPreferredModel(bool preferCoder) const;

    // Build a GenerationRequest from agent context
    Runtime::GenerationRequest BuildGenerationRequest(
        const std::string& prompt) const;
    Runtime::FIMRequest BuildFIMRequest(
        const Prediction::PredictionContext& ctx) const;

public:
    bool m_initialized = false;
    std::string m_workingDir;
    std::string m_backendName = "deep2";
    std::string m_modelPath;
    std::unique_ptr<Runtime::IModelRuntime> m_runtime;
    int m_maxSteps = 8;
    std::vector<std::string> m_availableModels;
};

} // namespace Agent
} // namespace RawrXD

// ---------------------------------------------------------------------------
// MASM/C interop surface (single-hop request model)
// ---------------------------------------------------------------------------
// Returns 0 on success, negative on error.
// If out_buf is provided, output is always NUL-terminated when out_buf_size > 0.
// out_required receives the full required byte count including terminating NUL.
extern "C" __declspec(dllexport) int RawrXD_AgentRunSync(const char* prompt,
                                                          char* out_buf,
                                                          unsigned int out_buf_size,
                                                          unsigned int* out_required);

extern "C" __declspec(dllexport) int RawrXD_AgentRequestFIMSync(const char* prefix,
                                                                  const char* suffix,
                                                                  const char* file_path,
                                                                  char* out_buf,
                                                                  unsigned int out_buf_size,
                                                                  unsigned int* out_required);

extern "C" __declspec(dllexport) int RawrXD_AgentSetTemperature(float temperature);
