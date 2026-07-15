#pragma once
#ifndef RAWRXD_EXECUTION_POLICY_H
#define RAWRXD_EXECUTION_POLICY_H

#include <string>
#include <functional>

namespace RawrXD {

// ============================================================================
// Execution Policy Layer
// Explicit control over inference routing with full observability
// ============================================================================

enum class RuntimeMode {
    StrictLocal,      // Local inference ONLY - fail if unavailable
    HybridControlled, // Local preferred, cloud allowed with explicit opt-in
    FullyDistributed  // Automatic routing based on policy rules
};

enum class ExecutionPath {
    LOCAL_GGUF,       // Native GGUF loader
    LOCAL_OLLAMA,     // Ollama localhost endpoint
    REMOTE_CLOUD,     // Cloud API (Anthropic, OpenAI, etc.)
    HYBRID_FALLBACK   // Automatic fallback path
};

struct ModelExecutionProfile {
    RuntimeMode runtimeMode = RuntimeMode::HybridControlled;
    bool allowLocal = true;
    bool allowRemote = false;  // Must be explicitly enabled
    ExecutionPath lastExecutionPath = ExecutionPath::LOCAL_GGUF;
    std::string routingDecisionLog;
};

// ============================================================================
// Policy Router with Observability
// ============================================================================
class ExecutionPolicyRouter {
public:
    using PathDecisionCallback = std::function<void(ExecutionPath, const std::string&)>;

    explicit ExecutionPolicyRouter(RuntimeMode mode = RuntimeMode::HybridControlled);

    // Core routing decision with logging
    ExecutionPath decideExecutionPath(
        const std::string& modelName,
        const ModelExecutionProfile& profile,
        bool localAvailable,
        bool cloudAvailable
    );

    // Explicit policy overrides
    void setRuntimeMode(RuntimeMode mode) { m_runtimeMode = mode; }
    void setPathDecisionCallback(PathDecisionCallback cb) { m_onPathDecision = cb; }

    // Query current policy state
    RuntimeMode getRuntimeMode() const { return m_runtimeMode; }
    std::string getLastDecisionLog() const { return m_lastDecisionLog; }

    // Policy enforcement helpers
    bool isCloudAllowed(const ModelExecutionProfile& profile) const;
    bool isLocalRequired(const ModelExecutionProfile& profile) const;

private:
    RuntimeMode m_runtimeMode;
    std::string m_lastDecisionLog;
    PathDecisionCallback m_onPathDecision;

    void logDecision(ExecutionPath path, const std::string& reason);
    static std::string pathToString(ExecutionPath path);
    static std::string modeToString(RuntimeMode mode);
};

// ============================================================================
// Global policy accessors (thread-safe singleton)
// ============================================================================
ExecutionPolicyRouter& GetGlobalPolicyRouter();
void SetGlobalRuntimeMode(RuntimeMode mode);
RuntimeMode GetGlobalRuntimeMode();

} // namespace RawrXD

#endif // RAWRXD_EXECUTION_POLICY_H
