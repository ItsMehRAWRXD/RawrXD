#include "execution_policy.h"
#include <sstream>
#include <chrono>
#include <iomanip>
#include <mutex>

namespace RawrXD {

// ============================================================================
// Thread-safe global policy router
// ============================================================================
static std::mutex g_policyMutex;
static ExecutionPolicyRouter* g_globalRouter = nullptr;

ExecutionPolicyRouter& GetGlobalPolicyRouter() {
    std::lock_guard<std::mutex> lock(g_policyMutex);
    if (!g_globalRouter) {
        g_globalRouter = new ExecutionPolicyRouter(RuntimeMode::HybridControlled);
    }
    return *g_globalRouter;
}

void SetGlobalRuntimeMode(RuntimeMode mode) {
    GetGlobalPolicyRouter().setRuntimeMode(mode);
}

RuntimeMode GetGlobalRuntimeMode() {
    return GetGlobalPolicyRouter().getRuntimeMode();
}

// ============================================================================
// ExecutionPolicyRouter Implementation
// ============================================================================
ExecutionPolicyRouter::ExecutionPolicyRouter(RuntimeMode mode)
    : m_runtimeMode(mode)
    , m_onPathDecision(nullptr)
{
}

ExecutionPath ExecutionPolicyRouter::decideExecutionPath(
    const std::string& modelName,
    const ModelExecutionProfile& profile,
    bool localAvailable,
    bool cloudAvailable)
{
    std::stringstream log;
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    
    log << "[Router " << std::put_time(std::localtime(&time_t), "%H:%M:%S") << "] ";
    log << "model=" << modelName << " ";
    log << "mode=" << modeToString(m_runtimeMode) << " ";
    log << "localAvail=" << (localAvailable ? "yes" : "no") << " ";
    log << "cloudAvail=" << (cloudAvailable ? "yes" : "no") << " ";

    ExecutionPath chosenPath = ExecutionPath::LOCAL_GGUF;
    std::string reason;

    switch (m_runtimeMode) {
        case RuntimeMode::StrictLocal:
            if (localAvailable) {
                chosenPath = ExecutionPath::LOCAL_GGUF;
                reason = "StrictLocal: local inference mandatory";
            } else {
                chosenPath = ExecutionPath::LOCAL_OLLAMA;
                reason = "StrictLocal: falling back to Ollama";
            }
            break;

        case RuntimeMode::HybridControlled:
            // Local preferred, cloud only if explicitly allowed AND available
            if (localAvailable) {
                chosenPath = ExecutionPath::LOCAL_GGUF;
                reason = "HybridControlled: local preferred";
            } else if (profile.allowRemote && cloudAvailable) {
                chosenPath = ExecutionPath::REMOTE_CLOUD;
                reason = "HybridControlled: local unavailable, cloud permitted";
            } else {
                chosenPath = ExecutionPath::LOCAL_OLLAMA;
                reason = "HybridControlled: local fallback to Ollama";
            }
            break;

        case RuntimeMode::FullyDistributed:
            // Automatic routing based on availability and policy
            if (localAvailable) {
                chosenPath = ExecutionPath::LOCAL_GGUF;
                reason = "FullyDistributed: local available";
            } else if (cloudAvailable && profile.allowRemote) {
                chosenPath = ExecutionPath::REMOTE_CLOUD;
                reason = "FullyDistributed: cloud burst";
            } else {
                chosenPath = ExecutionPath::HYBRID_FALLBACK;
                reason = "FullyDistributed: hybrid fallback";
            }
            break;
    }

    log << "-> " << pathToString(chosenPath) << " [" << reason << "]";
    m_lastDecisionLog = log.str();

    // Log to stderr for visibility
    fprintf(stderr, "%s\n", m_lastDecisionLog.c_str());

    if (m_onPathDecision) {
        m_onPathDecision(chosenPath, reason);
    }

    return chosenPath;
}

bool ExecutionPolicyRouter::isCloudAllowed(const ModelExecutionProfile& profile) const {
    if (m_runtimeMode == RuntimeMode::StrictLocal) {
        return false;
    }
    return profile.allowRemote;
}

bool ExecutionPolicyRouter::isLocalRequired(const ModelExecutionProfile& profile) const {
    (void)profile; // Profile may contain per-model overrides in future
    return m_runtimeMode == RuntimeMode::StrictLocal;
}

std::string ExecutionPolicyRouter::pathToString(ExecutionPath path) {
    switch (path) {
        case ExecutionPath::LOCAL_GGUF: return "LOCAL_GGUF";
        case ExecutionPath::LOCAL_OLLAMA: return "LOCAL_OLLAMA";
        case ExecutionPath::REMOTE_CLOUD: return "REMOTE_CLOUD";
        case ExecutionPath::HYBRID_FALLBACK: return "HYBRID_FALLBACK";
    }
    return "UNKNOWN";
}

std::string ExecutionPolicyRouter::modeToString(RuntimeMode mode) {
    switch (mode) {
        case RuntimeMode::StrictLocal: return "StrictLocal";
        case RuntimeMode::HybridControlled: return "HybridControlled";
        case RuntimeMode::FullyDistributed: return "FullyDistributed";
    }
    return "UNKNOWN";
}

} // namespace RawrXD
