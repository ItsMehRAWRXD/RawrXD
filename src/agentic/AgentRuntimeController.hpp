#pragma once
// ============================================================================
// AgentRuntimeController — Agent ⇄ Response Gen toggle ABOVE inference
// ============================================================================
// Execution Mode (this file) is orthogonal to Inference Backend (Deep2/llama/…).
// Response Gen does NOT require a loaded GGUF; it routes to HexMag (+ optional oracle).
// ============================================================================

#include <functional>
#include <string>

#include "core/hexmag_control_plane.hpp"

namespace RawrXD {

enum class AgentRuntimeMode {
    Agent,        // NativeAgent: model + tools + workspace mutation
    ResponseGen,  // HexMag: inflate ephemeral swarm, consult oracle if needed, deflate
    Auto          // optional classifier; not required for UI v1
};

enum class HexMagMode {
    ResponseGeneration,
    AgentDelegation
};

/// Advisory language/reasoning resource — NOT HexMag's weights.
struct ReasoningOracle {
    virtual ~ReasoningOracle() = default;
    virtual bool available() const = 0;
    virtual std::string ask(const std::string& prompt,
                            const std::string& roleContext) = 0;
};

/// Null oracle: HexMag stays fully weightless / deterministic-only.
struct NullReasoningOracle final : ReasoningOracle {
    bool available() const override { return false; }
    std::string ask(const std::string&, const std::string&) override {
        return {};
    }
};

using AgentAskFn = std::function<void(const std::string& input)>;
using HexMagAskFn = std::function<std::string(const std::string& question,
                                               HexMagMode mode)>;

/**
 * One visible Agent surface; mode selects execution policy, not "another model".
 *
 * AGENT:        model_required≈true, tools=yes, mutate=yes, goal=DO
 * RESPONSE_GEN: model_required=false, tools=no, mutate=no, goal=ANSWER,
 *               HexMag inflate → reverse/verify → (ASK_USER if missing info) → deflate → 0
 *               unsupported_claim_emission=FORBIDDEN (evidence required to finalize)
 */
class AgentRuntimeController {
public:
    void setMode(AgentRuntimeMode mode) { m_mode = mode; }
    AgentRuntimeMode mode() const { return m_mode; }

    void setAgentAsk(AgentAskFn fn) { m_agentAsk = std::move(fn); }
    void setHexMagAsk(HexMagAskFn fn) { m_hexMagAsk = std::move(fn); }
    void setOracle(ReasoningOracle* oracle) { m_oracle = oracle; }

    ReasoningOracle* oracle() const { return m_oracle; }

    std::string submit(const std::string& input) {
        switch (effectiveMode(input)) {
        case AgentRuntimeMode::ResponseGen:
            return runResponseGen(input);
        case AgentRuntimeMode::Agent:
        default:
            return runAgent(input);
        }
    }

    static const char* modeName(AgentRuntimeMode m) {
        switch (m) {
        case AgentRuntimeMode::Agent: return "Agent";
        case AgentRuntimeMode::ResponseGen: return "Response Gen";
        case AgentRuntimeMode::Auto: return "Auto";
        }
        return "?";
    }

private:
    AgentRuntimeMode m_mode = AgentRuntimeMode::Agent;
    AgentAskFn m_agentAsk;
    HexMagAskFn m_hexMagAsk;
    ReasoningOracle* m_oracle = nullptr;

    AgentRuntimeMode effectiveMode(const std::string& input) const {
        if (m_mode != AgentRuntimeMode::Auto)
            return m_mode;
        // Cheap heuristic for Auto (optional exposure later)
        const std::string& s = input;
        auto has = [&](const char* k) {
            return s.find(k) != std::string::npos;
        };
        if (has("fix") || has("build") || has("test") || has("edit") ||
            has("change") || has("run ") || has("write "))
            return AgentRuntimeMode::Agent;
        if (has("why") || has("explain") || has("what is") || has("compare") ||
            has("how does"))
            return AgentRuntimeMode::ResponseGen;
        return AgentRuntimeMode::Agent;
    }

    std::string runAgent(const std::string& input) {
        if (!m_agentAsk)
            return "Agent mode: no NativeAgent binder (model+tools path).";
        m_agentAsk(input);
        return {}; // NativeAgent streams via callback
    }

    std::string runResponseGen(const std::string& question) {
        // Bypass NativeAgent::Ask entirely — no "No model loaded" gate.
        if (m_hexMagAsk)
            return m_hexMagAsk(question, HexMagMode::ResponseGeneration);
        // Default binder: MASM HexMag control plane (policy stack + swarm).
        return HexMag::defaultResponseGenAsk(question);
    }
};

} // namespace RawrXD
