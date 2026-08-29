#pragma once
// ============================================================================
// AgentRuntimeController — Agent ⇄ Response Gen toggle ABOVE inference
// ============================================================================
// Response Gen routes through HexMagRuntimeController (sequencing) +
// FinalizePolicy (FINAL authority). Controller does not invent FINAL.
// ============================================================================

#include <functional>
#include <memory>
#include <string>

#include "core/hexmag_control_plane.hpp"
#include "core/hexmag_runtime_controller.hpp"

namespace RawrXD {

enum class AgentRuntimeMode {
    Agent,        // NativeAgent: model + tools + workspace mutation
    ResponseGen,  // HexMag controller → client → FinalizePolicy
    Auto
};

enum class HexMagMode {
    ResponseGeneration,
    AgentDelegation
};

struct ReasoningOracle {
    virtual ~ReasoningOracle() = default;
    virtual bool available() const = 0;
    virtual std::string ask(const std::string& prompt,
                            const std::string& roleContext) = 0;
};

struct NullReasoningOracle final : ReasoningOracle {
    bool available() const override { return false; }
    std::string ask(const std::string&, const std::string&) override {
        return {};
    }
};

using AgentAskFn = std::function<void(const std::string& input)>;
using HexMagAskFn = std::function<std::string(const std::string& question,
                                               HexMagMode mode)>;

class AgentRuntimeController {
public:
    void setMode(AgentRuntimeMode mode) { m_mode = mode; }
    AgentRuntimeMode mode() const { return m_mode; }

    void setAgentAsk(AgentAskFn fn) { m_agentAsk = std::move(fn); }
    void setHexMagAsk(HexMagAskFn fn) { m_hexMagAsk = std::move(fn); }
    void setOracle(ReasoningOracle* oracle) { m_oracle = oracle; }

    ReasoningOracle* oracle() const { return m_oracle; }

    HexMag::HexMagRuntimeController& hexController() {
        ensureHexSession();
        return *m_hexCtrl;
    }

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
    std::unique_ptr<HexMag::LiveHexMagTransport> m_hexTransport;
    std::unique_ptr<HexMag::HexMagRuntimeController> m_hexCtrl;

    void ensureHexSession() {
        if (!m_hexTransport)
            m_hexTransport = std::make_unique<HexMag::LiveHexMagTransport>();
        if (!m_hexCtrl)
            m_hexCtrl = std::make_unique<HexMag::HexMagRuntimeController>(
                m_hexTransport.get());
    }

    AgentRuntimeMode effectiveMode(const std::string& input) const {
        if (m_mode != AgentRuntimeMode::Auto)
            return m_mode;
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
        return {};
    }

    std::string runResponseGen(const std::string& question) {
        if (m_hexMagAsk)
            return m_hexMagAsk(question, HexMagMode::ResponseGeneration);

        ensureHexSession();
        // New Response Gen turn — clear prior NEED_INPUT / FINAL stop.
        m_hexCtrl->resetSession();
        auto r = m_hexCtrl->run(question, {});
        if (r.finalAuthority) {
            if (!r.lastClient.ask.answer.empty())
                return r.lastClient.ask.answer;
            return r.diagnostic.empty() ? std::string("goal.satisfied")
                                        : r.diagnostic;
        }
        if (r.needInputLatched
            || r.fail == HexMag::ControllerFail::NeedInput) {
            return std::string("[HexMag NEED_INPUT] ")
                + (r.lastClient.ask.error.empty() ? r.diagnostic
                                                  : r.lastClient.ask.error);
        }
        if (!r.lastClient.ask.error.empty())
            return std::string("[HexMag] ") + r.lastClient.ask.error;
        return std::string("[HexMag] ")
            + (r.diagnostic.empty() ? "failed" : r.diagnostic);
    }
};

} // namespace RawrXD
