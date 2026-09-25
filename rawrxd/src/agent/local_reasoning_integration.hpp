#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <optional>
#include <functional>
#include <variant>
#include <map>

namespace rawrxd::agent {

enum class ReasoningPhase {
    Perception = 0,
    Analysis = 1,
    Planning = 2,
    Execution = 3,
    Verification = 4,
    Reflection = 5
};

enum class ReasoningStrategy {
    ChainOfThought = 0,
    TreeOfThoughts = 1,
    ReAct = 2,
    Reflexion = 3,
    AutoGPT = 4,
    PlanAndSolve = 5
};

struct ReasoningStep {
    ReasoningPhase phase;
    std::string description;
    std::string observation;
    std::string action;
    float confidence = 0.0f;
    uint64_t timestamp_ms = 0;
    std::vector<uint32_t> token_trace;
};

struct ReasoningResult {
    std::vector<ReasoningStep> steps;
    std::string final_answer;
    float aggregate_confidence = 0.0f;
    uint32_t total_tokens = 0;
    uint64_t latency_ms = 0;
    bool completed = false;
    std::string error_message;
};

struct ReasoningConfig {
    ReasoningStrategy strategy = ReasoningStrategy::ChainOfThought;
    uint32_t max_steps = 10;
    float min_confidence = 0.5f;
    float temperature = 0.7f;
    uint32_t max_tokens_per_step = 512;
    bool enable_reflection = true;
    bool enable_self_correction = true;
    std::vector<std::string> tools;
};

struct AgentContext {
    std::string session_id;
    std::string user_query;
    std::vector<std::string> conversation_history;
    std::map<std::string, std::string> environment_state;
    std::vector<uint32_t> active_tool_ids;
};

class LocalReasoningEngine {
public:
    LocalReasoningEngine();
    ~LocalReasoningEngine();

    void SetConfig(const ReasoningConfig& config);
    const ReasoningConfig& GetConfig() const;

    ReasoningResult Reason(const AgentContext& context);
    ReasoningResult Reason(const AgentContext& context,
                           const std::function<std::string(const std::string&)>& llm_callback);

    ReasoningResult Step(const AgentContext& context,
                         const std::vector<ReasoningStep>& previous_steps);

    void ClearHistory();
    std::vector<ReasoningStep> GetHistory() const;

    bool IsRunning() const;
    void Cancel();

    static std::string StrategyName(ReasoningStrategy strategy);
    static std::string PhaseName(ReasoningPhase phase);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

class LocalReasoningIntegration {
public:
    static LocalReasoningEngine& instance();
    static void Initialize(const ReasoningConfig& config);
    static void Shutdown();
    static bool IsInitialized();
private:
    LocalReasoningIntegration() = default;
};

} // namespace rawrxd::agent

