// ============================================================================
// include/reasoning_pipeline_orchestrator.h -- Tunable reasoning pipeline
// ============================================================================
// Declares ReasoningPipelineOrchestrator and its supporting result types. The
// full implementation lives in src/core/reasoning_pipeline_orchestrator.cpp.
//
// ----------------------------------------------------------------------------
// WHY THIS FILE EXISTS NOW (RAWRXD_MISSING_SOURCE_001)
// ----------------------------------------------------------------------------
// src/core/reasoning_pipeline_orchestrator.cpp is 1256 lines of finished
// implementation and src/core/reasoning_cot_bridge.cpp (293 lines) is its
// client. Both open with this header. Neither header nor file was ever written,
// so both translation units have never compiled:
//
//     src\core\reasoning_pipeline_orchestrator.cpp(12,10): error C1083: Cannot
//         open include file: '../include/reasoning_pipeline_orchestrator.h':
//         No such file or directory
//     src\core\reasoning_cot_bridge.cpp(18,10): error C1083: Cannot open
//         include file: '../include/reasoning_pipeline_orchestrator.h': No such
//         file or directory
//
// Both files are in the RawrXD_Gold source list, so this absence alone is enough
// to stop that target compiling.
//
// ----------------------------------------------------------------------------
// RECONSTRUCTION BASIS
// ----------------------------------------------------------------------------
// Every declaration below was read off a use site in one of the two .cpp files
// or off the friend declaration in reasoning_profile.h:475. A wrong declaration
// here is a compile error, not a silent mismatch.
//
// TWO ITEMS HAD NO USE SITE AND ARE FLAGGED AS SUCH:
//   StreamingInferenceCallback -- assigned and moved by
//       setStreamingCallback (lines 154-157) and never invoked anywhere in the
//       tree. Its signature is chosen as the streaming analogue of the
//       InferenceCallback shape that IS pinned by its call site at line 593
//       (cb(systemPrompt, input, model) -> std::string). Nothing currently
//       depends on the exact signature; wiring a consumer is outstanding.
//   OrchestratorStats field types -- the counters are pinned to uint64_t by
//       `uint64_t n = m_stats.totalExecutions` at line 329, avgLatencyMs to
//       double and avgConfidence to float by the mixing arithmetic at lines
//       330-331. The struct is memset to zero in the constructor and in
//       resetStats(), so it must stay trivially copyable and therefore carries
//       no default member initialisers.
//
// ReasoningMode and InputComplexity are NOT declared here. They already exist in
// include/reasoning_profile.h, which this header includes -- declaring them
// again would be a redefinition. That is also why this class is at global
// scope: reasoning_profile.h:475 befriends ReasoningPipelineOrchestrator from
// inside class ReasoningProfileManager, which is itself at global scope, so a
// namespaced class here would be a different type from the one befriended.
//
// Rule: NO SOURCE FILE IS TO BE SIMPLIFIED
// ============================================================================

#pragma once

#include "reasoning_profile.h"

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

// ============================================================================
// Inference Callbacks
// ============================================================================
// InferenceCallback's shape is fixed by its use at
// reasoning_pipeline_orchestrator.cpp:593 -- `cb(systemPrompt, input, model)`
// returning std::string, inside a try/catch that converts a thrown exception
// into PipelineResult::fail(...). std::function is required rather than a raw
// pointer: it is default-constructed, copied under the mutex at line 576,
// std::move'd at line 151, and truth-tested at line 580.
using InferenceCallback =
    std::function<std::string(const std::string& systemPrompt,
                              const std::string& userInput,
                              const std::string& model)>;

// NO USE SITE. See the header note. Declared so setStreamingCallback has a
// parameter type; nothing in the tree calls through it yet.
using StreamingInferenceCallback =
    std::function<void(const std::string& systemPrompt,
                       const std::string& userInput,
                       const std::string& model,
                       const std::string& token)>;

// ============================================================================
// One Step of a Chained Pipeline
// ============================================================================
struct PipelineStepResult {
    int         stepIndex  = 0;
    std::string agentRole;
    std::string content;
    bool        success    = false;
    bool        skipped    = false;
    float       confidence = 0.0f;
    double      latencyMs  = 0.0;
    // Rough token count for this step, derived by the implementation as
    // response.size() / 4 (reasoning_pipeline_orchestrator.cpp:689) and
    // forwarded from the chain-of-thought result in reasoning_cot_bridge.cpp:141.
    // This is the same /4 heuristic in both places, not a tokenizer count.
    int         tokenCount = 0;
    std::string errorMsg;
};

// ============================================================================
// One Agent of a Swarm Run
// ============================================================================
// Field-for-field the same shape as PipelineStepResult plus the agent index and
// the model that agent was assigned; reasoning_pipeline_orchestrator.cpp:848-854
// copies an agent result straight into a step result by name.
struct SwarmAgentResult {
    int         agentIndex = 0;
    std::string model;
    std::string output;
    bool        success    = false;
    float       confidence = 0.0f;
    double      latencyMs  = 0.0;
    std::string errorMsg;
};

// ============================================================================
// Pipeline Result
// ============================================================================
struct PipelineResult {
    // --- What the user gets ---
    bool        success      = false;
    std::string finalAnswer;
    float       finalConfidence = 0.0f;
    std::string errorMsg;

    // --- What actually ran ---
    std::vector<PipelineStepResult> steps;
    double      totalLatencyMs      = 0.0;
    int         effectiveDepth      = 0;
    ReasoningMode effectiveMode     = ReasoningMode::Fast;
    InputComplexity inputComplexity = InputComplexity::Trivial;

    // --- What the router decided ---
    bool wasBypassed          = false;   // shouldBypass() short-circuited
    bool wasAdaptiveAdjusted  = false;
    bool wasThermalThrottled  = false;
    bool usedSwarm            = false;
    bool usedFallback         = false;

    // --- Presentation, filled by ReasoningPipelineOrchestrator::formatVisibleOutput ---
    struct VisibleOutput {
        std::string              finalAnswer;
        int                      totalSteps      = 0;
        bool                     showProgress    = false;
        std::vector<std::string> stepSummaries;      // populated for StepSummary
        std::vector<std::string> fullCoTSteps;       // populated for FullCoT
        std::vector<double>      stepTimings;        // only when exposeStepTimings
        std::vector<float>       stepConfidences;    // only when exposeConfidence
    } visible;

    // Successful result carrying an answer.
    static PipelineResult ok(const std::string& answer);

    // Failed result carrying a reason. Every early exit in the implementation
    // goes through this, including "No inference callback configured." at lines
    // 581 and 729, so an orchestrator with no callback reports failure rather
    // than an empty success.
    static PipelineResult fail(const char* reason);
};

// ============================================================================
// Reasoning Pipeline Orchestrator
// ============================================================================
class ReasoningPipelineOrchestrator {
public:
    static ReasoningPipelineOrchestrator& instance();

    ReasoningPipelineOrchestrator(const ReasoningPipelineOrchestrator&)            = delete;
    ReasoningPipelineOrchestrator& operator=(const ReasoningPipelineOrchestrator&) = delete;

    // --- Configuration ---
    void setInferenceCallback(InferenceCallback cb);
    void setStreamingCallback(StreamingInferenceCallback cb);
    void setDefaultModel(const std::string& model);

    // --- Primary entry point ---
    // Classifies the input, applies the profile, routes, runs, then emits
    // telemetry and returns. This is the only entry point callers need; the
    // mode-specific execute* overloads exist so a caller can force a mode.
    PipelineResult execute(const std::string& userInput,
                           const std::string& context = "");

    PipelineResult executeFast(const std::string& input, const std::string& context);
    PipelineResult executeNormal(const std::string& input, const std::string& context);
    PipelineResult executeDeep(const std::string& input, const std::string& context);
    PipelineResult executeCritical(const std::string& input, const std::string& context);
    PipelineResult executeSwarm(const std::string& input, const std::string& context);

    // --- Control ---
    void cancel();
    bool isRunning() const;

    // --- Routing predicates ---
    InputComplexity classifyInput(const std::string& input) const;
    bool shouldBypass(const std::string& input, InputComplexity complexity) const;

    // --- Depth / mode resolution ---
    int            computeEffectiveDepth(const ReasoningProfile& profile,
                                         InputComplexity complexity) const;
    int            applyAdaptiveAdjustment(int baseDepth, const ReasoningProfile& profile) const;
    int            applyThermalThrottling(int depth, const ReasoningProfile& profile) const;
    ReasoningMode  resolveEffectiveMode(const ReasoningProfile& profile,
                                        InputComplexity complexity,
                                        int effectiveDepth) const;
    std::vector<std::string> buildAgentChain(const ReasoningProfile& profile,
                                             int effectiveDepth) const;
    std::string getSystemPromptForRole(const std::string& role) const;

    // --- Execution strategies ---
    PipelineResult runDirectLLM(const std::string& input, const std::string& context) const;
    PipelineResult runChainedPipeline(const std::string& input,
                                      const std::string& context,
                                      const std::vector<std::string>& chain,
                                      const ReasoningProfile& profile);
    PipelineResult runSwarmPipeline(const std::string& input,
                                    const std::string& context,
                                    const ReasoningProfile& profile);

    // --- Swarm combinators ---
    std::string swarmParallelVote(const std::vector<SwarmAgentResult>& results,
                                  float voteThreshold) const;
    std::string swarmTournament(std::vector<SwarmAgentResult>& results,
                                int rounds,
                                const std::string& input) const;
    std::string swarmEnsemble(const std::vector<SwarmAgentResult>& results,
                              float weightDecay) const;

    // --- Output shaping ---
    std::string enforceFinalAnswer(const std::string& finalOutput,
                                   const std::vector<PipelineStepResult>& steps,
                                   const ReasoningProfile& profile) const;
    float estimateConfidence(const std::string& output) const;
    float estimateQuality(const std::string& output, const std::string& input) const;
    PipelineResult::VisibleOutput formatVisibleOutput(const PipelineResult& result,
                                                       const ReasoningProfile& profile) const;

    // --- Thermal monitor ---
    // Owns a background std::thread. start() is idempotent; the destructor calls
    // stop() after cancel(), so the thread is always joined before the members
    // it captures go away.
    void startThermalMonitor();
    void stopThermalMonitor();
    bool isThermalMonitorRunning() const;

    // --- Feedback / self-tuning / telemetry ---
    void          feedUserFeedback(uint64_t requestId, bool accepted, bool edited);
    SelfTuneState getSelfTuneState() const;

    // Records one ReasoningTelemetry sample with the profile manager and, when
    // self-tuning is enabled, one SelfTuneObservation. Non-const: it bumps the
    // request counter and takes the mutex (reasoning_pipeline_orchestrator.cpp
    // :1190-1239).
    void emitTelemetry(const PipelineResult& result, const std::string& input);

    // --- Statistics ---
    // Trivially copyable and zeroed with memset, so no default initialisers
    // here -- see the header note.
    struct OrchestratorStats {
        uint64_t totalExecutions;
        uint64_t fastExecutions;
        uint64_t normalExecutions;
        uint64_t deepExecutions;
        uint64_t criticalExecutions;
        uint64_t swarmExecutions;
        uint64_t bypassed;
        uint64_t fallbacksUsed;
        uint64_t adaptiveAdjustments;
        uint64_t thermalThrottles;
        uint64_t errorCount;
        double   avgLatencyMs;
        float    avgConfidence;
    };

    OrchestratorStats getStats() const;
    void             resetStats();

private:
    ReasoningPipelineOrchestrator();
    ~ReasoningPipelineOrchestrator();

    void thermalMonitorLoop();

    // Guards the configuration block and m_stats. Mutable because the const
    // execution paths (runDirectLLM, runChainedPipeline) read the callbacks and
    // the model under it.
    mutable std::mutex m_mutex;

    InferenceCallback        m_inferenceCallback;
    StreamingInferenceCallback m_streamingCallback;
    std::string              m_defaultModel;

    std::atomic<bool> m_running;
    std::atomic<bool> m_cancelled;
    uint64_t          m_requestCounter;

    // Exponential moving average of end-to-end latency, seeded on the first
    // completed request. Adaptive depth uses it; resetStats() clears it.
    double m_ewmaLatency;
    bool   m_ewmaInitialized;

    OrchestratorStats m_stats;

    std::atomic<bool> m_thermalMonitorRunning;
    std::atomic<bool> m_thermalStopFlag;
    std::thread       m_thermalThread;
};