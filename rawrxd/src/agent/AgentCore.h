// AgentCore.h — RAWRXD_LOCAL_AGENT_E2E_001
//
// One autonomous agent core, usable from any front end (rawr CLI, IDE chat).
// The first certified mode is READ_ONLY: it may observe the repository and
// reason about it, and it may not write anything.
//
// The loop is genuine. If the model does not emit a tool request, the run
// FAILS; it does not fabricate one. Every transition is recorded from what
// actually happened, and the verdict is derived from those measurements.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "deep2/Deep2Engine.h"   // GenerationResult / GenerationStatus

namespace rawrxd { namespace agentcore {

// ---------------------------------------------------------------- model side

// The inference plane the core reasons over. Implemented over Deep2 in
// LocalModelBackend; kept abstract so a front end can swap it.
class IModelBackend {
public:
    virtual ~IModelBackend() = default;
    virtual const std::string& modelRef() const = 0;
    virtual const std::string& resolvedPath() const = 0;
    virtual bool available(std::string& reason) = 0;
    // Returns generated text. Sets `ok` false and `reason` on failure.
    virtual std::string generate(const std::string& prompt,
                                 uint32_t maxTokens,
                                 bool& ok,
                                 std::string& reason) = 0;
    // Tokens emitted by the most recent generate() call, counted from the
    // stream callback rather than estimated from the text length.
    virtual uint32_t lastTokenCount() const { return 0; }
    // The engine's own report for the most recent call. Authoritative.
    virtual uint64_t engineGeneratedTokens() const { return 0; }
    virtual uint64_t enginePromptTokens()    const { return 0; }
    virtual std::string engineStatus()       const { return "NONE"; }
    virtual std::string engineFailureDetail()const { return {}; }
    virtual double enginePromptMs()          const { return 0.0; }
    virtual double engineGenerationMs()      const { return 0.0; }
};

// Real Deep2-backed model, addressed by Ollama reference, path, or alias.
class LocalModelBackend final : public IModelBackend {
public:
    explicit LocalModelBackend(std::string modelRef, uint32_t maxTokens = 96);
    const std::string& modelRef() const override { return modelRef_; }
    bool available(std::string& reason) override;
    std::string generate(const std::string& prompt, uint32_t maxTokens,
                         bool& ok, std::string& reason) override;
    uint32_t    lastTokenCount() const override { return lastTokenCount_; }
    uint64_t    engineGeneratedTokens()  const override { return eng_.generatedTokens; }
    uint64_t    enginePromptTokens()     const override { return eng_.promptTokens; }
    std::string engineStatus()            const override { return engStatus_; }
    std::string engineFailureDetail()     const override { return engDetail_; }
    double      enginePromptMs()           const override { return eng_.promptTimeMs; }
    double      engineGenerationMs()       const override { return eng_.generationTimeMs; }
    const std::string& resolvedPath() const { return resolvedPath_; }

private:
    std::string modelRef_;
    uint32_t    maxTokens_ = 96;
    uint32_t    lastTokenCount_ = 0;
    std::string resolvedPath_;
    Deep2::GenerationResult eng_{};
    std::string engStatus_ = "NONE";
    std::string engDetail_;
};

// ---------------------------------------------------------------- tool side

// A parsed tool request. Deliberately a two-line line-oriented protocol
// (TOOL:/ARG:) because small local models follow it far more reliably than
// JSON, which they routinely malform.
struct ToolRequest {
    bool        present = false;
    std::string tool;      // see kReadOnlyToolNames
    std::string argument;  // constrained per tool; never a raw command line
    std::string raw;       // verbatim text the parser accepted
};

// The complete READ_ONLY tool set. The model may only NAME one of these; it
// can never supply an executable, a subcommand outside this list, or a free
// command line. `git` is invoked with a fixed argument vector through
// CreateProcess, never through a shell, so no metacharacter, redirection or
// pipeline can be interpreted.
extern const char* const kReadOnlyToolNames[];
extern const int         kReadOnlyToolCount;

enum class ToolOutcome { Executed, RejectedNotAllowed, RejectedPathEscape, ParseFailed, NotRequested };

// Read-only tool registry. There is no write path in this class by design:
// a WRITE tool cannot be added to a READ_ONLY run.

// Cap on the observation handed to the model. Large enough to answer a real
// question, small enough that the second turn stays tractable on an engine
// that re-runs every layer for every token.
constexpr size_t kMaxObservationBytes = 1200;

class ReadOnlyToolbox {
public:
    explicit ReadOnlyToolbox(std::string repoRoot);
    ToolOutcome execute(const ToolRequest& req, std::string& output, std::string& detail);
    uint32_t    callCount()  const { return calls_; }
    uint32_t    rejectCount() const { return rejects_; }
    int32_t     lastExitCode() const { return lastExitCode_; }

private:
    std::string repoRoot_;
    uint32_t    calls_   = 0;
    uint32_t    rejects_ = 0;
    int32_t     lastExitCode_ = -1;
};

// Extract a tool request from model text. Tolerates surrounding prose and
// light formatting noise, but requires a recognizable TOOL/PATH pair.
ToolRequest parseToolRequest(const std::string& text);

// ------------------------------------------------------------------ the core

struct AgentTask {
    std::string objective;
    std::string context;
    uint32_t    maxTurns = 3;
};

enum class Phase { Plan, Act, Observe, Continue, Complete, Failed };

struct Transition {
    Phase       phase = Phase::Plan;
    std::string detail;
};

struct AgentRun {
    bool        success = false;
    std::string modelRef;
    std::string resolvedPath;

    std::vector<Transition> transitions;
    std::string plan;
    std::string toolRequestRaw;
    std::string observation;
    std::string finalResponse;

    bool        modelResolved   = false;
    bool        modelLoaded     = false;
    bool        planned         = false;
    bool        toolRequested   = false;
    bool        toolExecuted    = false;
    bool        toolRejected    = false;
    bool        observationUsed = false;
    bool        completed       = false;
    // True when the tool output exceeded kMaxObservationBytes and the model saw
    // a clipped observation. The receipt states this rather than presenting a
    // truncated observation as if it were the whole one.
    bool        observationTruncated = false;

    uint32_t    toolCalls       = 0;
    uint32_t    toolRejects     = 0;
    uint32_t    stubFallbacks   = 0;   // always 0; the core has no fallback path
    std::string verdict;
    std::string rationale;

    // ---- measurements the RAWRXD_LOCAL_AGENT_E2E_001 contract requires ----
    uint32_t    agentTurnCount        = 0;   // model inference turns
    uint32_t    planTokenCount        = 0;   // generated tokens, turn 1
    uint32_t    finalTokenCount       = 0;   // generated tokens, turn 2
    bool        modelActionGenerated  = false;
    bool        toolRequestParsed     = false;
    bool        toolAuthorized        = false;
    bool        toolObservationCaptured = false;
    bool        observationReturnedToModel = false;
    bool        modelConsumedObservation = false;
    int32_t     toolExitCode          = -1;  // -1 => tool never ran
    // Structural facts about the tool surface, not claims about intent.
    uint32_t    mutatingToolsAvailable   = 0;
    uint32_t    arbitraryShellAvailable  = 0;
    uint32_t    fakeToolResults          = 0;

    // What the engine itself reported for the most recent generate() call.
    // The engine is authoritative about its own token count and outcome; the
    // callback counter is a second opinion, not a replacement.
    uint64_t    engineGeneratedTokens = 0;
    uint64_t    enginePromptTokens    = 0;
    std::string engineStatus          = "NONE";
    std::string engineFailureDetail;
    double      enginePromptMs        = 0.0;
    double      engineGenerationMs    = 0.0;
};

// Run one READ_ONLY PLAN -> ACT -> OBSERVE -> CONTINUE cycle.
// Never writes to the repository.
AgentRun runReadOnly(const AgentTask& task, IModelBackend& backend,
                     ReadOnlyToolbox& toolbox);

// Derive the verdict from measured state. A run that did not genuinely
// execute a real tool call is never a PASS.
std::string deriveVerdict(const AgentRun& run);

// Write RAWRXD_LOCAL_AGENT_E2E_001 from a measured run.
void writeAgentReceipt(const std::string& path, const AgentRun& run);

// Receipt the core flushes to mid-run, so a long or killed second turn still
// leaves evidence of the completed PLAN->ACT->OBSERVE steps.
void setReceiptPath(const std::string& p);

}} // namespace rawrxd::agentcore
