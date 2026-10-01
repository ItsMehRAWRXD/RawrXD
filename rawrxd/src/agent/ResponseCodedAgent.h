// ResponseCodedAgent.h — RAWRXD_RESPONSE_CODED_AGENT_001
//
// One user turn drives one bounded agent turn. The model writes the response;
// the host supplies only machinery: inference, protocol parse, authority check,
// real tool execution, observation, one more inference, stop.
//
// There is deliberately no loop, no background work, no self-prompting, no
// self-assigned task, no repository mutation, and no arbitrary shell. The
// model may request at most one whitelisted read-only tool per turn.
//
// The host must never infer intent from keywords. Nothing here inspects the
// user's words to decide which tool to run; the model emits RAWR_TOOL
// explicitly or it gets no tool call at all.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace rawrxd { namespace rcagent {

// ------------------------------------------------------------ the model side

class IModelBackend {
public:
    virtual ~IModelBackend() = default;
    virtual bool available(std::string& reason) = 0;
    virtual std::string generate(const std::string& prompt, uint32_t maxTokens,
                                 bool& ok, std::string& reason) = 0;
    virtual const std::string& modelRef() const = 0;
    virtual const std::string& resolvedPath() const = 0;
    // Drop any cached KV/session state. A new user turn starts a new session.
    virtual void beginNewSession() = 0;
};

class LocalModelBackend final : public IModelBackend {
public:
    explicit LocalModelBackend(std::string modelRef);
    bool available(std::string& reason) override;
    std::string generate(const std::string& prompt, uint32_t maxTokens,
                         bool& ok, std::string& reason) override;
    const std::string& modelRef() const override { return modelRef_; }
    const std::string& resolvedPath() const override { return resolvedPath_; }
    void beginNewSession() override;

private:
    std::string modelRef_;
    std::string resolvedPath_;
    bool        sessionFresh_ = true;
};

// ------------------------------------------------------------ the tool side

// The complete, fixed, READ_ONLY registry. A tool not listed here cannot be
// invoked by any means. There is no write, delete, network, or shell entry,
// so no tool call in this agent can mutate anything.
struct ToolSpec {
    const char* name;
    const char* description;
};

// A tool the model asked for, already authorised by the registry.
struct ToolRequest {
    bool        present = false;
    std::string name;
    std::string arg;
    std::string raw;
};

enum class ToolStatus { NotRequested, NotWhitelisted, Executed, ExecutionFailed };

struct ToolOutcome {
    ToolStatus  status = ToolStatus::NotRequested;
    std::string tool;
    int         exitCode = 0;
    std::string output;
    std::string detail;
};

// The registry is data, not behaviour: the host never decides which tool a
// question needs, and never runs a tool the model did not name.
const std::vector<ToolSpec>& toolRegistry();
bool isWhitelisted(const std::string& name);

// Execute exactly one whitelisted read-only tool. Rejects anything else.
ToolOutcome executeTool(const std::string& repoRoot, const ToolRequest& req);

// ------------------------------------------------------------- the protocol

// Parse a model turn. The model must open with RAWR_TOOL or RAWR_RESPONSE.
struct ModelTurn {
    bool        sawToolTag    = false;
    bool        sawResponseTag = false;
    bool        hasTool       = false;
    ToolRequest tool;
    std::string response;
    std::string raw;
    std::string malformed;     // non-empty when the protocol was violated
};

ModelTurn parseModelTurn(const std::string& text);

// ------------------------------------------------------------ the one turn

struct AgentTurn {
    std::string userInput;
    std::string modelRef;
    std::string resolvedPath;

    std::string firstTurn;     // the model's first emission, verbatim
    std::string toolRaw;
    std::string toolName;
    std::string observation;   // real tool output returned to the model
    std::string finalResponse; // the model's answer, verbatim

    bool        toolRequested = false;
    bool        toolExecuted  = false;
    int         toolExitCode  = 0;
    bool        protocolValid = false;
    bool        completed     = false;   // a final response was produced
    std::string verdict;
    std::string rationale;
};

// Run one bounded turn: one inference, at most one tool, one more inference,
// then STOP. Never mutates the repository.
AgentTurn runOneTurn(const std::string& userInput, IModelBackend& backend,
                     const std::string& repoRoot);

std::string deriveVerdict(const AgentTurn& t);
void writeReceipt(const std::string& path, const AgentTurn& t);

}} // namespace rawrxd::rcagent
