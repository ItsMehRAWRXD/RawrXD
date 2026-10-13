// =============================================================================
// StructuredOutput.h/.hpp role — Structured Action Controller (P0)
// =============================================================================
// Fixes the malformed-structured-output class of failure in the agent trace:
//   * unquoted property names        ("summary:")
//   * duplicate keys                 ("next_actions" twice)
//   * unbalanced brackets            ("]})
//   * tool calls after a final response was requested
//   * unrelated prose instead of the action envelope
//
// Contract (fail-closed, bounded):
//   1. The request is constrained by the corrected GBNF grammar
//      (structured_output.gbnf) when the backend supports constrained
//      decoding. Grammar enforcement is the inference backend's job; this
//      controller is the second line of defence.
//   2. Every decoded response is validated against a STRICT schema.
//   3. On validation failure, at most ONE bounded repair request is issued.
//   4. If the repair also fails, a structured error is returned. There is no
//      unbounded retry loop and no repeated "give me a ledger" prompting.
//   5. The controller emits exactly one action per turn. The final audit
//      ledger is assembled by the DRIVER from recorded tool results — never
//      trusted from a model-generated claim.
//   6. Authorization is resolved here too: grammar-valid is not
//      authorized. Tool name, argument schema, workspace restriction and mode
//      permission are enforced natively before dispatch.
// =============================================================================
#pragma once

#include "InferenceBackend.h"
#include "AgentMode.h"
#include "tool_core.hpp"

#include <string>
#include <vector>
#include <functional>
#include <optional>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace RawrXD {
namespace Agent {

// ---------------------------------------------------------------------------
// Action kinds
// ---------------------------------------------------------------------------
enum class ActionKind : uint8_t {
    Tool = 0,
    Final = 1,
    Invalid = 2,
};

// ---------------------------------------------------------------------------
// Validated action
// ---------------------------------------------------------------------------
struct ValidatedAction {
    ActionKind kind = ActionKind::Invalid;

    // Tool action
    std::string tool;
    json        args;

    // Final action
    std::string summary;
    json        findings = json::array();
    json        next_actions = json::array();

    // Validation state
    bool              valid = false;
    std::string       error;               // why it is invalid
    bool              repaired = false;     // one repair attempt was used
    bool              unauthorized = false;// tool refused by the permission gate

    static ValidatedAction MakeInvalid(std::string why) {
        ValidatedAction a;
        a.kind = ActionKind::Invalid;
        a.valid = false;
        a.error = std::move(why);
        return a;
    }
};

// ---------------------------------------------------------------------------
// Tool schema (authoritative, per tool)
// ---------------------------------------------------------------------------
struct ToolArgSpec {
    std::string name;
    std::string type;    // "path" | "string" | "int" | "bool" | "object" | "array"
    bool        required = true;
};

struct ToolSpec {
    std::string name;
    std::string description;
    std::vector<ToolArgSpec> args;
};

// ---------------------------------------------------------------------------
// Strict schema registry
// ---------------------------------------------------------------------------
class StructuredSchema {
public:
    // The seven grammar tools. `list_repo` covers directory listing, `read_file`
    // the bounded read, `search_text` the phrase search. Shell/build/test/git
    // are separate tools that must pass the same gate.
    static std::vector<ToolSpec> BuiltinTools();

    static const ToolSpec* Find(const std::string& tool_name);

    // Validate `args` against `spec`. Returns an empty string on success.
    static std::string ValidateArgs(const ToolSpec& spec, const json& args);

    // Convenience: validate by tool name.
    static std::string Validate(const std::string& tool_name, const json& args);
};

// ---------------------------------------------------------------------------
// Strict JSON parse with duplicate-key detection
// ---------------------------------------------------------------------------
// nlohmann::json silently keeps the last duplicate key. The trace showed
// duplicated keys, so we detect that explicitly and fail closed.
struct StrictParseResult {
    bool        ok = false;
    json        value;
    std::string error;
    std::vector<std::string> duplicate_keys;
};

StrictParseResult ParseStrictJson(const std::string& text);

// ---------------------------------------------------------------------------
// StructuredOutputController
// ---------------------------------------------------------------------------
class StructuredOutputController {
public:
    // `permission` is consulted BEFORE dispatch so an unauthorized action is
    // reported as unauthorized rather than executed then blamed.
    using PermissionFn = std::function<bool(const std::string& tool, const json& args)>;

    explicit StructuredOutputController(InferenceBackend* backend);
    ~StructuredOutputController() = default;

    void SetPermission(PermissionFn fn) { m_permission = std::move(fn); }
    void SetMode(AgentMode mode) { m_mode = mode; }
    AgentMode GetMode() const { return m_mode; }

    // ---- Grammar ----
    // Returns the GBNF source, from the embedded artifact.
    static std::string Grammar();

    // ---- Single turn ----
    // Requests ONE action, validates it, and returns it.
    // `history` is the full conversation so far (driver-owned).
    ValidatedAction NextAction(std::vector<ChatMessage>& history);

    // ---- Diagnostics ----
    int  ParseFailures() const { return m_parse_failures; }
    int  RepairsUsed() const { return m_repairs_used; }
    int  TurnsTaken() const { return m_turns; }
    void ResetStats();

    // ---- Prompt construction ----
    // Services the "minimal action envelope for small models" requirement:
    // the model is asked for ONE action, not an entire audit ledger.
    static std::vector<ChatMessage> BuildActionPrompt(
        const std::string& objective,
        const std::vector<ChatMessage>& history,
        AgentMode mode);

private:
    InferenceBackend* m_backend;
    PermissionFn      m_permission;
    AgentMode         m_mode = AgentMode::Code;

    // Mutable so the const ValidateResponse() can still count failures without
    // making the whole validation path non-const.
    mutable int m_parse_failures = 0;
    int m_repairs_used = 0;
    int m_turns = 0;

    // ---- Validation ----
    ValidatedAction ValidateResponse(const std::string& raw) const;

    // ---- Repair ----
    // Issues exactly one bounded repair request. Never loops.
    ValidatedAction RepairOnce(std::vector<ChatMessage>& history,
                               const std::string& previous_error);
};

// ---------------------------------------------------------------------------
// Grammar text (embedded so the binary is self-contained)
// ---------------------------------------------------------------------------
inline std::string StructuredOutputController::Grammar() {
    return R"GBNF(root ::= ws (toolcall | finalcall) ws

toolcall ::= "{" ws "\"action\"" ws ":" ws "\"tool\"" ws "," ws "\"tool\"" ws ":" ws tool ws "," ws "\"args\"" ws ":" ws object ws "}"

finalcall ::= "{" ws "\"action\"" ws ":" ws "\"final\"" ws "," ws "\"summary\"" ws ":" ws string ws "," ws "\"findings\"" ws ":" ws array ws "," ws "\"next_actions\"" ws ":" ws array ws "}"

tool ::= "\"list_repo\"" | "\"read_file\"" | "\"search_text\"" | "\"git_status\"" | "\"write_file\"" | "\"run_build\"" | "\"run_tests\""

object ::= "{" ws (pair (ws "," ws pair)*)? ws "}"
pair ::= string ws ":" ws value

array ::= "[" ws (value (ws "," ws value)*)? ws "]"

value ::= object | array | string | number | "true" | "false" | "null"

string ::= "\"" chars "\""
chars ::= char*
char ::= [^"\\\x00-\x1F] | "\\" (["\\/bfnrt] | "u" hex hex hex hex)
hex ::= [0-9a-fA-F]

number ::= "-"? int frac? exp?
int ::= "0" | [1-9] [0-9]*
frac ::= "." [0-9]+
exp ::= [eE] [+-]? [0-9]+

ws ::= [ \t\n\r]*
)GBNF";
}

} // namespace Agent
} // namespace RawrXD
