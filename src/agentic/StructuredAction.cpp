// =============================================================================
// StructuredAction.cpp — Strict validation + bounded repair (fail-closed)
// =============================================================================
#include "StructuredAction.h"
#include <sstream>
#include <set>

namespace RawrXD {
namespace Agent {

// ---------------------------------------------------------------------------
// Strict JSON parse with duplicate-key detection
// ---------------------------------------------------------------------------
StrictParseResult ParseStrictJson(const std::string& text) {
    StrictParseResult r;

    if (text.empty()) {
        r.error = "empty response";
        return r;
    }

    // Reject obvious prose instead of blowing up the parser.
    // An action envelope MUST begin with '{' after optional whitespace.
    size_t first = text.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) {
        r.error = "response is whitespace only";
        return r;
    }
    if (text[first] != '{') {
        r.error = "response does not begin with a JSON object (got '" +
                  text.substr(first, 24) + "')";
        return r;
    }

    try {
        r.value = json::parse(text);
    } catch (const json::parse_error& e) {
        r.error = std::string("JSON parse error: ") + e.what();
        return r;
    }

    if (!r.value.is_object()) {
        r.error = "top-level value is not a JSON object";
        return r;
    }

    // Duplicate-key detection: nlohmann keeps the last occurrence, so we scan
    // the raw text for repeated key spellings at the same nesting level using
    // the SAX-free approach of re-parsing with a callback that records keys.
    {
        json::parser_callback_t cb = [&r, &seen = std::as_const(r)](
                                         int depth, json::parse_event_t ev, json& parsed) -> bool {
            if (ev == json::parse_event_t::key) {
                // The parsed value is the key string.
                if (parsed.is_string()) {
                    r.duplicate_keys.push_back(parsed.get<std::string>());
                }
            }
            return true;
        };
        std::vector<std::string> keys;
        json::parser_callback_t key_cb = [&keys](int depth, json::parse_event_t ev, json& parsed) -> bool {
            if (ev == json::parse_event_t::key && parsed.is_string()) {
                keys.push_back(parsed.get<std::string>());
            }
            return true;
        };
        try {
            json::parse(text, key_cb, true);
        } catch (const json::parse_error&) {
            // Already reported above.
        }
        // Detect any key that appears more than once anywhere in the document.
        // This is intentionally coarse: a repeated key at ANY level in a single
        // action envelope is a malformed response and must fail closed.
        std::set<std::string> unique_keys(keys.begin(), keys.end());
        if (unique_keys.size() != keys.size()) {
            for (const auto& k : unique_keys) {
                int n = static_cast<int>(std::count(keys.begin(), keys.end(), k));
                if (n > 1) {
                    bool already = false;
                    for (const auto& d : r.duplicate_keys) if (d == k) { already = true; break; }
                    if (!already) r.duplicate_keys.emplace_back(k);
                }
            }
            if (!r.duplicate_keys.empty()) {
                std::ostringstream oss;
                oss << "duplicate keys: ";
                for (size_t i = 0; i < r.duplicate_keys.size(); ++i) {
                    if (i) oss << ", ";
                    oss << "'" << r.duplicate_keys[i] << "'";
                }
                r.error = oss.str();
                return r;
            }
        }
    }

    r.ok = true;
    return r;
}

// ---------------------------------------------------------------------------
// Tool schema registry
// ---------------------------------------------------------------------------
std::vector<ToolSpec> StructuredSchema::BuiltinTools() {
    return {
        {"list_repo", "List directory entries in the workspace",
         {{"path", "path", false}}},
        {"read_file", "Read a bounded workspace file",
         {{"path", "path", true}}},
        {"search_text", "Search workspace text for a phrase",
         {{"query", "string", true}, {"path", "path", false}}},
        {"git_status", "Show working tree status",
         {}},
        {"write_file", "Create a new file inside the workspace",
         {{"path", "path", true}, {"content", "string", true}}},
        {"run_build", "Build the project and report the real exit code",
         {{"config", "string", false}, {"target", "string", false}}},
        {"run_tests", "Run tests and report the real exit code",
         {{"filter", "string", false}}},
    };
}

const ToolSpec* StructuredSchema::Find(const std::string& tool_name) {
    static const std::vector<ToolSpec> kTools = BuiltinTools();
    for (const auto& t : kTools) {
        if (t.name == tool_name) return &t;
    }
    return nullptr;
}

std::string StructuredSchema::ValidateArgs(const ToolSpec& spec, const json& args) {
    if (!args.is_object()) {
        return "'args' must be a JSON object for tool '" + spec.name + "'";
    }

    // Required-argument check.
    for (const auto& a : spec.args) {
        if (!a.required) continue;
        if (!args.contains(a.name)) {
            return "missing required argument '" + a.name + "' for tool '" + spec.name + "'";
        }
    }

    // Type check for declared arguments. Unknown args are permitted (forward
    // compatibility) but reported so the schema can be tightened later.
    for (auto it = args.begin(); it != args.end(); ++it) {
        const std::string& key = it.key();
        const ToolArgSpec* spec_arg = nullptr;
        for (const auto& a : spec.args) {
            if (a.name == key) { spec_arg = &a; break; }
        }
        if (!spec_arg) continue;

        const json& v = it.value();
        if (spec_arg->type == "string") {
            if (!v.is_string()) {
                return "argument '" + key + "' must be a string";
            }
        } else if (spec_arg->type == "int") {
            if (!v.is_number_integer()) {
                return "argument '" + key + "' must be an integer";
            }
        } else if (spec_arg->type == "bool") {
            if (!v.is_boolean()) {
                return "argument '" + key + "' must be a boolean";
            }
        } else if (spec_arg->type == "object") {
            if (!v.is_object()) {
                return "argument '" + key + "' must be an object";
            }
        } else if (spec_arg->type == "array") {
            if (!v.is_array()) {
                return "argument '" + key + "' must be an array";
            }
        } else if (spec_arg->type == "path") {
            if (!v.is_string()) {
                return "argument '" + key + "' must be a path string";
            }
            const std::string p = v.get<std::string>();
            if (p.empty()) {
                return "argument '" + key + "' path must not be empty";
            }
            // A path argument that is a phrase rather than a path is rejected
            // here too, so it fails closed instead of being dispatched.
            if (p.find(' ') != std::string::npos &&
                p.find('/') == std::string::npos &&
                p.find('\\') == std::string::npos) {
                return "argument '" + key + "' looks like a phrase, not a path (" + p + ")";
            }
        }
    }
    return {};
}

std::string StructuredSchema::Validate(const std::string& tool_name, const json& args) {
    const ToolSpec* spec = Find(tool_name);
    if (!spec) {
        return "unknown tool '" + tool_name + "'";
    }
    return ValidateArgs(*spec, args);
}

// ---------------------------------------------------------------------------
// Controller
// ---------------------------------------------------------------------------
StructuredOutputController::StructuredOutputController(InferenceBackend* backend)
    : m_backend(backend) {}

void StructuredOutputController::ResetStats() {
    m_parse_failures = 0;
    m_repairs_used = 0;
    m_turns = 0;
}

std::vector<ChatMessage> StructuredOutputController::BuildActionPrompt(
    const std::string& objective,
    const std::vector<ChatMessage>& history,
    AgentMode mode) {

    std::vector<ChatMessage> messages;

    std::string mode_note;
    switch (mode) {
        case AgentMode::Ask:
        case AgentMode::Review:
        case AgentMode::Research:
            mode_note = "You are READ-ONLY in this mode. You may not modify "
                        "files or execute commands. Use read_file, search_text, "
                        "list_repo, git_status only.";
            break;
        case AgentMode::Plan:
        case AgentMode::Architect:
        case AgentMode::Audit:
            mode_note = "You may only write under the .rawrxd/plans directory. "
                        "You may not modify project source or run builds.";
            break;
        default:
            mode_note = "You may read, search, edit and build within the "
                        "workspace, subject to native permission checks.";
            break;
    }

    messages.push_back({
        "system",
        "You are RawrXD, a local autonomous coding agent. "
        "You must answer with exactly ONE JSON action and nothing else.\n"
        "Two action shapes are allowed:\n"
        "TOOL: {\"action\":\"tool\",\"tool\":\"<name>\",\"args\":{...}}\n"
        "FINAL: {\"action\":\"final\",\"summary\":\"<text>\",\"findings\":[...],\"next_actions\":[...]}\n"
        "Rules:\n"
        "- Emit ONE action per response. Never combine a tool call and a final\n"
        "  response, and never emit prose before or after the JSON object.\n"
        "- Every property name MUST be double-quoted. No duplicate keys.\n"
        "- Prefer the smallest args object that works.\n"
        "- When you have finished, use the final action ONCE.\n"
        + mode_note
    });

    for (const auto& m : history) messages.push_back(m);

    if (!objective.empty()) {
        messages.push_back({"user", objective});
    }

    return messages;
}

ValidatedAction StructuredOutputController::ValidateResponse(const std::string& raw) const {
    StrictParseResult parsed = ParseStrictJson(raw);
    if (!parsed.ok) {
        m_parse_failures++;
        return ValidatedAction::MakeInvalid(parsed.error);
    }

    const json& obj = parsed.value;

    // Required: action discriminator.
    if (!obj.contains("action") || !obj["action"].is_string()) {
        return ValidatedAction::MakeInvalid(
            "missing or non-string required field 'action'");
    }
    const std::string action = obj["action"].get<std::string>();

    if (action == "final") {
        ValidatedAction a;
        a.kind = ActionKind::Final;
        a.summary = obj.value("summary", std::string());
        a.findings = obj.value("findings", json::array());
        a.next_actions = obj.value("next_actions", json::array());

        if (a.summary.empty()) {
            return ValidatedAction::MakeInvalid(
                "final action requires a non-empty 'summary' string");
        }
        if (!a.findings.is_array()) {
            return ValidatedAction::MakeInvalid(
                "'findings' must be a JSON array");
        }
        if (!a.next_actions.is_array()) {
            return ValidatedAction::MakeInvalid(
                "'next_actions' must be a JSON array");
        }
        // A final action must not also carry a tool call. This is the
        // "tool calls after the controller requested a final response" defect.
        if (obj.contains("tool") || obj.contains("args")) {
            return ValidatedAction::MakeInvalid(
                "final action must not contain 'tool' or 'args' fields");
        }
        a.valid = true;
        return a;
    }

    if (action == "tool") {
        if (!obj.contains("tool") || !obj["tool"].is_string()) {
            return ValidatedAction::MakeInvalid(
                "tool action requires a string 'tool' field");
        }
        const std::string tool = obj["tool"].get<std::string>();

        ValidatedAction a;
        a.kind = ActionKind::Tool;
        a.tool = tool;
        a.args = obj.value("args", json::object());

        // Schema validation.
        std::string err = StructuredSchema::Validate(tool, a.args);
        if (!err.empty()) {
            return ValidatedAction::MakeInvalid(err);
        }

        // Authorization. Grammar-valid is NOT authorized.
        if (m_permission) {
            if (!m_permission(tool, a.args)) {
                a.unauthorized = true;
                return ValidatedAction::MakeInvalid(
                    "tool '" + tool + "' is not authorized in the current mode");
            }
        }
        a.valid = true;
        return a;
    }

    return ValidatedAction::MakeInvalid(
        "unknown action '" + action + "' (expected \"tool\" or \"final\")");
}

ValidatedAction StructuredOutputController::RepairOnce(
    std::vector<ChatMessage>& history,
    const std::string& previous_error) {

    // Bounded: exactly one repair request, ever.
    history.push_back({
        "assistant",
        "The previous response was rejected. Reason: " + previous_error
    });
    history.push_back({
        "user",
        "That response was not a valid action. Reply with exactly ONE corrected "
        "JSON object and nothing else. Do not repeat the previous mistake. Use "
        "either {\"action\":\"tool\",\"tool\":\"<name>\",\"args\":{...}} or "
        "{\"action\":\"final\",\"summary\":\"...\",\"findings\":[],\"next_actions\":[]}."
    });

    m_repairs_used++;

    InferenceResult result = m_backend->ChatSync(history, json::array());
    if (!result.success) {
        m_parse_failures++;
        return ValidatedAction::MakeInvalid(
            "repair request failed: " + result.error_message);
    }

    return ValidateResponse(result.response);
}

ValidatedAction StructuredOutputController::NextAction(
    std::vector<ChatMessage>& history) {

    m_turns++;

    if (!m_backend) {
        return ValidatedAction::MakeInvalid("no inference backend configured");
    }

    InferenceResult result = m_backend->ChatSync(history, json::array());
    if (!result.success) {
        m_parse_failures++;
        return ValidatedAction::MakeInvalid(
            "inference failed: " + result.error_message);
    }

    ValidatedAction action = ValidateResponse(result.response);
    if (action.valid) return action;

    // One bounded repair.
    ValidatedAction repaired = RepairOnce(history, action.error);
    if (repaired.valid) {
        repaired.repaired = true;
        return repaired;
    }

    // Fail closed with a structured error. No further requests are issued.
    return repaired;
}

} // namespace Agent
} // namespace RawrXD
