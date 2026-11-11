// =============================================================================
// agent_action.h — Normalized Agent Action Representation
// =============================================================================
// A provider-independent description of what the model wants to do next.
//
// The agent engine (RawrXD) must not depend on any single model's native tool
// calling syntax. A model that emits OpenAI-style function calls, one that
// emits a bare JSON object, and one that emits a tagged text block all reach
// the same engine through this representation. The engine then decides, under
// the permission gate, whether the action may run.
//
// The type set is intentionally coarse: it describes the KIND of authority an
// action needs (read / search / list / mutate / execute), not the specific
// tool. The concrete tool name is carried alongside so the registry can
// dispatch it unchanged.
//
// This header is dependency-free: it depends on nothing but the standard
// library, so both the CLI and the certification harness can include it.
// =============================================================================
#pragma once

#include <string>
#include <vector>

namespace RawrXD {
namespace Agentic {

enum class AgentActionType : uint8_t {
    Unknown = 0,
    Read,        ///< inspect file contents
    Search,      ///< find text or paths
    List,        ///< enumerate a directory
    Edit,        ///< modify an existing file
    Write,       ///< create a file or directory
    Shell,       ///< execute a command
    Build,       ///< compile the project
    Test,        ///< run the test suite
    Run,         ///< run the produced artifact
    ReadImage,   ///< inspect a rendered image
    Browser,     ///< drive a browser
    Finish,      ///< the model produced its final answer
};

inline const char* AgentActionTypeName(AgentActionType t) {
    switch (t) {
        case AgentActionType::Read:      return "read";
        case AgentActionType::Search:    return "search";
        case AgentActionType::List:      return "list";
        case AgentActionType::Edit:      return "edit";
        case AgentActionType::Write:     return "write";
        case AgentActionType::Shell:     return "shell";
        case AgentActionType::Build:     return "build";
        case AgentActionType::Test:      return "test";
        case AgentActionType::Run:       return "run";
        case AgentActionType::ReadImage: return "read_image";
        case AgentActionType::Browser:   return "browser";
        case AgentActionType::Finish:    return "finish";
        default:                         return "unknown";
    }
}

/// @brief Does this action kind require mutation authority?
inline bool AgentActionTypeMutates(AgentActionType t) {
    switch (t) {
        case AgentActionType::Edit:
        case AgentActionType::Write:
        case AgentActionType::Shell:
        case AgentActionType::Build:
        case AgentActionType::Test:
        case AgentActionType::Run:
            return true;
        default:
            return false;
    }
}

/// @brief Does this action kind require execution authority?
inline bool AgentActionTypeExecutes(AgentActionType t) {
    switch (t) {
        case AgentActionType::Shell:
        case AgentActionType::Build:
        case AgentActionType::Test:
        case AgentActionType::Run:
        case AgentActionType::Browser:
            return true;
        default:
            return false;
    }
}

/// @brief A single normalized action proposed by a model.
struct AgentAction {
    AgentActionType type = AgentActionType::Unknown;
    std::string     tool;        ///< concrete registry tool name
    std::string     arguments;   ///< JSON object text
    std::string     id;          ///< provider-assigned call id, when present
    bool            valid = false;
};

/// @brief Map a registry tool name onto its normalized action kind.
///
/// The mapping covers the RawrXD tool registry. Unknown tools map to
/// Unknown rather than being guessed at, so an unrecognized tool cannot be
/// silently treated as a read.
inline AgentActionType ClassifyAgentTool(const std::string& tool) {
    if (tool == "readFile")          return AgentActionType::Read;
    if (tool == "read_motd")         return AgentActionType::Read;
    if (tool == "fileSearch")        return AgentActionType::Search;
    if (tool == "textSearch")        return AgentActionType::Search;
    if (tool == "listDirectory")     return AgentActionType::List;
    if (tool == "editFiles")         return AgentActionType::Edit;
    if (tool == "createFile")        return AgentActionType::Write;
    if (tool == "createDirectory")   return AgentActionType::Write;
    if (tool == "runInTerminal")     return AgentActionType::Shell;
    if (tool == "run_build")         return AgentActionType::Build;
    if (tool == "build")             return AgentActionType::Build;
    if (tool == "run_tests")         return AgentActionType::Test;
    if (tool == "test")              return AgentActionType::Test;
    if (tool == "run")               return AgentActionType::Run;
    if (tool == "readImage")         return AgentActionType::ReadImage;
    if (tool == "browser")           return AgentActionType::Browser;
    if (tool == "finish")            return AgentActionType::Finish;
    return AgentActionType::Unknown;
}

/// @brief Build a normalized action from a tool name and JSON argument text.
inline AgentAction MakeAgentAction(const std::string& tool,
                                   const std::string& arguments,
                                   const std::string& id = std::string()) {
    AgentAction a;
    a.tool = tool;
    a.arguments = arguments;
    a.id = id;
    a.type = ClassifyAgentTool(tool);
    a.valid = !tool.empty() && a.type != AgentActionType::Unknown;
    return a;
}

/// @brief Build a normalized action from a parsed tool call.
///
/// ParsedToolCall lives in tool_call_parser.h; the dependency is forward
// declared here so this header stays free of the JSON dependency.
struct ParsedToolCallView {
    std::string name;
    std::string arguments_json;
    std::string id;
};

inline AgentAction MakeAgentAction(const ParsedToolCallView& call) {
    return MakeAgentAction(call.name, call.arguments_json, call.id);
}

} // namespace Agentic
} // namespace RawrXD
