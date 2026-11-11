// tool_call_parser.cpp — Agentic Tool Call Parser implementation
// Parses both structured XML tool calls and natural language tool intent
// from model output. Handles TinyLlama's less-structured output gracefully.

#include "tool_call_parser.h"
#include <regex>
#include <algorithm>
#include <cctype>
#include <iostream>
#include <fstream>
#include <sstream>

namespace RawrXD {
namespace Agentic {

// ---------------------------------------------------------------------------
// Map natural language verbs/phrases to tool names
// ---------------------------------------------------------------------------
static std::string mapNaturalLanguageToTool(const std::string& text) {
    std::string lower = text;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c){ return std::tolower(c); });

    // Read operations
    if (lower.find("read") != std::string::npos ||
        lower.find("open") != std::string::npos ||
        lower.find("cat") != std::string::npos ||
        lower.find("show") != std::string::npos ||
        lower.find("display") != std::string::npos ||
        lower.find("view") != std::string::npos) {
        return "read_file";
    }

    // Write/edit operations
    if (lower.find("write") != std::string::npos ||
        lower.find("create") != std::string::npos ||
        lower.find("save") != std::string::npos) {
        return "write_file";
    }

    if (lower.find("edit") != std::string::npos ||
        lower.find("modify") != std::string::npos ||
        lower.find("fix") != std::string::npos ||
        lower.find("repair") != std::string::npos ||
        lower.find("replace") != std::string::npos) {
        return "edit_files";
    }

    // Search operations
    if (lower.find("search") != std::string::npos ||
        lower.find("grep") != std::string::npos ||
        lower.find("find") != std::string::npos) {
        return "grep_files";
    }

    // Build operations
    if (lower.find("build") != std::string::npos ||
        lower.find("compile") != std::string::npos ||
        lower.find("make") != std::string::npos) {
        return "run_build";
    }

    // Test operations
    if (lower.find("test") != std::string::npos ||
        lower.find("run test") != std::string::npos ||
        lower.find("ctest") != std::string::npos) {
        return "run_tests";
    }

    // Git operations
    if (lower.find("git status") != std::string::npos) {
        return "git_status";
    }
    if (lower.find("git diff") != std::string::npos) {
        return "git_diff";
    }

    return "";
}

// ---------------------------------------------------------------------------
// Extract a file path from natural language
// ---------------------------------------------------------------------------
static std::string extractFilePath(const std::string& text) {
    // Look for quoted strings first
    std::regex quotedRe("\"([^\"]+)\"");
    std::smatch match;
    if (std::regex_search(text, match, quotedRe)) {
        return match[1].str();
    }

    // Look for .cpp, .h, .hpp, .c, .cc extensions
    std::regex extRe("([\\w\\/\\\\.-]+\\.(?:cpp|cc|cxx|c|h|hpp|hxx|jsonl|txt|bat|sh))");
    if (std::regex_search(text, match, extRe)) {
        return match[1].str();
    }

    return "";
}

// ---------------------------------------------------------------------------
// Parse structured XML tool call format
// ---------------------------------------------------------------------------
static bool parseStructuredToolCall(const std::string& text,
                                     ParsedToolCall& out) {
    // Find <name>...</name>
    std::regex nameRe("<name>([^<]+)</name>");
    std::smatch nameMatch;
    if (!std::regex_search(text, nameMatch, nameRe)) {
        return false;
    }
    out.name = nameMatch[1].str();

    // Find <parameters>...</parameters>
    std::regex paramsRe("<parameters>([\\s\\S]*?)</parameters>");
    std::smatch paramsMatch;
    if (!std::regex_search(text, paramsMatch, paramsRe)) {
        // No parameters - try to extract path from surrounding text
        std::string path = extractFilePath(text);
        if (!path.empty()) {
            out.arguments["path"] = path;
        }
        return true;
    }

    std::string paramsStr = paramsMatch[1].str();

    // Try to parse as JSON
    try {
        out.arguments = nlohmann::json::parse(paramsStr);
    } catch (...) {
        // Not valid JSON - try to extract path
        std::string path = extractFilePath(paramsStr);
        if (!path.empty()) {
            out.arguments["path"] = path;
        }
        out.arguments["raw"] = paramsStr;
    }

    return true;
}

// ---------------------------------------------------------------------------
// Parse natural language tool intent
// ---------------------------------------------------------------------------
static bool parseNaturalLanguageToolCall(const std::string& text,
                                          ParsedToolCall& out) {
    std::string tool = mapNaturalLanguageToTool(text);
    if (tool.empty()) {
        return false;
    }

    // File-related tools require a path. If none found, don't return a
    // tool call — let the orchestrator fallback handle it.
    if (tool == "read_file" || tool == "write_file" || tool == "edit_files") {
        std::string path = extractFilePath(text);
        if (path.empty()) {
            return false;
        }
        out.arguments["path"] = path;
    }

    out.name = tool;
    return true;
}

std::string ToolCallParser::NormalizeToolName(const std::string& name) {
    // The RawrXD registry's canonical names, plus the legacy aliases models
    // commonly imitate. Mapping here keeps the dispatch path uniform.
    static const struct { const char* from; const char* to; } kAliases[] = {
        {"read_file",     "readFile"},
        {"readfile",      "readFile"},
        {"write_file",    "createFile"},
        {"create_file",   "createFile"},
        {"createfile",    "createFile"},
        {"edit_files",    "editFiles"},
        {"edit_file",     "editFiles"},
        {"editfiles",     "editFiles"},
        {"grep_files",    "textSearch"},
        {"text_search",   "textSearch"},
        {"search_text",   "textSearch"},
        {"file_search",   "fileSearch"},
        {"list_dir",      "listDirectory"},
        {"list_directory","listDirectory"},
        {"run_build",     "runInTerminal"},
        {"run_tests",     "runInTerminal"},
        {"run_test",      "runInTerminal"},
        {"git_status",    "runInTerminal"},
        {"git_diff",      "runInTerminal"},
        {"run_command",   "runInTerminal"},
        {"run_terminal",  "runInTerminal"},
    };
    for (const auto& a : kAliases) {
        if (name == a.from) return a.to;
    }
    return name;
}

// ---------------------------------------------------------------------------
// Public parse entry point
// ---------------------------------------------------------------------------
ToolCallParseResult ToolCallParser::parse(const std::string& modelOutput) {
    ToolCallParseResult result;
    if (modelOutput.empty()) return result;

    // Priority 1: a JSON function call in the text. This is the shape the
    // agent contract asks for, and the shape a model that was given the tool
    // schemas produces. It must be checked FIRST: the natural-language
    // heuristic below matches ordinary prose ("show me...") and would
    // otherwise hijack a real tool call.
    parseJsonFunctionCalls_(modelOutput, result.toolCalls);
    if (!result.toolCalls.empty()) {
        for (auto& c : result.toolCalls) c.name = NormalizeToolName(c.name);
        return result;
    }

    // Priority 2: the structured XML format.
    ParsedToolCall call;
    if (parseStructuredToolCall(modelOutput, call)) {
        call.name = NormalizeToolName(call.name);
        result.toolCalls.push_back(call);
        return result;
    }

    // Priority 3: the natural-language heuristic (small models only).
    if (parseNaturalLanguageToolCall(modelOutput, call)) {
        call.name = NormalizeToolName(call.name);
        result.toolCalls.push_back(call);
        return result;
    }

    return result;
}

// ---------------------------------------------------------------------------
// JSON function call extraction
// ---------------------------------------------------------------------------
void ToolCallParser::parseJsonFunctionCalls_(const std::string& text,
                                             std::vector<ParsedToolCall>& outCalls) {
    size_t i = 0;
    while (i < text.size()) {
        const size_t open = text.find('{', i);
        if (open == std::string::npos) break;
        size_t objStart = 0;
        size_t objEnd = 0;
        if (!extractBalancedJsonRange(text, open, objStart, objEnd)) break;
        const std::string blob = text.substr(objStart, objEnd - objStart + 1);
        i = objEnd + 1;

        nlohmann::json parsed;
        bool ok = false;
        try {
            parsed = nlohmann::json::parse(blob);
            ok = parsed.is_object();
        } catch (...) {
            ok = false;
        }
        if (!ok) continue;

        std::string name;
        nlohmann::json args = nlohmann::json::object();
        bool haveArgs = false;

        if (parsed.contains("function") && parsed["function"].is_object()) {
            const auto& fn = parsed["function"];
            if (fn.contains("name") && fn["name"].is_string()) name = fn["name"].get<std::string>();
            if (fn.contains("arguments")) { args = parseArgumentsValue_(fn["arguments"]); haveArgs = true; }
        }
        if (name.empty() && parsed.contains("name") && parsed["name"].is_string()) {
            name = parsed["name"].get<std::string>();
        }
        if (!haveArgs) {
            if (parsed.contains("arguments")) { args = parseArgumentsValue_(parsed["arguments"]); haveArgs = true; }
            else if (parsed.contains("args")) { args = parseArgumentsValue_(parsed["args"]); haveArgs = true; }
            else if (parsed.contains("parameters")) { args = parseArgumentsValue_(parsed["parameters"]); haveArgs = true; }
        }

        if (name.empty()) continue;
        // "action":"tool" is the envelope the older contract used; the tool
        // name then lives under "tool".
        if (name == "tool" && parsed.contains("tool") && parsed["tool"].is_string()) {
            name = parsed["tool"].get<std::string>();
        }
        if (name.empty() || name == "tool") continue;

        ParsedToolCall call;
        call.name = name;
        if (!args.is_object()) args = nlohmann::json::object();
        call.arguments = args;
        outCalls.push_back(call);
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------
std::size_t ToolCallParser::findMatchingBrace_(const std::string& text,
                                                std::size_t openBrace) {
    int depth = 0;
    for (std::size_t i = openBrace; i < text.size(); ++i) {
        if (text[i] == '{') ++depth;
        else if (text[i] == '}') {
            if (--depth == 0) return i;
        }
    }
    return std::string::npos;
}

bool ToolCallParser::extractBalancedJsonRange(const std::string& text,
                                               std::size_t searchStart,
                                               std::size_t& outStart,
                                               std::size_t& outEnd) {
    std::size_t start = text.find('{', searchStart);
    if (start == std::string::npos) return false;
    std::size_t end = findMatchingBrace_(text, start);
    if (end == std::string::npos) return false;
    outStart = start;
    outEnd = end;
    return true;
}

nlohmann::json ToolCallParser::parseArgumentsValue_(const nlohmann::json& v) {
    // Some providers deliver the arguments object as a JSON *string*.
    if (v.is_string()) {
        try {
            nlohmann::json parsed = nlohmann::json::parse(v.get<std::string>());
            if (parsed.is_object()) return parsed;
        } catch (...) {
            // Not JSON: fall through to an empty object.
        }
        return nlohmann::json::object();
    }
    if (v.is_object()) return v;
    return nlohmann::json::object();
}

bool ToolCallParser::parseOneJsonObject_(const nlohmann::json& parsed,
                                          std::vector<ParsedToolCall>& outCalls) {
    (void)parsed;
    (void)outCalls;
    return false;
}

} // namespace Agentic
} // namespace RawrXD
