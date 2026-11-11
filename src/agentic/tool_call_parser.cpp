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

// ---------------------------------------------------------------------------
// Public parse entry point
// ---------------------------------------------------------------------------
ToolCallParseResult ToolCallParser::parse(const std::string& modelOutput) {
    ToolCallParseResult result;

    // Try structured XML format first
    ParsedToolCall call;
    if (parseStructuredToolCall(modelOutput, call)) {
        result.toolCalls.push_back(call);
        return result;
    }

    // Fall back to natural language parsing
    if (parseNaturalLanguageToolCall(modelOutput, call)) {
        result.toolCalls.push_back(call);
        return result;
    }

    return result;
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
    return v;
}

bool ToolCallParser::parseOneJsonObject_(const nlohmann::json& parsed,
                                          std::vector<ParsedToolCall>& outCalls) {
    (void)parsed;
    (void)outCalls;
    return false;
}

} // namespace Agentic
} // namespace RawrXD
