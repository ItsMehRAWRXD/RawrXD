// =============================================================================
// Win32IDE_BuildParser.cpp — I4/C1 build output -> Problems (TOP50 I4/C1).
// =============================================================================
// Parses compiler/build output chunks (MSVC, MSBuild, gcc/clang, Ninja) and
// pushes structured problems into the unified ProblemsAggregator (source
// "Build") + the classic problem list. The IDE build pipeline
// (Win32IDE_Commands.cpp) already runs vcvars + cmake --build in a terminal
// pane; this closes the "errors -> Problems" half of I4/C1.
// =============================================================================
#include "Win32IDE.h"

#include <cstdio>
#include <regex>
#include <sstream>
#include <string>

#include "core/problems_aggregator.hpp"

namespace {

struct ParsedLine {
    std::string file;
    int line = 0;
    int column = 0;
    int severity = 1;   // 1=error, 2=warning
    std::string code;
    std::string message;
};

// MSVC:  path(12): error C2143: message   /  path(12,5): error C2143: msg
// MSBuild: path(12,5): error MSB1234: message
// gcc/clang: path:12:5: error: message
bool ParseLine(const std::string& raw, ParsedLine& out) {
    static const std::regex msvc(
        R"(^\s*(.+?)\((\d+)(?:,\d+)?\)\s*:\s*(error|warning)\s+([A-Z]+\d+)\s*:\s*(.+)$)",
        std::regex::icase);
    static const std::regex gcc(
        R"(^\s*(.+?):(\d+)(?::(\d+))?:\s*(error|warning|fatal error)\s*:\s*(.+)$)",
        std::regex::icase);
    std::smatch m;
    if (std::regex_match(raw, m, msvc)) {
        out.file = m[1].str();
        out.line = std::stoi(m[2].str());
        out.column = 0;
        out.severity = (m[3].str() == "error") ? 1 : 2;
        out.code = m[4].str();
        out.message = m[5].str();
        return true;
    }
    if (std::regex_match(raw, m, gcc)) {
        out.file = m[1].str();
        out.line = std::stoi(m[2].str());
        out.column = m[3].matched ? std::stoi(m[3].str()) : 0;
        out.severity = (m[4].str().find("warning") != std::string::npos) ? 2 : 1;
        out.code = "BUILD";
        out.message = m[5].str();
        return true;
    }
    return false;
}

}  // namespace

void Win32IDE::parseBuildOutputForProblems(const std::string& chunk) {
    if (chunk.empty()) return;
    // Append to the Build output tab (real capture) and scan for diagnostics.
    appendToOutput(chunk, "Build", OutputSeverity::Info);

    std::istringstream stream(chunk);
    std::string raw;
    int added = 0;
    while (std::getline(stream, raw)) {
        ParsedLine p;
        if (!ParseLine(raw, p)) continue;
        auto& agg = RawrXD::ProblemsAggregator::instance();
        agg.add("Build", p.file, p.line, p.column, p.severity, p.code,
                p.message, p.code);
        addProblem(p.file, p.line, p.column, p.message, p.severity - 1);
        ++added;
    }
    if (added > 0) {
        refreshProblemsView();
        m_buildProblemCount += added;
        appendToOutput("[Build] parsed " + std::to_string(added) +
                       " diagnostic(s) into Problems (total " +
                       std::to_string(m_buildProblemCount) + ")\n",
                       "Build", OutputSeverity::Info);
    }
}