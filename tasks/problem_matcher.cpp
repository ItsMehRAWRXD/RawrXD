// problem_matcher.cpp — Problem Matcher Engine
#include "task_runner.hpp"
#include <regex>
#include <fstream>

namespace RawrXD {
namespace Tasks {

// ============================================================================
// Problem Matcher Registry — Built-in matchers for common tools
// ============================================================================
class ProblemMatcherRegistry {
public:
    static ProblemMatcherRegistry& Get();

    // Get built-in matcher by name
    ProblemMatcher* GetMatcher(const std::string& name);

    // Register custom matcher
    void RegisterMatcher(const ProblemMatcher& matcher);

    // List all available matchers
    std::vector<ProblemMatcher> ListMatchers() const;

    // Apply matchers to output and extract problems
    struct Problem {
        std::string file;
        int line = 0;
        int column = 0;
        std::string severity;
        std::string message;
        std::string code;
        std::string owner;
    };
    std::vector<Problem> ApplyMatchers(const std::string& output, const std::vector<ProblemMatcher>& matchers) const;

    // Load matchers from JSON file
    bool LoadMatchersFile(const std::filesystem::path& path);

private:
    ProblemMatcherRegistry();
    void RegisterBuiltinMatchers();

    std::map<std::string, ProblemMatcher> m_matchers;
};

ProblemMatcherRegistry& ProblemMatcherRegistry::Get() {
    static ProblemMatcherRegistry instance;
    return instance;
}

ProblemMatcherRegistry::ProblemMatcherRegistry() {
    RegisterBuiltinMatchers();
}

void ProblemMatcherRegistry::RegisterBuiltinMatchers() {
    // MSVC compiler
    {
        ProblemMatcher msvc;
        msvc.name = "$msvc";
        msvc.filePattern = R"(([a-zA-Z]:[^:]+))";
        msvc.linePattern = R"(line (\d+))";
        msvc.severityPattern = R"((error|warning))";
        msvc.messagePattern = R"(([a-zA-Z]:[^:]+)\((\d+)\):\s+(error|warning)\s+(\w+):\s+(.+))";
        msvc.owner = "cpp";
        m_matchers["$msvc"] = msvc;
    }

    // GCC/Clang
    {
        ProblemMatcher gcc;
        gcc.name = "$gcc";
        gcc.messagePattern = R"(([^:]+):(\d+):(\d+):\s+(error|warning):\s+(.+))";
        gcc.owner = "cpp";
        m_matchers["$gcc"] = gcc;
    }

    // TypeScript
    {
        ProblemMatcher ts;
        ts.name = "$tsc";
        ts.messagePattern = R"(([^\(]+)\((\d+),(\d+)\):\s+(error|warning)\s+(\w+):\s+(.+))";
        ts.owner = "typescript";
        m_matchers["$tsc"] = ts;
    }

    // ESLint
    {
        ProblemMatcher eslint;
        eslint.name = "$eslint-stylish";
        eslint.messagePattern = R"((\d+):(\d+)\s+(error|warning)\s+(.+))";
        eslint.owner = "javascript";
        m_matchers["$eslint-stylish"] = eslint;
    }

    // CMake
    {
        ProblemMatcher cmake;
        cmake.name = "$cmake";
        cmake.messagePattern = R"(([^:]+):(\d+):\s+(error|warning):\s+(.+))";
        cmake.owner = "cmake";
        m_matchers["$cmake"] = cmake;
    }

    // Generic
    {
        ProblemMatcher generic;
        generic.name = "$generic";
        generic.messagePattern = R"((error|warning|info):\s+(.+))";
        generic.owner = "generic";
        m_matchers["$generic"] = generic;
    }
}

ProblemMatcher* ProblemMatcherRegistry::GetMatcher(const std::string& name) {
    auto it = m_matchers.find(name);
    return it != m_matchers.end() ? &it->second : nullptr;
}

void ProblemMatcherRegistry::RegisterMatcher(const ProblemMatcher& matcher) {
    m_matchers[matcher.name] = matcher;
}

std::vector<ProblemMatcher> ProblemMatcherRegistry::ListMatchers() const {
    std::vector<ProblemMatcher> matchers;
    for (const auto& [name, matcher] : m_matchers) {
        matchers.push_back(matcher);
    }
    return matchers;
}

std::vector<ProblemMatcherRegistry::Problem> ProblemMatcherRegistry::ApplyMatchers(
    const std::string& output, const std::vector<ProblemMatcher>& matchers) const
{
    std::vector<Problem> problems;

    for (const auto& matcher : matchers) {
        std::regex pattern(matcher.messagePattern);
        std::smatch match;
        std::string::const_iterator searchStart(output.cbegin());

        while (std::regex_search(searchStart, output.cend(), match, pattern)) {
            Problem problem;
            problem.owner = matcher.owner;

            // Extract file (first capture group)
            if (match.size() > 1) problem.file = match[1].str();
            // Extract line (second capture group)
            if (match.size() > 2) problem.line = std::stoi(match[2].str());
            // Extract column (third capture group)
            if (match.size() > 3) problem.column = std::stoi(match[3].str());
            // Extract severity
            if (match.size() > 4) {
                problem.severity = match[4].str();
                // Normalize
                if (problem.severity == "error" || problem.severity == "Error") problem.severity = "Error";
                else if (problem.severity == "warning" || problem.severity == "Warning") problem.severity = "Warning";
                else problem.severity = "Info";
            }
            // Extract code
            if (match.size() > 5) problem.code = match[5].str();
            // Extract message
            if (match.size() > 6) problem.message = match[6].str();

            problems.push_back(problem);
            searchStart = match.suffix().first;
        }
    }

    return problems;
}

bool ProblemMatcherRegistry::LoadMatchersFile(const std::filesystem::path& path) {
    if (!std::filesystem::exists(path)) return false;

    std::ifstream file(path);
    if (!file.is_open()) return false;

    std::string line;
    ProblemMatcher current;
    bool inMatcher = false;

    while (std::getline(file, line)) {
        auto parseStr = [](const std::string& l, const std::string& key) -> std::string {
            auto pos = l.find("\"" + key + "\"");
            if (pos == std::string::npos) return {};
            auto colon = l.find(':', pos);
            if (colon == std::string::npos) return {};
            auto start = l.find('"', colon + 1);
            if (start == std::string::npos) return {};
            auto end = l.find('"', start + 1);
            if (end == std::string::npos) return {};
            return l.substr(start + 1, end - start - 1);
        };

        if (line.find("\"name\"") != std::string::npos) {
            if (inMatcher) RegisterMatcher(current);
            current = ProblemMatcher();
            current.name = parseStr(line, "name");
            inMatcher = true;
        }
        if (line.find("\"owner\"") != std::string::npos) current.owner = parseStr(line, "owner");
        if (line.find("\"pattern\"") != std::string::npos) current.messagePattern = parseStr(line, "pattern");
    }

    if (inMatcher) RegisterMatcher(current);
    return true;
}

} // namespace Tasks
} // namespace RawrXD
