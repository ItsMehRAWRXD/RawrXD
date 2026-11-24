// =============================================================================
// test_explorer.cpp — I5/T3 discovery + isolated execution.
// =============================================================================
#include "test_explorer.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <regex>
#include <sstream>

#include "agentic/tool_security.hpp"

namespace rawrxd::testing {
namespace fs = std::filesystem;

namespace {

std::string JsonEscape(const std::string& s) {
    std::string out;
    for (unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) { char b[8]; std::snprintf(b, sizeof(b), "\\u%04x", c); out += b; }
                else out += (char)c;
        }
    }
    return out;
}

bool StartsWith(const std::string& s, const std::string& p) {
    return s.size() >= p.size() && s.compare(0, p.size(), p) == 0;
}

}  // namespace

std::vector<TestCase> TestExplorer::Discover(const std::string& root,
                                             int max_tests) const {
    std::vector<TestCase> out;
    std::error_code ec;
    if (!fs::is_directory(root, ec)) return out;

    fs::recursive_directory_iterator it(root,
        fs::directory_options::skip_permission_denied, ec), end;
    for (; it != end && (int)out.size() < max_tests; it.increment(ec)) {
        if (ec) break;
        const std::string p = it->path().string();
        if (p.find("\\.git\\") != std::string::npos ||
            p.find("\\build") != std::string::npos ||
            p.find("\\node_modules\\") != std::string::npos)
            continue;
        if (!it->is_regular_file(ec)) continue;
        const std::string name = it->path().filename().string();

        // CTest tests declared via add_test in CMakeLists.
        if (name == "CMakeLists.txt") {
            std::ifstream in(p);
            std::stringstream ss;
            ss << in.rdbuf();
            static const std::regex add_test(
                R"(add_test\s*\(\s*([A-Za-z0-9_]+)\s+([^\s)]+))");
            for (std::sregex_iterator m(ss.str().begin(), ss.str().end(),
                                        add_test), e; m != e; ++m) {
                TestCase t;
                t.name = (*m)[1].str();
                t.file = p;
                t.kind = "ctest";
                t.command = "ctest --test-dir \"" +
                    fs::path(p).parent_path().parent_path().string() +
                    "\" -R \"^" + t.name + "$\" --output-on-failure";
                out.push_back(std::move(t));
            }
            continue;
        }

        // Python pytest files.
        if (StartsWith(name, "test_") &&
            it->path().extension() == ".py") {
            TestCase t;
            t.name = name;
            t.file = p;
            t.kind = "pytest";
            t.command = "python -m pytest \"" + p + "\" -q";
            out.push_back(std::move(t));
            continue;
        }

        // Generic test scripts (.cmd) with a test-ish name.
        if ((StartsWith(name, "test_") || StartsWith(name, "run_test")) &&
            (it->path().extension() == ".cmd" || it->path().extension() == ".bat")) {
            TestCase t;
            t.name = name;
            t.file = p;
            t.kind = "script";
            t.command = "cmd.exe /d /c \"" + p + "\"";
            out.push_back(std::move(t));
        }
    }
    return out;
}

TestResult TestExplorer::Run(const TestCase& test,
                             unsigned long long timeout_ms) const {
    TestResult r;
    r.name = test.name;
    std::string out, err;
    bool timed_out = false;
    const bool launched = rawrxd::agentic::security::JobIsolation::RunIsolated(
        test.command, std::string(), timeout_ms, out, err, r.exit_code,
        timed_out);
    r.timed_out = timed_out;
    r.output = out;
    if (!err.empty()) {
        if (!r.output.empty()) r.output += "\n";
        r.output += err;
    }
    if (!launched) {
        r.exit_code = -1;
        r.output = "launch failed: " + test.command;
    }
    return r;
}

std::string TestExplorer::ToJson(const std::vector<TestResult>& results) {
    std::ostringstream out;
    out << "[\n";
    for (size_t i = 0; i < results.size(); ++i) {
        const auto& r = results[i];
        out << "{\"name\":\"" << JsonEscape(r.name) << "\",\"exit_code\":"
            << r.exit_code << ",\"timed_out\":"
            << (r.timed_out ? "true" : "false") << ",\"output\":\""
            << JsonEscape(r.output.substr(0, 512)) << "\"}";
        if (i + 1 < results.size()) out << ",";
        out << "\n";
    }
    out << "]\n";
    return out.str();
}

}  // namespace rawrxd::testing