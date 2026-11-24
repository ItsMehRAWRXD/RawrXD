// =============================================================================
// sast_rule_engine.cpp — S1 SAST rule engine implementation.
// =============================================================================
#include "sast_rule_engine.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <regex>
#include <sstream>

namespace rawrxd::security {
namespace fs = std::filesystem;

const char* SeverityName(Severity s) {
    switch (s) {
        case Severity::Info: return "info";
        case Severity::Warning: return "warning";
        case Severity::Error: return "error";
        case Severity::Critical: return "critical";
    }
    return "warning";
}

// ---------------------------------------------------------------------------
// Rule table (S1). Each rule is a regex over one source line plus optional
// per-file state (e.g. freed-variable tracking for use-after-free).
// Rule is defined in the header (std::vector requires a complete type).
// ---------------------------------------------------------------------------
// Rule definitions live in sast_rules/c_cpp_rules.inc so the table is
// declarative and reviewable in one place.
namespace {
struct RawRule {
    const char* id;
    const char* name;
    const char* cwe;
    Severity severity;
    const char* pattern;
    const char* message;
    bool needs_state;
};
}  // namespace

#include "sast_rules/c_cpp_rules.inc"

SastRuleEngine::SastRuleEngine() {
    for (const auto& r : kSastRules) {
        Rule rule;
        rule.id = r.id;
        rule.name = r.name;
        rule.cwe = r.cwe;
        rule.severity = r.severity;
        rule.pattern = std::regex(r.pattern,
            std::regex::ECMAScript | std::regex::icase);
        rule.message = r.message;
        rule.needs_state = r.needs_state;
        rules_.push_back(std::move(rule));
    }
}

size_t SastRuleEngine::RuleCount() const { return rules_.size(); }

namespace {

std::string TrimCopy(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace((unsigned char)s[a])) ++a;
    while (b > a && std::isspace((unsigned char)s[b - 1])) --b;
    return s.substr(a, b - a);
}

bool IsCppSource(const std::string& ext) {
    return ext == ".c" || ext == ".cc" || ext == ".cpp" || ext == ".cxx" ||
           ext == ".h" || ext == ".hpp" || ext == ".hxx" || ext == ".m" ||
           ext == ".mm";
}

std::string JsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", (unsigned)c);
                    out += buf;
                } else out += (char)c;
        }
    }
    return out;
}

}  // namespace

std::vector<Finding> SastRuleEngine::ScanFile(const std::string& path,
                                              const ScanOptions& opts) const {
    std::vector<Finding> findings;
    std::error_code ec;
    if (!fs::is_regular_file(path, ec)) return findings;
    const auto size = fs::file_size(path, ec);
    if (ec || (int)size > opts.max_file_bytes) return findings;

    std::ifstream in(path, std::ios::binary);
    if (!in) return findings;

    // Per-file state for stateful rules: variables passed to free().
    std::vector<std::string> freed_vars;

    std::string line;
    int line_no = 0;
    while (std::getline(in, line)) {
        ++line_no;
        if ((int)findings.size() >= opts.max_findings) break;
        // Strip // comments (does not handle strings containing //; the rule
        // patterns are anchored on API calls so false positives are bounded).
        std::string code = line;
        const size_t cpos = code.find("//");
        if (cpos != std::string::npos) code = code.substr(0, cpos);

        auto push_finding = [&](const Rule& rule, const std::string& code_line,
                                int column) {
            Finding f;
            f.rule_id = rule.id;
            f.rule_name = rule.name;
            f.file = path;
            f.line = line_no;
            f.column = column;
            f.severity = rule.severity;
            f.message = rule.message;
            f.cwe = rule.cwe;
            f.snippet = TrimCopy(code_line);
            if (f.snippet.size() > 240) f.snippet.resize(240);
            findings.push_back(std::move(f));
        };

        for (const auto& rule : rules_) {
            if ((int)findings.size() >= opts.max_findings) break;

            // Stateful rule (use-after-free): track free(var) across the file;
            // flag the line that DEREFERENCES a freed variable.
            if (rule.needs_state) {
                static const std::regex free_re(
                    R"(\bfree\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\))");
                for (std::sregex_iterator it(code.begin(), code.end(), free_re),
                     end; it != end; ++it) {
                    const std::string var = (*it)[1].str();
                    if (std::find(freed_vars.begin(), freed_vars.end(), var) ==
                        freed_vars.end())
                        freed_vars.push_back(var);
                }
                for (const auto& var : freed_vars) {
                    if (var.empty()) continue;
                    const std::string use_re_str = "\\b" + var + "\\b\\s*(->|\\[)";
                    if (std::regex_search(code,
                            std::regex(use_re_str, std::regex::icase))) {
                        push_finding(rule, code, 1);
                        break;
                    }
                }
                continue;
            }

            std::smatch m;
            if (!std::regex_search(code, m, rule.pattern)) continue;
            push_finding(rule, code, (int)(m.position(0)) + 1);
        }
    }
    return findings;
}

std::vector<Finding> SastRuleEngine::ScanPath(const std::string& path,
                                              const ScanOptions& opts) const {
    std::vector<Finding> all;
    std::error_code ec;
    if (fs::is_directory(path, ec)) {
        fs::recursive_directory_iterator it(path,
            fs::directory_options::skip_permission_denied, ec), end;
        for (; it != end; it.increment(ec)) {
            if (ec) break;
            if (!it->is_regular_file(ec)) continue;
            if (!IsCppSource(it->path().extension().string())) continue;
            auto f = ScanFile(it->path().string(), opts);
            all.insert(all.end(), f.begin(), f.end());
            if ((int)all.size() >= opts.max_findings) break;
        }
    } else {
        all = ScanFile(path, opts);
    }
    std::sort(all.begin(), all.end(), [](const Finding& a, const Finding& b) {
        if (a.file != b.file) return a.file < b.file;
        if (a.line != b.line) return a.line < b.line;
        return a.column < b.column;
    });
    return all;
}

std::string SastRuleEngine::ToJson(const std::vector<Finding>& findings) {
    std::ostringstream out;
    out << "[\n";
    for (size_t i = 0; i < findings.size(); ++i) {
        const auto& f = findings[i];
        out << "{\"rule_id\":\"" << JsonEscape(f.rule_id) << "\""
            << ",\"rule_name\":\"" << JsonEscape(f.rule_name) << "\""
            << ",\"file\":\"" << JsonEscape(f.file) << "\""
            << ",\"line\":" << f.line
            << ",\"column\":" << f.column
            << ",\"severity\":\"" << SeverityName(f.severity) << "\""
            << ",\"cwe\":\"" << JsonEscape(f.cwe) << "\""
            << ",\"message\":\"" << JsonEscape(f.message) << "\""
            << ",\"snippet\":\"" << JsonEscape(f.snippet) << "\"}";
        if (i + 1 < findings.size()) out << ",";
        out << "\n";
    }
    out << "]\n";
    return out.str();
}

}  // namespace rawrxd::security