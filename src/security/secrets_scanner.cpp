// =============================================================================
// secrets_scanner.cpp — S2 secrets scanner implementation.
// =============================================================================
#include "secrets_scanner.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <map>
#include <regex>
#include <set>
#include <sstream>

namespace rawrxd::security {
namespace fs = std::filesystem;

double ShannonEntropy(const std::string& s) {
    if (s.empty()) return 0.0;
    std::map<unsigned char, size_t> freq;
    for (unsigned char c : s) ++freq[c];
    double h = 0.0;
    const double n = (double)s.size();
    for (const auto& p : freq) {
        const double f = (double)p.second / n;
        h -= f * std::log2(f);
    }
    return h;
}

namespace {

std::string Redact(const std::string& s) {
    if (s.size() <= 8) return std::string(s.size(), '*');
    return s.substr(0, 4) + "..." + s.substr(s.size() - 2);
}

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

struct PatternRule {
    const char* id;
    const char* message;
    std::regex re;
};

const std::vector<PatternRule>& PatternRules() {
    static const std::vector<PatternRule> rules = {
        {"AWS_ACCESS_KEY", "AWS access key id in source",
         std::regex(R"(AKIA[0-9A-Z]{16})")},
        {"GITHUB_TOKEN", "GitHub token in source",
         std::regex(R"(gh[pousr]_[A-Za-z0-9]{20,})")},
        {"GITHUB_PAT", "GitHub fine-grained PAT in source",
         std::regex(R"(github_pat_[A-Za-z0-9_]{20,})")},
        {"SLACK_TOKEN", "Slack token in source",
         std::regex(R"(xox[baprs]-[A-Za-z0-9-]{10,})")},
        {"GOOGLE_API_KEY", "Google API key in source",
         std::regex(R"(AIza[0-9A-Za-z_-]{35})")},
        {"PRIVATE_KEY", "Private key block in source",
         std::regex(R"(-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----)")},
        {"JWT", "JSON Web Token in source",
         std::regex(R"(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,})")},
        {"CREDENTIAL_ASSIGN", "Credential-looking literal assignment",
         std::regex(R"(\b(?:api_?key|secret|token|password|passwd|pwd)\s*[:=]\s*["'][^"']{8,}["'])", std::regex::icase)},
    };
    return rules;
}

bool IsScannableExt(const std::string& ext) {
    static const std::set<std::string> ok = {
        ".c", ".cc", ".cpp", ".h", ".hpp", ".cs", ".js", ".ts", ".py",
        ".json", ".yml", ".yaml", ".xml", ".ini", ".cfg", ".conf",
        ".env", ".ps1", ".cmd", ".bat", ".sh", ".md", ".txt", ".cmake"};
    return ok.count(ext) > 0;
}

}  // namespace

std::vector<SecretFinding> SecretsScanner::ScanPath(
    const std::string& path, int max_file_bytes) const {
    std::vector<SecretFinding> out;
    std::error_code ec;
    std::vector<std::string> files;
    if (fs::is_directory(path, ec)) {
        fs::recursive_directory_iterator it(path,
            fs::directory_options::skip_permission_denied, ec), end;
        for (; it != end; it.increment(ec)) {
            if (ec) break;
            // Skip VCS/build/vendor noise.
            const std::string p = it->path().string();
            if (p.find("\\.git\\") != std::string::npos ||
                p.find("\\node_modules\\") != std::string::npos ||
                p.find("\\build") != std::string::npos) continue;
            if (it->is_regular_file(ec) &&
                IsScannableExt(it->path().extension().string()))
                files.push_back(p);
        }
    } else if (fs::is_regular_file(path, ec)) {
        files.push_back(path);
    }

    for (const auto& f : files) {
        std::error_code fec;
        if (fs::file_size(f, fec) > max_file_bytes) continue;
        std::ifstream in(f, std::ios::binary);
        if (!in) continue;
        std::string line;
        int ln = 0;
        while (std::getline(in, line)) {
            ++ln;
            for (const auto& rule : PatternRules()) {
                std::smatch m;
                if (std::regex_search(line, m, rule.re)) {
                    SecretFinding sf;
                    sf.rule_id = rule.id;
                    sf.file = f;
                    sf.line = ln;
                    sf.column = (int)m.position(0) + 1;
                    sf.match = Redact(m.str(0));
                    sf.message = rule.message;
                    out.push_back(std::move(sf));
                }
            }
            // Generic high-entropy heuristic: long base64/hex-ish token.
            std::smatch em;
            static const std::regex entropy_re(
                R"([A-Za-z0-9+/=]{24,})");
            for (std::sregex_iterator it2(line.begin(), line.end(), entropy_re),
                 e2; it2 != e2; ++it2) {
                const std::string tok = it2->str();
                // Require mixed classes to avoid flagging long identifiers.
                bool upper = false, lower = false, digit = false;
                for (char c : tok) {
                    if (std::isupper((unsigned char)c)) upper = true;
                    else if (std::islower((unsigned char)c)) lower = true;
                    else if (std::isdigit((unsigned char)c)) digit = true;
                }
                if (upper && lower && digit && ShannonEntropy(tok) > 4.5) {
                    SecretFinding sf;
                    sf.rule_id = "HIGH_ENTROPY";
                    sf.file = f;
                    sf.line = ln;
                    sf.column = (int)it2->position(0) + 1;
                    sf.match = Redact(tok);
                    sf.message = "high-entropy string (possible secret)";
                    out.push_back(std::move(sf));
                }
            }
        }
    }
    return out;
}

std::string SecretsScanner::ToJson(const std::vector<SecretFinding>& findings) {
    std::ostringstream out;
    out << "[\n";
    for (size_t i = 0; i < findings.size(); ++i) {
        const auto& f = findings[i];
        out << "{\"rule_id\":\"" << JsonEscape(f.rule_id) << "\""
            << ",\"file\":\"" << JsonEscape(f.file) << "\""
            << ",\"line\":" << f.line
            << ",\"column\":" << f.column
            << ",\"match\":\"" << JsonEscape(f.match) << "\""
            << ",\"message\":\"" << JsonEscape(f.message) << "\"}";
        if (i + 1 < findings.size()) out << ",";
        out << "\n";
    }
    out << "]\n";
    return out.str();
}

}  // namespace rawrxd::security