// =============================================================================
// dependency_audit.cpp — S3 SCA implementation (offline advisory table).
// =============================================================================
#include "dependency_audit.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <regex>
#include <sstream>

namespace rawrxd::security {
namespace fs = std::filesystem;

int CompareVersions(const std::string& a, const std::string& b) {
    auto parts = [](const std::string& v) {
        std::vector<long> out;
        std::stringstream ss(v);
        std::string tok;
        while (std::getline(ss, tok, '.')) {
            long n = 0;
            try { n = std::stol(tok); } catch (...) { n = 0; }
            out.push_back(n);
        }
        return out;
    };
    const auto pa = parts(a), pb = parts(b);
    for (size_t i = 0; i < std::max(pa.size(), pb.size()); ++i) {
        const long x = i < pa.size() ? pa[i] : 0;
        const long y = i < pb.size() ? pb[i] : 0;
        if (x != y) return x < y ? -1 : 1;
    }
    return 0;
}

namespace {

std::string JsonEscape(const std::string& s) {
    std::string out;
    for (unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            default:
                if (c < 0x20) { char b[8]; std::snprintf(b, sizeof(b), "\\u%04x", c); out += b; }
                else out += (char)c;
        }
    }
    return out;
}

std::string Trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace((unsigned char)s[a])) ++a;
    while (b > a && std::isspace((unsigned char)s[b - 1])) --b;
    return s.substr(a, b - a);
}

}  // namespace

const std::vector<Advisory>& DependencyAuditor::AdvisoryTable() {
    // Offline table of well-known vulnerable ranges. Extend deliberately;
    // each entry must be defensible without a network lookup.
    static const std::vector<Advisory> table = {
        {"minimist", "npm", "1.2.6", "critical",
         "prototype pollution (CVE-2021-44906)"},
        {"lodash", "npm", "4.17.21", "high",
         "command injection / prototype pollution (CVE-2021-23337)"},
        {"axios", "npm", "0.21.2", "high",
         "SSRF / credential leak (CVE-2021-3749)"},
        {"log4j-core", "pypi", "2.17.1", "critical",
         "Log4Shell RCE (CVE-2021-44228)"},
        {"requests", "pypi", "2.31.0", "moderate",
         "certificate verification bypass (CVE-2023-32681)"},
        {"py", "pypi", "1.11.0", "moderate",
         "path traversal in py.path (CVE-2022-42969)"},
        {"jinja2", "pypi", "3.1.3", "moderate",
         "HTML attribute injection (CVE-2024-22195)"},
        {"openssl", "vcpkg", "3.1.4", "high",
         "buffer overflow / DoS (CVE-2023-5678)"},
        {"zlib", "vcpkg", "1.3", "moderate",
         "memory corruption in inflate (CVE-2023-45853)"},
    };
    return table;
}

std::vector<Dependency> DependencyAuditor::ParseManifest(
    const std::string& path) const {
    std::vector<Dependency> deps;
    std::ifstream in(path);
    if (!in) return deps;
    std::stringstream ss;
    ss << in.rdbuf();
    const std::string body = ss.str();
    const std::string base = fs::path(path).filename().string();

    if (base == "package.json") {
        static const std::regex dep_re(
            R"re("([A-Za-z0-9_.@/-]+)"\s*:\s*"([^"]+)")re");
        for (std::sregex_iterator it(body.begin(), body.end(), dep_re), end;
             it != end; ++it) {
            const std::string name = (*it)[1].str();
            if (name == "name" || name == "version" || name == "description")
                continue;
            std::string ver = (*it)[2].str();
            // Strip range prefixes; keep the numeric core.
            const size_t d = ver.find_first_of("0123456789");
            ver = (d == std::string::npos) ? "" : ver.substr(d);
            deps.push_back({name, ver, "npm", base});
        }
    } else if (base == "requirements.txt") {
        std::istringstream lines(body);
        std::string line;
        while (std::getline(lines, line)) {
            line = Trim(line);
            if (line.empty() || line[0] == '#' || line[0] == '-') continue;
            const size_t op = line.find_first_of("=<>!~");
            if (op == std::string::npos) {
                deps.push_back({line, "", "pypi", base});
            } else {
                std::string ver = Trim(line.substr(op));
                while (!ver.empty() && (ver[0] == '=' || ver[0] == '<' ||
                                        ver[0] == '>' || ver[0] == '!' ||
                                        ver[0] == '~'))
                    ver.erase(ver.begin());
                deps.push_back({Trim(line.substr(0, op)), ver, "pypi", base});
            }
        }
    } else if (base == "vcpkg.json") {
        static const std::regex name_re(R"re("name"\s*:\s*"([^"]+)")re");
        std::smatch m;
        if (std::regex_search(body, m, name_re))
            deps.push_back({m[1].str(), "", "vcpkg", base});
        static const std::regex ver_re(
            R"re("version(?:-string|-semver|-relaxed)?"\s*:\s*"([^"]+)")re");
        for (std::sregex_iterator it(body.begin(), body.end(), ver_re), end;
             it != end; ++it)
            if (!deps.empty() && deps.back().version.empty())
                deps.back().version = (*it)[1].str();
    } else if (base == "CMakeLists.txt") {
        static const std::regex pkg_re(
            R"(find_package\s*\(\s*([A-Za-z0-9_]+)(?:\s+([0-9]+(?:\.[0-9]+)*))?)",
            std::regex::icase);
        for (std::sregex_iterator it(body.begin(), body.end(), pkg_re), end;
             it != end; ++it)
            deps.push_back({(*it)[1].str(), (*it)[2].str(), "cmake", base});
    }
    return deps;
}

std::vector<Dependency> DependencyAuditor::ScanTree(
    const std::string& root) const {
    std::vector<Dependency> all;
    std::error_code ec;
    if (!fs::is_directory(root, ec)) return ParseManifest(root);
    fs::recursive_directory_iterator it(root,
        fs::directory_options::skip_permission_denied, ec), end;
    int depth = 0;
    for (; it != end; it.increment(ec)) {
        if (ec) break;
        if (it.depth() > 6) { it.disable_recursion_pending(); continue; }
        const std::string name = it->path().filename().string();
        if (name == "package.json" || name == "requirements.txt" ||
            name == "vcpkg.json" || name == "CMakeLists.txt") {
            auto d = ParseManifest(it->path().string());
            all.insert(all.end(), d.begin(), d.end());
        }
        ++depth;
        if (depth > 20000) break;
    }
    return all;
}

std::vector<Advisory> DependencyAuditor::Audit(
    const std::vector<Dependency>& deps) const {
    std::vector<Advisory> out;
    for (const auto& d : deps) {
        for (const auto& a : AdvisoryTable()) {
            if (a.ecosystem != d.ecosystem) continue;
            if (a.dependency.find(d.name) == std::string::npos &&
                d.name.find(a.dependency) == std::string::npos)
                continue;
            if (d.version.empty() ||
                CompareVersions(d.version, a.fixed_version) < 0) {
                Advisory hit = a;
                hit.summary += " (found " + d.name + " " +
                               (d.version.empty() ? "unpinned" : d.version) +
                               " in " + d.manifest + ")";
                out.push_back(hit);
            }
        }
    }
    return out;
}

std::string DependencyAuditor::ToJson(const std::vector<Dependency>& deps,
                                      const std::vector<Advisory>& advisories) {
    std::ostringstream out;
    out << "{\"dependencies\":[";
    for (size_t i = 0; i < deps.size(); ++i) {
        const auto& d = deps[i];
        out << "{\"name\":\"" << JsonEscape(d.name) << "\",\"version\":\""
            << JsonEscape(d.version) << "\",\"ecosystem\":\""
            << JsonEscape(d.ecosystem) << "\",\"manifest\":\""
            << JsonEscape(d.manifest) << "\"}";
        if (i + 1 < deps.size()) out << ",";
    }
    out << "],\"advisories\":[";
    for (size_t i = 0; i < advisories.size(); ++i) {
        const auto& a = advisories[i];
        out << "{\"dependency\":\"" << JsonEscape(a.dependency)
            << "\",\"fixed_version\":\"" << JsonEscape(a.fixed_version)
            << "\",\"severity\":\"" << JsonEscape(a.severity)
            << "\",\"summary\":\"" << JsonEscape(a.summary) << "\"}";
        if (i + 1 < advisories.size()) out << ",";
    }
    out << "]}\n";
    return out.str();
}

}  // namespace rawrxd::security