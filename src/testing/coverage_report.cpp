// =============================================================================
// coverage_report.cpp — T2 lcov + llvm-cov parsing.
// =============================================================================
#include "coverage_report.h"

#include <cctype>
#include <cstdio>
#include <fstream>
#include <regex>
#include <sstream>
#include <string>

namespace rawrxd::testing {

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

}  // namespace

bool CoverageReport::LoadLcov(const std::string& path) {
    std::ifstream in(path);
    if (!in) return false;
    files_.clear();
    std::string line;
    FileCoverage cur;
    bool inRecord = false;
    auto flush = [&]() {
        if (inRecord && cur.lines_found > 0) files_.push_back(cur);
        cur = FileCoverage{};
        inRecord = false;
    };
    while (std::getline(in, line)) {
        if (line.rfind("SF:", 0) == 0) {
            flush();
            cur.file = line.substr(3);
            inRecord = true;
        } else if (line.rfind("LF:", 0) == 0) {
            cur.lines_found = std::atoi(line.c_str() + 3);
        } else if (line.rfind("LH:", 0) == 0) {
            cur.lines_hit = std::atoi(line.c_str() + 3);
        } else if (line == "end_of_record") {
            flush();
        }
    }
    flush();
    return true;
}

bool CoverageReport::LoadLlvmJson(const std::string& path) {
    std::ifstream in(path);
    if (!in) return false;
    std::stringstream ss;
    ss << in.rdbuf();
    const std::string body = ss.str();
    files_.clear();
    // Each file entry: "filename":"X" ... "lines":{"covered":C,"count":N}
    static const std::regex file_re(
        R"re("filename"\s*:\s*"([^"]+)"[\s\S]*?"lines"\s*:\s*\{\s*"covered"\s*:\s*(\d+)\s*,\s*"count"\s*:\s*(\d+)\s*\})re");
    for (std::sregex_iterator it(body.begin(), body.end(), file_re), end;
         it != end; ++it) {
        FileCoverage fc;
        fc.file = (*it)[1].str();
        fc.lines_hit = std::stoi((*it)[2].str());
        fc.lines_found = std::stoi((*it)[3].str());
        files_.push_back(std::move(fc));
    }
    return !files_.empty() || body.find("\"files\"") != std::string::npos;
}

double CoverageReport::OverallPercent() const {
    int found = 0, hit = 0;
    for (const auto& f : files_) {
        found += f.lines_found;
        hit += f.lines_hit;
    }
    return found > 0 ? (100.0 * hit / found) : 0.0;
}

std::string CoverageReport::ToJson(const std::vector<FileCoverage>& files) {
    std::ostringstream out;
    out << "[\n";
    for (size_t i = 0; i < files.size(); ++i) {
        const auto& f = files[i];
        char pct[32];
        std::snprintf(pct, sizeof(pct), "%.1f", f.percent());
        out << "{\"file\":\"" << JsonEscape(f.file) << "\",\"lines_found\":"
            << f.lines_found << ",\"lines_hit\":" << f.lines_hit
            << ",\"percent\":" << pct << "}";
        if (i + 1 < files.size()) out << ",";
        out << "\n";
    }
    out << "]\n";
    return out.str();
}

}  // namespace rawrxd::testing