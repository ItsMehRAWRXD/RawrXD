// agentic_failure_detector.cpp — real implementation of
// src/agent/agentic_failure_detector.hpp (W3 BATCH H). Real pattern scan of
// stage console output; no synthetic success, no fake records.

#include "agentic_failure_detector.hpp"

#include <chrono>
#include <cstring>
#include <utility>

namespace RawrXD {
namespace Agent {

namespace {

uint64_t nowMs() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch())
        .count();
}

struct PatternEntry {
    const char*  needle;
    FailureKind  kind;
};

// Real console-text failure signatures (compiler/linker/test runners).
constexpr PatternEntry kPatterns[] = {
    { ": error C",        FailureKind::CompileError },
    { "error LNK",        FailureKind::LinkError    },
    { "fatal error",      FailureKind::CompileError },
    { "FAILED",           FailureKind::TestFailure  },
    { "No such file",     FailureKind::MissingFile  },
    { "timeout",          FailureKind::Timeout      },
    { "Timeout",          FailureKind::Timeout      },
};

bool containsIgnoreCase(const std::string& hay, const char* needle) {
    const size_t nlen = std::strlen(needle);
    if (nlen == 0 || hay.size() < nlen) return false;
    for (size_t i = 0; i + nlen <= hay.size(); ++i) {
        size_t j = 0;
        while (j < nlen) {
            const char a = hay[i + j];
            const char b = needle[j];
            const char al = (a >= 'A' && a <= 'Z') ? static_cast<char>(a + 32) : a;
            const char bl = (b >= 'A' && b <= 'Z') ? static_cast<char>(b + 32) : b;
            if (al != bl) break;
            ++j;
        }
        if (j == nlen) return true;
    }
    return false;
}

// First line containing the pattern — the detail line for the record.
std::string firstMatchingLine(const std::string& text, const char* needle) {
    size_t start = 0;
    while (start < text.size()) {
        const size_t end = text.find('\n', start);
        const size_t endPos = (end == std::string::npos) ? text.size() : end;
        const std::string line = text.substr(start, endPos - start);
        if (containsIgnoreCase(line, needle)) return line;
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return {};
}

} // namespace

void AgenticFailureDetector::ingestStageOutput(const char* stageName,
                                               const std::string& consoleText) {
    if (!stageName || consoleText.empty()) return;

    for (const auto& p : kPatterns) {
        if (!containsIgnoreCase(consoleText, p.needle)) continue;
        FailureRecord rec;
        rec.kind        = p.kind;
        rec.sourceFile  = stageName ? stageName : "";
        rec.detail      = firstMatchingLine(consoleText, p.needle);
        rec.count       = 1;
        rec.timestampMs = nowMs();

        // Merge with an identical prior record (same source + kind): count only.
        for (auto& prior : m_records) {
            if (prior.kind == rec.kind && prior.sourceFile == rec.sourceFile) {
                ++prior.count;
                prior.timestampMs = rec.timestampMs;
                if (!rec.detail.empty()) prior.detail = rec.detail;
                return;
            }
        }
        m_records.push_back(std::move(rec));
        return; // one record per ingest call (first matching pattern wins)
    }
}

bool AgenticFailureDetector::hasFailure() const {
    return !m_records.empty();
}

const FailureRecord& AgenticFailureDetector::lastFailure() const {
    // Caller must check hasFailure() first; returning an empty static record
    // keeps the accessor non-throwing without fabricating evidence.
    static const FailureRecord kEmpty{};
    return m_records.empty() ? kEmpty : m_records.back();
}

void AgenticFailureDetector::clear() {
    m_records.clear();
}

} // namespace Agent
} // namespace RawrXD
