// ============================================================================
// rawr_stub_scan.cpp — RAWR_STUB_SCAN_001 implementation.
// Deterministic lexical candidate detection. Reads each enumerated source
// file once, flags suspicious lines, NEVER auto-convicts. Generic control
// flow (bare return true/false/nullptr) is deliberately NOT flagged unless
// the surrounding context looks stub-like.
// ============================================================================
#include "rawr_stub_scan.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <mutex>

namespace rawrxd {
namespace agent {

namespace {

inline bool isWordChar(char c) {
    return std::isalnum(static_cast<unsigned char>(c)) || c == '_';
}

// Case-insensitive word-boundary substring test.
bool containsWord(const std::string& hay, const std::string& needle) {
    if (needle.empty() || hay.size() < needle.size()) return false;
    const size_t n = needle.size();
    for (size_t i = 0; i + n <= hay.size(); ++i) {
        if (i > 0 && isWordChar(hay[i - 1])) continue;
        bool match = true;
        for (size_t j = 0; j < n; ++j) {
            if (std::tolower(static_cast<unsigned char>(hay[i + j])) !=
                std::tolower(static_cast<unsigned char>(needle[j]))) {
                match = false;
                break;
            }
        }
        if (match) {
            const size_t after = i + n;
            if (after < hay.size() && isWordChar(hay[after])) continue;
            return true;
        }
    }
    return false;
}

// Case-insensitive plain substring (for multi-word phrases).
bool containsPhrase(const std::string& hay, const std::string& needle) {
    if (needle.empty() || hay.size() < needle.size()) return false;
    const size_t n = needle.size();
    for (size_t i = 0; i + n <= hay.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < n; ++j) {
            if (std::tolower(static_cast<unsigned char>(hay[i + j])) !=
                std::tolower(static_cast<unsigned char>(needle[j]))) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

std::string trimCopy(const std::string& s) {
    size_t b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return {};
    size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

// A body is "stub-like" when a bare constant return sits in a function whose
// line content suggests unimplemented work (e.g. "return false; // stub").
// We only treat bare returns as candidates when the SAME line or the
// immediately preceding comment line carries a stub marker. Generic
// `return false;` control flow is never a candidate by itself.
bool lineHasStubMarker(const std::string& line) {
    return containsWord(line, "stub") || containsWord(line, "placeholder") ||
           containsPhrase(line, "not implemented") ||
           containsWord(line, "unimplemented") ||
           containsWord(line, "NOT_IMPLEMENTED");
}

} // namespace

void scanSourceText(const std::string& relPath, const std::string& text,
                    std::vector<ScanCandidate>& out) {
    size_t lineStart = 0;
    uint32_t lineNo = 0;
    std::string prevLine;

    auto handleLine = [&](const std::string& raw) {
        ++lineNo;
        const std::string line = trimCopy(raw);

        ScanKind kind = ScanKind::StubComment;
        bool hit = false;

        if (containsWord(line, "TODO") || containsWord(line, "FIXME") ||
            containsWord(line, "XXX") || containsWord(line, "HACK")) {
            kind = ScanKind::TodoFixme; hit = true;
        } else if (containsWord(line, "NOT_IMPLEMENTED") ||
                   containsPhrase(line, "not implemented") ||
                   containsWord(line, "unimplemented")) {
            kind = ScanKind::NotImplemented; hit = true;
        } else if (containsPhrase(line, "assert(false)") ||
                   containsPhrase(line, "assert( false") ||
                   containsPhrase(line, "__builtin_unreachable")) {
            kind = ScanKind::AssertFalse; hit = true;
        } else if (containsPhrase(line, "fake success") ||
                   containsPhrase(line, "pretend ") ||
                   containsPhrase(line, "hardcoded demo") ||
                   containsPhrase(line, "hard-coded demo") ||
                   containsPhrase(line, "demo result")) {
            kind = ScanKind::FakeSuccess; hit = true;
        } else if (line.rfind("#if 0", 0) == 0) {
            kind = ScanKind::DisabledPath; hit = true;
        } else if (containsWord(line, "stub") || containsWord(line, "placeholder")) {
            kind = ScanKind::StubComment; hit = true;
        } else if (line == "{" || line == "}" || line == "{}") {
            // Empty production body: line is a lone brace AND the previous
            // non-empty line ends with ')' or "const" — looks like a stubbed
            // function. Too noisy for full precision; still candidate-grade.
            const std::string prev = trimCopy(prevLine);
            if (line == "{}" && !prev.empty() &&
                (prev.back() == ')' || containsPhrase(prev, "const"))) {
                kind = ScanKind::StubBody; hit = true;
            }
        }

        // Bare constant returns become candidates ONLY with a same-line or
        // adjacent stub marker (per candidate-reduction guidance).
        if (!hit && (trimCopy(line) == "return false;" ||
                     trimCopy(line) == "return true;"  ||
                     trimCopy(line) == "return nullptr;" ||
                     trimCopy(line) == "return 0;")) {
            if (lineHasStubMarker(line) || lineHasStubMarker(prevLine)) {
                kind = ScanKind::StubBody; hit = true;
            }
        }

        if (hit) {
            ScanCandidate c;
            c.file = relPath;
            c.line = lineNo;
            c.kind = kind;
            c.snippet = line.substr(0, 200);
            out.push_back(std::move(c));
        }
        prevLine = line;
    };

    for (size_t i = 0; i <= text.size(); ++i) {
        if (i == text.size() || text[i] == '\n') {
            handleLine(text.substr(lineStart, i - lineStart));
            lineStart = i + 1;
            if (i == text.size()) break;
        }
    }
}

} // namespace agent
} // namespace rawrxd