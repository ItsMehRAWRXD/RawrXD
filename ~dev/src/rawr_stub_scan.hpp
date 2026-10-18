#pragma once
// ============================================================================
// rawr_stub_scan.hpp — RAWR_STUB_SCAN_001
// Native deterministic source scanner: finds suspicious (candidate)
// locations across the enumerated audit universe. The scanner NEVER convicts
// — candidates only. The model decides defect/false-positive/needs-proof;
// the runtime owns truth and coverage.
// ============================================================================
#include <cstdint>
#include <string>
#include <vector>

namespace rawrxd {
namespace agent {

// Lexical candidate kinds emitted by the scanner.
enum class ScanKind : uint8_t {
    TodoFixme        = 0,   // TODO / FIXME / XXX / HACK comments
    NotImplemented   = 1,   // NOT_IMPLEMENTED / "not implemented"
    AssertFalse      = 2,   // assert(false) / __builtin_unreachable markers
    StubComment      = 3,   // "stub" / "placeholder" comments
    FakeSuccess      = 4,   // "fake success" / "pretend" / "hardcoded demo"
    DisabledPath     = 5,   // #if 0 blocks / disabled production branch text
    StubBody         = 6,   // empty production-looking body { } or { return; }
    UnimplementedRef = 7,   // "unimplemented" identifiers/comments
};

inline const char* scanKindName(ScanKind k) {
    switch (k) {
        case ScanKind::TodoFixme:        return "todo_fixme";
        case ScanKind::NotImplemented:   return "not_implemented";
        case ScanKind::AssertFalse:      return "assert_false";
        case ScanKind::StubComment:      return "stub_comment";
        case ScanKind::FakeSuccess:      return "fake_success";
        case ScanKind::DisabledPath:     return "disabled_path";
        case ScanKind::StubBody:         return "stub_body";
        case ScanKind::UnimplementedRef: return "unimplemented_ref";
    }
    return "other";
}

struct ScanCandidate {
    std::string file;       // workspace-relative
    uint32_t    line = 0;
    ScanKind    kind = ScanKind::StubComment;
    std::string snippet;    // trimmed source line
};

struct ScanReport {
    uint64_t filesScanned   = 0;
    uint64_t scanFailures   = 0;   // unreadable files (counted, not fatal)
    uint64_t candidates     = 0;
    bool     scanComplete   = false;
};

// Scans one file's text (already read) into candidates. Exposed for the
// scanner authority self-test.
void scanSourceText(const std::string& relPath, const std::string& text,
                    std::vector<ScanCandidate>& out);

} // namespace agent
} // namespace rawrxd