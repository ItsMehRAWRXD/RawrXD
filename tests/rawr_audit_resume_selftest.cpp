// ============================================================================
// rawr_audit_resume_selftest.cpp — RAWR_AUDIT_RESUME_001
// Deterministic cross-process resume + stale-guard certification. No model,
// no GPU: two AuditLedger instances over the same workspace simulate two
// OS processes (the durable files are the contract).
//
// Certifies:
//   1. process A: scan -> review 2 -> persist
//   2. process B: resumeGeneration loads the SAME generation, preserves the
//      2 verdicts, no rescan
//   3. per-file stale guard: editing a candidate's file makes its review
//      hard-reject; a fresh candidate in an untouched file still reviews
//   4. generationMatchesLive flips false after an edit (batch-boundary halt)
// ============================================================================
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>

#include "rawr_audit_state.hpp"

using namespace rawrxd::agent;

namespace {

int failures = 0;

void check(bool cond, const char* name) {
    std::printf("%-52s %s\n", name, cond ? "PASS" : "FAIL");
    if (!cond) ++failures;
}

void appendLine(const std::filesystem::path& p, const std::string& text) {
    std::ofstream f(p, std::ios::app);
    f << text << "\n";
}

} // namespace

int main(int argc, char** argv) {
    std::printf("GATE=RAWR_AUDIT_RESUME_001\n");

    const std::filesystem::path ws =
        argc > 1 ? std::filesystem::path(argv[1])
                 : std::filesystem::temp_directory_path() / "rawr_resume_test";
    std::error_code ec;
    std::filesystem::remove_all(ws, ec);
    std::filesystem::create_directories(ws, ec);
    // NOTE: a synthetic fixture workspace is used, not the live repo: the
    // live tree is huge and mid-audit edits would invalidate real state.

    const std::filesystem::path srcA = ws / "a_sample.cpp";
    const std::filesystem::path srcB = ws / "b_sample.cpp";
    {
        std::ofstream f(srcA);
        f << "int foo() {\n    // TODO: implement foo\n    return 0;\n}\n";
        std::ofstream g(srcB);
        g << "int bar() {\n    // FIXME: stub\n    return 1;\n}\n";
    }

    // --- Process A: enumerate, scan, review 2 of the candidates, persist ---
    AuditLedger a(ws);
    const uint64_t enumeratedA = a.enumerateSources();
    check(enumeratedA >= 1, "process A: enumeration >=1 file");
    a.runSourceScan();
    const uint64_t total = a.counters().candidatesTotal;
    check(total >= 2, "process A: scan produced >=2 candidates");

    uint64_t id1 = 0, id2 = 0;
    for (const auto& c : a.pendingCandidates(8)) {
        if (c.file == "a_sample.cpp" && id1 == 0) id1 = c.id;
        if (c.file == "b_sample.cpp" && id2 == 0) id2 = c.id;
    }
    check(id1 != 0 && id2 != 0, "process A: candidates in both files");
    check(a.reviewCandidate(id1, "confirmed", "fixture verdict 1"),
          "process A: review candidate 1 accepted");
    check(a.reviewCandidate(id2, "false_positive", "fixture verdict 2"),
          "process A: review candidate 2 accepted");
    check(a.loadGeneration(), "process A: generation persisted");
    const std::string epochA = a.scanEpoch();
    const uint64_t genA = a.generation().generationId;
    check(!epochA.empty(), "process A: content epoch computed");

    // --- Process B: NEW ledger instance over the same workspace ---
    AuditLedger b(ws);
    b.enumerateSources();
    check(b.resumeGeneration(), "process B: generation LOADED from disk");
    check(b.generation().generationId == genA,
          "process B: same GENERATION_ID preserved");
    check(b.scanEpoch() == epochA, "process B: same SCAN_CHANGE_HASH");
    check(b.candidatesReviewedAtLoad() == 2,
          "process B: 2 prior verdicts survived process death");
    check(b.counters().sourceScanComplete,
          "process B: no rescan (scan-complete carried)");
    check(b.generationMatchesLive(), "process B: generation matches live tree");

    // Process B reviews the NEXT candidate (simulating candidate 5).
    uint64_t idNext = 0;
    for (const auto& c : b.pendingCandidates(8)) {
        if (c.id != id1 && c.id != id2) { idNext = c.id; break; }
    }
    bool reviewedNext = false;
    if (idNext != 0) {
        reviewedNext = b.reviewCandidate(idNext, "needs_runtime_proof", "next");
        check(reviewedNext, "process B: next candidate review continues");
    } else {
        check(true, "process B: (no third candidate — skip)");
    }
    check(b.loadGeneration(), "process B: re-persist after review");

    // --- Process C: stale-source guard ---
    AuditLedger cLed(ws);
    cLed.enumerateSources();
    check(cLed.resumeGeneration(), "process C: generation re-loaded");

    // Edit a_sample.cpp in place (same path, different content).
    {
        std::ofstream f(srcA, std::ios::trunc);
        f << "int foo() {\n    // EDITED mid-audit\n    return 42;\n}\n";
    }
    check(!cLed.generationMatchesLive(),
          "process C: live epoch detects in-place edit");

    AuditLedger cStale(ws);
    cStale.enumerateSources();
    check(cStale.resumeGeneration(), "process C2: generation loaded for guard");
    // id1 lives in a_sample.cpp — the file we just edited in place.
    const bool staleRejected = !cStale.reviewCandidate(id1, "confirmed", "stale");
    check(staleRejected,
          "process C2: stale-file review hard-rejected (per-file hash guard)");
    // And the unedited file's candidate still accepts (guard precision).
    const bool freshStillOk = cStale.reviewCandidate(id2, "confirmed", "ok2");
    check(freshStillOk,
          "process C2: unedited-file review still accepted (guard precision)");

    // Cleanup fixture.
    std::filesystem::remove_all(ws, ec);

    std::printf("RESUME_FAILURES=%d\n", failures);
    const bool pass = failures == 0;
    std::printf("RAWR_AUDIT_RESUME_001=%s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;
}