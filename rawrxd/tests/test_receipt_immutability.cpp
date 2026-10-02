// test_receipt_immutability.cpp -- RAWRXD_RECEIPT_IMMUTABILITY_AUTHORITY_001
//
// Regression test for immutable receipts: prove they are create-new and not
// overwritable, AND report whether production gates actually adopted them.
//
// RAWRXD_FALSE_PASS_RETRACTION_001
// The previous version of this file printed 17 fields as string literals,
// including `VERDICT=PASS`, `STRICT_CHAIN_USES_IMMUTABLE_API=1` and
// `FIXED_PATH_WRITES_ALLOWED_FOR_STRICT_GATES=0`. None of those were measured.
// The verdict was a constant, so the test could not fail -- which is why
// RAWRXD_RECEIPT_IMMUTABILITY_AUTHORITY_001 was retracted twice (4659ed89e,
// 37685e71b) and why it stayed retracted after the retraction itself was
// duplicated.
//
// Every field below is now either (a) derived from an observation made in this
// process, or (b) derived from a count of real source callsites. The verdict is
// COMPUTED from those. If adoption is incomplete the test says so and returns
// nonzero; that is the point.
//
// The adoption scan deliberately reports what it finds rather than what it
// wishes. A gate list can be extended over time; the test cannot be edited to
// match a desired answer without the verdict fields changing, because every one
// of them is now a variable.
//
// Build: cl /EHsc /std:c++20 test_receipt_immutability.cpp ReceiptAuthority.cpp /link bcrypt.lib
// Run:   test_receipt_immutability.exe [repo_root]
// Exit:  0 = immutability holds AND adoption complete
//        2 = immutability holds, adoption INCOMPLETE (real finding)
//        1 = immutability itself is broken

#include "../src/deep2/ReceiptAuthority.h"

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>
#include <windows.h>

namespace fs = std::filesystem;

namespace {

// Count occurrences of `needle` in `text`. Used for callsite census, so it
// counts every occurrence rather than the first -- a caller that invokes the
// immutable API twice is still one authority but two callsites, and the
// mutable/immutable ratio is what the adoption claim rests on.
int CountOccurrences(const std::string& text, const std::string& needle) {
    int n = 0;
    size_t pos = 0;
    while ((pos = text.find(needle, pos)) != std::string::npos) {
        ++n;
        pos += needle.size();
    }
    return n;
}

// Count in-file callsites of `fn(`.
//
// Definition and declaration exclusion is done by FILE, not by pattern
// matching the line text. An earlier version tried to recognise a definition
// line heuristically and misclassified the real callsite at
// src/win32app/W8LifecycleAuthority.cpp:32
//
//     std::string runPath = rawrxd::receipt::beginImmutableGate(gateName);
//
// as a definition because the line contains "std::string" -- reporting
// W8_USES_IMMUTABLE_API=0 when W8 demonstrably uses the immutable API. A
// census that undercounts adoption makes a real finding disappear, which is
// the same failure mode as the hardcoded fields this file replaced.
//
// The exclusion is safe because the API is declared and defined only in
// ReceiptAuthority.{h,cpp}, and ScanAdoption skips exactly those two files.
int CountCallsites(const std::string& text, const std::string& fn) {
    int n = 0;
    size_t pos = 0;
    const std::string call = fn + "(";
    while ((pos = text.find(call, pos)) != std::string::npos) {
        ++n;
        pos += call.size();
    }
    return n;
}

std::string ReadFileOrEmpty(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f) return {};
    return std::string((std::istreambuf_iterator<char>(f)),
                       std::istreambuf_iterator<char>());
}

struct Adoption {
    int mutableCallsites   = 0;
    int immutableCallsites = 0;
    int strictUsesImmutable = 0;
    int strictUsesMutable   = 0;
    int w8UsesImmutable     = 0;
    int w8UsesMutable       = 0;
};

Adoption ScanAdoption(const fs::path& root) {
    Adoption a;
    // Walk src/ recursively and census every production callsite. Restricted to
    // .cpp/.h/.hpp so no build artifact or log contributes a match.
    std::vector<fs::path> files;
    for (fs::recursive_directory_iterator it(root / "src"), end; it != end; ++it) {
        if (!it->is_regular_file()) continue;
        const std::string ext = it->path().extension().string();
        if (ext != ".cpp" && ext != ".h" && ext != ".hpp") continue;
        files.push_back(it->path());
    }
    for (const fs::path& f : files) {
        const std::string text = ReadFileOrEmpty(f);
        if (text.empty()) continue;
        const std::string name = f.filename().string();
        // Skip the authority's own declaration/definition file so the API does
        // not count as its own adoption.
        if (name == "ReceiptAuthority.cpp" || name == "ReceiptAuthority.h") continue;

        const int imm = CountCallsites(text, "beginImmutableGate");
        // `beginGate(` is a substring of neither; guard against the immutable
        // name containing it (it does not, but the census must not depend on
        // that staying true).
        const int mut = CountCallsites(text, "beginGate");
        a.immutableCallsites += imm;
        a.mutableCallsites += mut;

        if (name == "StrictCertificationAuthority.cpp") {
            a.strictUsesImmutable = imm;
            a.strictUsesMutable = mut;
        }
        if (name == "W8LifecycleAuthority.cpp") {
            a.w8UsesImmutable = imm;
            a.w8UsesMutable = mut;
        }
    }
    return a;
}

} // namespace

int main(int argc, char** argv) {
    // Unbuffered: a run that faults partway must still have emitted what it
    // measured. A block-buffered stdout under redirection discards exactly the
    // evidence a failure needs.
    setvbuf(stdout, nullptr, _IONBF, 0);

    const char* kGateName = "RAWRXD_RECEIPT_IMMUTABILITY_TEST_001";
    const std::string gateName = kGateName;

    // Receipt location and source-scan root are DIFFERENT paths and must not be
    // conflated:
    //
    //   receipts  -> ReceiptAuthority.cpp:73 uses current_path()/receipts/<gate>
    //   scan root -> the directory that CONTAINS src/
    //
    // The first version of this test derived both from one root, so passing the
    // repo root made it look for F:\~dev\receipts while the authority wrote to
    // the process working directory. It then reported LATEST_POINTER_UPDATED=0
    // and INDEX_ENTRIES=0 as though immutability had failed. The immutability
    // mechanism was fine; the test was checking the wrong directory.
    //
    // Note the repo root also has a src/ directory that contains none of these
    // gates, so "does src/ exist" is not a sufficient test for the scan root --
    // the gates must actually be found under it.
    const fs::path cwd = fs::current_path();
    const fs::path receiptRoot = cwd / "receipts";

    fs::path root = (argc > 1) ? fs::path(argv[1]) : cwd;
    if (!fs::exists(root / "src" / "cert" / "StrictCertificationAuthority.cpp") &&
        fs::exists(root / "rawrxd" / "src" / "cert" / "StrictCertificationAuthority.cpp")) {
        root = root / "rawrxd";
    }

    std::printf("GATE=RAWRXD_RECEIPT_IMMUTABILITY_AUTHORITY_001\n");
    std::printf("SCAN_ROOT=%s\n", root.string().c_str());
    std::printf("RECEIPT_ROOT=%s\n", receiptRoot.string().c_str());
    if (!fs::exists(root / "src" / "cert" / "StrictCertificationAuthority.cpp")) {
        std::fprintf(stderr,
            "FAIL: scan root %s does not contain src/cert/StrictCertificationAuthority.cpp; "
            "adoption would be reported as zero by construction\n",
            root.string().c_str());
        return 1;
    }

    const fs::path receiptDir = receiptRoot / gateName;
    std::error_code ec;
    fs::remove_all(receiptDir, ec);

    // ================================================== immutability behaviour
    int failures = 0;

    const std::string run1 = rawrxd::receipt::beginImmutableGate(gateName);
    if (run1.empty()) {
        std::fprintf(stderr, "FAIL: beginImmutableGate returned empty for run 1\n");
        return 1;
    }
    rawrxd::receipt::writeImmutableKeyValue(run1, "TEST_FIELD", "RUN_1_DATA");
    const std::string sha1 =
        rawrxd::receipt::endImmutableGate(run1, "PASS");
    if (sha1.empty()) {
        std::fprintf(stderr, "FAIL: endImmutableGate returned empty SHA for run 1\n");
        return 1;
    }
    if (!fs::exists(run1)) {
        std::fprintf(stderr, "FAIL: first receipt missing at %s\n", run1.c_str());
        ++failures;
    }
    // Hash of the finalized run-1 receipt. Computed now so the post-run-2 check
    // compares against a value observed BEFORE run 2 happened.
    const std::string sha1Before = rawrxd::receipt::sha256File(run1);

    const std::string run2 = rawrxd::receipt::beginImmutableGate(gateName);
    if (run2.empty()) {
        std::fprintf(stderr, "FAIL: beginImmutableGate returned empty for run 2\n");
        return 1;
    }
    rawrxd::receipt::writeImmutableKeyValue(run2, "TEST_FIELD", "RUN_2_DATA");
    const std::string sha2 = rawrxd::receipt::endImmutableGate(run2, "PASS");

    const bool distinctPath = (run2 != run1);
    const bool run1Survives = fs::exists(run1);
    const std::string sha1After = rawrxd::receipt::sha256File(run1);
    // The real immutability proof: run 2 did not alter run 1's bytes. The old
    // version asserted this as a literal and never compared the two hashes.
    const bool shaUnchanged = (sha1Before == sha1After) && !sha1After.empty();

    const fs::path latestPath = receiptDir / "latest.txt";
    bool latestOk = false;
    std::string latestContent;
    if (fs::exists(latestPath)) {
        std::ifstream lf(latestPath);
        std::getline(lf, latestContent);
        latestOk = (latestContent == run2);
    }

    const fs::path indexPath = receiptDir / "index.jsonl";
    int indexLines = 0;
    if (fs::exists(indexPath)) {
        std::ifstream inf(indexPath);
        std::string line;
        while (std::getline(inf, line)) ++indexLines;
    }

    // CREATE_NEW: re-creating an existing run path must fail.
    HANDLE h = CreateFileA(run1.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    const bool overwriteBlocked = (h == INVALID_HANDLE_VALUE);
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);

    const bool immutableHolds =
        distinctPath && run1Survives && shaUnchanged && latestOk &&
        indexLines == 2 && overwriteBlocked && !sha1.empty() && !sha2.empty();

    if (!immutableHolds) {
        ++failures;
        std::fprintf(stderr,
            "FAIL: immutability broken: distinct=%d survives=%d shaStable=%d "
            "latest=%d indexLines=%d overwriteBlocked=%d\n",
            distinctPath, run1Survives, shaUnchanged, latestOk, indexLines,
            overwriteBlocked);
    }

    // ===================================================== adoption (measured)
    const Adoption a = ScanAdoption(root);
    const bool strictAdopted = (a.strictUsesImmutable > 0 && a.strictUsesMutable == 0);
    const bool w8Adopted      = (a.w8UsesImmutable > 0 && a.w8UsesMutable == 0);
    const bool adoptionComplete = strictAdopted && w8Adopted &&
                                  a.mutableCallsites == 0;

    // Fields are named to match the historical receipt keys so a downstream
    // reader comparing old and new runs sees the same vocabulary, but every
    // value is an observation.
    std::printf("RECEIPT_AUTHORITY_PRESENT=1\n");
    std::printf("IMMUTABLE_RUN_PATH_ENABLED=%d\n", distinctPath ? 1 : 0);
    std::printf("CREATE_NEW_SEMANTICS=%d\n", overwriteBlocked ? 1 : 0);
    std::printf("FIRST_RUN_RECEIPT_PATH=%s\n", run1.c_str());
    std::printf("FIRST_RUN_RECEIPT_SHA256_BEFORE_SECOND=%s\n", sha1Before.c_str());
    std::printf("FIRST_RUN_RECEIPT_SHA256_AFTER_SECOND=%s\n", sha1After.c_str());
    std::printf("SECOND_RUN_RECEIPT_PATH=%s\n", run2.c_str());
    std::printf("SECOND_RUN_RECEIPT_SHA256=%s\n", sha2.c_str());
    std::printf("SECOND_RUN_CREATED_DISTINCT_RECEIPT=%d\n", distinctPath ? 1 : 0);
    std::printf("FIRST_RUN_RECEIPT_STILL_EXISTS=%d\n", run1Survives ? 1 : 0);
    std::printf("FIRST_RUN_RECEIPT_SHA256_UNCHANGED=%d\n", shaUnchanged ? 1 : 0);
    std::printf("LATEST_POINTER_PATH=%s\n", latestPath.string().c_str());
    std::printf("LATEST_POINTER_UPDATED=%d\n", latestOk ? 1 : 0);
    std::printf("INDEX_PATH=%s\n", indexPath.string().c_str());
    std::printf("INDEX_ENTRIES=%d\n", indexLines);
    std::printf("INDEX_APPEND_ONLY=%d\n", indexLines == 2 ? 1 : 0);
    std::printf("OVERWRITE_ATTEMPT_BLOCKED=%d\n", overwriteBlocked ? 1 : 0);

    std::printf("BEGIN_IMMUTABLE_GATE_CALLSITES=%d\n", a.immutableCallsites);
    std::printf("LEGACY_BEGIN_GATE_CALLSITES=%d\n", a.mutableCallsites);
    std::printf("STRICT_CHAIN_USES_IMMUTABLE_API=%d\n", strictAdopted ? 1 : 0);
    std::printf("STRICT_CHAIN_IMMUTABLE_CALLSITES=%d\n", a.strictUsesImmutable);
    std::printf("STRICT_CHAIN_MUTABLE_CALLSITES=%d\n", a.strictUsesMutable);
    std::printf("W8_USES_IMMUTABLE_API=%d\n", w8Adopted ? 1 : 0);
    std::printf("W8_IMMUTABLE_CALLSITES=%d\n", a.w8UsesImmutable);
    std::printf("W8_MUTABLE_CALLSITES=%d\n", a.w8UsesMutable);
    std::printf("PRODUCTION_ADOPTION_COMPLETE=%d\n", adoptionComplete ? 1 : 0);
    std::printf("IMMUTABILITY_HOLDS=%d\n", immutableHolds ? 1 : 0);

    // Verdict is COMPUTED, never asserted.
    std::string verdict;
    int exitCode;
    if (!immutableHolds) {
        verdict = "FAIL_IMMUTABILITY_BROKEN";
        exitCode = 1;
    } else if (!adoptionComplete) {
        verdict = "FAIL_ADOPTION_INCOMPLETE";
        exitCode = 2;
    } else {
        verdict = "PASS";
        exitCode = 0;
    }
    std::printf("VERDICT=%s\n", verdict.c_str());

    // This gate's own receipt is written through the immutable API, so the
    // receipt recording adoption is itself append-only and hashed.
    const std::string selfRun =
        rawrxd::receipt::beginImmutableGate("RAWRXD_RECEIPT_IMMUTABILITY_AUTHORITY_001");
    if (!selfRun.empty()) {
        rawrxd::receipt::writeImmutableKeyValueInt(
            selfRun, "BEGIN_IMMUTABLE_GATE_CALLSITES", a.immutableCallsites);
        rawrxd::receipt::writeImmutableKeyValueInt(
            selfRun, "LEGACY_BEGIN_GATE_CALLSITES", a.mutableCallsites);
        rawrxd::receipt::writeImmutableKeyValueInt(
            selfRun, "STRICT_CHAIN_USES_IMMUTABLE_API", strictAdopted ? 1 : 0);
        rawrxd::receipt::writeImmutableKeyValueInt(
            selfRun, "W8_USES_IMMUTABLE_API", w8Adopted ? 1 : 0);
        rawrxd::receipt::writeImmutableKeyValueInt(
            selfRun, "PRODUCTION_ADOPTION_COMPLETE", adoptionComplete ? 1 : 0);
        rawrxd::receipt::writeImmutableKeyValueInt(
            selfRun, "IMMUTABILITY_HOLDS", immutableHolds ? 1 : 0);
        rawrxd::receipt::writeImmutableKeyValue(
            selfRun, "VERDICT", verdict);
        const std::string selfSha =
            rawrxd::receipt::endImmutableGate(selfRun, verdict);
        std::printf("SELF_RECEIPT=%s\n", selfRun.c_str());
        std::printf("SELF_RECEIPT_SHA256=%s\n", selfSha.c_str());
    } else {
        std::printf("SELF_RECEIPT=NONE\n");
    }

    fs::remove_all(receiptDir, ec);
    return exitCode;
}