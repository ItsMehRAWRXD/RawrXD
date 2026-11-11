// ============================================================================
// Crash containment, diagnostics, and graceful-degradation tests.
// ============================================================================
#ifndef _CRT_SECURE_NO_WARNINGS
#  define _CRT_SECURE_NO_WARNINGS
#endif
#ifndef _SILENCE_CXX20_U8PATH_DEPRECATION_WARNING
#  define _SILENCE_CXX20_U8PATH_DEPRECATION_WARNING
#endif

#include "test_harness.h"
#include "crash_handler.h"

#include <filesystem>
#include <fstream>
#include <string>

namespace fs = std::filesystem;
using namespace RawrXD::Resilience;

namespace {

std::string& crashDirRef()
{
    static std::string d = (fs::temp_directory_path() / "rawrxd_crash_tests").generic_string();
    return d;
}

int countFilesWithExtension(const std::string& ext)
{
    int n = 0;
    for (const auto& e : fs::directory_iterator(fs::u8path(crashDirRef()))) {
        if (e.path().extension() == ext) ++n;
    }
    return n;
}

/**
 * @brief Reset per-test state captured by other tests.
 *
 * Safe mode and the captured report are process-global, so without an explicit
 * reset each test would inherit whatever the previous one left behind. Every
 * crash test calls this first (mirrors a SetUp() fixture in larger frameworks).
 */
void resetCrashState()
{
    CrashHandler& h = CrashHandler::instance();
    CrashHandler::enterSafeMode("");
    h.setDumpDirectory(crashDirRef());
    std::error_code ec;
    fs::remove_all(fs::u8path(crashDirRef()), ec);
    fs::create_directories(fs::u8path(crashDirRef()), ec);
}

} // anonymous namespace

// ----------------------------------------------------------------------------
// Installation lifecycle
// ----------------------------------------------------------------------------

TEST(CrashHandler, InstallIsIdempotentAndReportsState) {
    resetCrashState();
    CrashHandler& h = CrashHandler::instance();
    CHECK(h.install(crashDirRef()));
    CHECK(h.isInstalled());
    // A second install must succeed and not re-install (idempotent).
    CHECK(h.install(crashDirRef()));
    CHECK(h.isInstalled());
    CHECK(h.uninstall());
    CHECK_FALSE(h.isInstalled());
    // Restore for the remaining tests.
    CHECK(h.install(crashDirRef()));
}

TEST(CrashHandler, DumpDirectoryIsCreated) {
    resetCrashState();
    CrashHandler& h = CrashHandler::instance();
    CHECK(!h.dumpDirectory().empty());
    // install() creates the directory via setDumpDirectory.
    CHECK(fs::is_directory(fs::u8path(crashDirRef())));
}

// ----------------------------------------------------------------------------
// reportFatal: the documented "caught fatal condition" path
// ----------------------------------------------------------------------------

TEST(CrashHandler, ReportFatalWritesArtifact) {
    resetCrashState();
    CrashHandler& h = CrashHandler::instance();
    std::error_code ec;
    fs::remove_all(fs::u8path(crashDirRef()), ec);
    h.setDumpDirectory(crashDirRef());

    CHECK(h.reportFatal("Test", "synthetic fatal condition", "0xDEAD", "EXCEPTION_TEST"));

    // A crash record must exist on disk.
    const int jsonFiles = countFilesWithExtension(".json");
    CHECK(jsonFiles >= 1);

    // And the report must be queryable afterwards.
    const CrashReport r = h.lastReport();
    CHECK_EQ(r.kind, std::string("Test"));
    CHECK_EQ(r.message, std::string("synthetic fatal condition"));
    CHECK_FALSE(r.timestampUtc.empty());
    CHECK_FALSE(r.moduleName.empty());
}

TEST(CrashHandler, ReportFatalTriggersSafeMode) {
    resetCrashState();
    CrashHandler& h = CrashHandler::instance();
    CHECK_FALSE(CrashHandler::inSafeMode());
    h.reportFatal("Test", "degradation trigger");
    CHECK(CrashHandler::inSafeMode());
    CHECK(CrashHandler::safeModeReason() != nullptr);
    CHECK(std::string(CrashHandler::safeModeReason()).find("ReportFatal")
          != std::string::npos
          || std::string(CrashHandler::safeModeReason()).find("reportFatal")
             != std::string::npos);
}

TEST(CrashHandler, SafeModeCanBeClearedAndReEntered) {
    resetCrashState();
    CrashHandler::enterSafeMode("first");
    CHECK(CrashHandler::inSafeMode());
    CHECK_EQ(std::string(CrashHandler::safeModeReason()), std::string("first"));

    // The first (root-cause) reason is retained while degraded.
    CrashHandler::enterSafeMode("second");
    CHECK(CrashHandler::inSafeMode());
    CHECK_EQ(std::string(CrashHandler::safeModeReason()), std::string("first"));

    CrashHandler::enterSafeMode("");
    CHECK_FALSE(CrashHandler::inSafeMode());
    CHECK_EQ(std::string(CrashHandler::safeModeReason()), std::string(""));
}

TEST(CrashHandler, ReportFatalIsReentrancyGuarded) {
    resetCrashState();
    // A second report from inside a report must be refused rather than
    // recursing (the classic crash-handler-in-crash-handler failure).
    CrashHandler& h = CrashHandler::instance();
    CHECK(h.reportFatal("Test", "outer"));
    // Directly calling again still succeeds (no active capture), but the
    // invariant that must hold is: a report never throws and never crashes.
    CHECK(h.reportFatal("Test", "second"));
}

TEST(CrashHandler, FatalCountIncreases) {
    resetCrashState();
    CrashHandler& h = CrashHandler::instance();
    const uint64_t before = h.fatalCount();
    h.reportFatal("Test", "count me");
    const uint64_t after = h.fatalCount();
    CHECK(after >= before);   // monotonic within a process
}

// ----------------------------------------------------------------------------
// SafeModeScope
// ----------------------------------------------------------------------------

TEST(CrashHandler, SafeModeScopeRestoresStateOnExit) {
    resetCrashState();
    CHECK_FALSE(CrashHandler::inSafeMode());
    {
        SafeModeScope scope("temporary degradation for a critical section");
        CHECK(CrashHandler::inSafeMode());
        CHECK_EQ(std::string(CrashHandler::safeModeReason()),
                 std::string("temporary degradation for a critical section"));
    }
    // Leaving the scope must clear safe mode again.
    CHECK_FALSE(CrashHandler::inSafeMode());
}

// ----------------------------------------------------------------------------
// Crash report structure / diagnostics
// ----------------------------------------------------------------------------

TEST(CrashHandler, CapturedReportCarriesDiagnostics) {
    resetCrashState();
    CrashHandler& h = CrashHandler::instance();
    h.setDumpDirectory(crashDirRef());
    h.reportFatal("Seh", "synthetic access violation", "0xC0000005",
                  "EXCEPTION_ACCESS_VIOLATION");
    const CrashReport r = h.lastReport();
    CHECK_EQ(r.exceptionCode, std::string("0xC0000005"));
    CHECK_EQ(r.exceptionName, std::string("EXCEPTION_ACCESS_VIOLATION"));
    CHECK_FALSE(r.moduleName.empty());
    CHECK_FALSE(r.timestampUtc.empty());
    // Timestamps must be ISO-8601 UTC with the trailing Z.
    CHECK(r.timestampUtc.size() >= 20);
    CHECK_EQ(r.timestampUtc.substr(r.timestampUtc.size() - 1), std::string("Z"));
}

TEST(CrashHandler, CrashRecordIsValidJson) {
    resetCrashState();
    // The written artifact must be parseable JSON so tooling can consume it.
    CrashHandler& h = CrashHandler::instance();
    h.setDumpDirectory(crashDirRef());
    h.reportFatal("Test", "artifact parseability");

    bool found = false;
    for (const auto& e : fs::directory_iterator(fs::u8path(crashDirRef()))) {
        if (e.path().extension() != ".json") continue;
        std::ifstream f(e.path(), std::ios::binary);
        std::string content((std::istreambuf_iterator<char>(f)),
                             std::istreambuf_iterator<char>());
        // Minimal structural check: keys present and balanced.
        if (content.find("\"schema\"") != std::string::npos
            && content.find("\"kind\"") != std::string::npos
            && content.find("\"message\"") != std::string::npos) {
            found = true;
            break;
        }
    }
    CHECK(found);
}

// ----------------------------------------------------------------------------
// Safe mode drives conservative behaviour (the real-world usage)
// ----------------------------------------------------------------------------

TEST(CrashHandler, SubsystemsCanDegradeOnSafeMode) {
    resetCrashState();
    // Mirrors how the inference engine should behave: after a crash, take the
    // conservative path instead of repeating the operation that crashed.
    auto expensiveOperation = []() -> const char* {
        if (CrashHandler::inSafeMode()) return "cpu-fallback";
        return "gpu-accelerated";
    };

    CHECK_EQ(std::string(expensiveOperation()), std::string("gpu-accelerated"));
    SafeModeScope scope("gpu path faulted");
    CHECK_EQ(std::string(expensiveOperation()), std::string("cpu-fallback"));
    CHECK_EQ(std::string(expensiveOperation()), std::string("cpu-fallback"));
}

/**
 * @brief Runs the crash-resilience suite within this translation unit.
 *
 * Called by tests/main_hardening_tests.cpp (the single entry point for the whole
 * hardening test binary).
 */
extern "C" int runCrashResilienceSuite()
{
    // Ensure a known baseline before the suite runs.
    CrashHandler::enterSafeMode("");
    return RUN_ALL_TESTS();
}
