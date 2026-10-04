// ============================================================================
// cpu_inference_engine_autofix.hpp — RAWRXD_AUTOFIX_ENGINE_001
// ============================================================================
// Interface for the autonomous repair loop.
//
// Separated from the implementation so that the driver (cli_entrypoint.cpp) and
// the engine can be read, and criticised, independently. Everything here is
// plain data: no callbacks, no globals, no hidden state. A finding carries its
// evidence, a fix carries its own before/after sizes, and a diagnosis carries
// the phase and exit code it was derived from. That is what makes the receipt
// in the driver checkable rather than decorative.
// ============================================================================

#ifndef RAWRXD_CPU_INFERENCE_ENGINE_AUTOFIX_HPP
#define RAWRXD_CPU_INFERENCE_ENGINE_AUTOFIX_HPP

#include <cstdint>
#include <string>
#include <vector>

namespace rawrxd {
namespace autofix {

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
struct Config {
    std::string repoRoot       = ".";
    std::string buildDir       = "";
    std::string config         = "Debug";
    std::string buildTarget    = "";
    std::string testExe        = "";
    std::string testArgs       = "";
    std::string defines        = "";   // e.g. "-DBUILD_RAWRXD_RUN_MODELNAME_001=ON"
    std::string cmakeExe       = "cmake";
    // RAWRXD_AUTOFIX_ALLOWLIST_001
    // The authoritative declaration of which codeless translation units are
    // KNOWN and accepted. Defaults to the same file the configure-time gate
    // reads (rawrxd_filter_missing_sources -> cmake/known_empty_sources.txt) so
    // this engine and CMake cannot disagree about what is a regression.
    std::string knownEmptyList = "";
    int         maxIterations  = 4;
    bool        dryRun         = false;
    // uint32_t, not DWORD: the public interface carries no <windows.h>
    // dependency, so this header can be included by a target that does not link
    // against the Windows SDK. The implementation narrows it to DWORD.
    uint32_t    phaseTimeoutMs = 20u * 60u * 1000u;
};

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------
struct Finding {
    enum class Kind {
        ABSENT_ACTIVE_REF,   // named by an active CMake entry, absent on disk
        STUB_TU_IN_TARGET,   // in an active target, contains no code, NOT declared
                             // known-empty -> a genuine regression
        KNOWN_EMPTY,         // codeless but declared in known_empty_sources.txt.
                             // REPORTED so the census is complete, never acted on.
        UNCLASSIFIED         // observed but not mechanically repairable
    };

    Kind        kind = Kind::UNCLASSIFIED;
    std::string path;
    std::string detail;       // the evidence, including the citing line number
};

struct AuditResult {
    std::string              cmakePath;
    std::string              knownEmptyListPath;
    bool                     allowListLoaded = false;
    std::size_t              allowListEntries = 0;
    std::size_t              cmakeBytes  = 0;
    std::size_t              entriesScanned = 0;

    // RAWRXD_AUTOFIX_CENSUS_VOCABULARY_001
    //
    // These three are deliberately NOT collapsed into one "findings" number.
    // rawCodeless is what the filesystem says; the other two say how much of it
    // is declared versus not. A single figure implies every codeless unit is a
    // defect, which is false: the authoritative configure gate carries 352
    // declared-empty units. Emitting the split is the difference between a
    // census and a complaint.
    std::size_t              rawCodeless      = 0;   // bodies strip to no code
    std::size_t              knownEmptyCount  = 0;   // ...and declared known-empty
    std::size_t              unexpectedCount  = 0;   // ...and NOT declared

    std::vector<Finding>     findings;       // actionable only
    std::string              fatal;          // non-empty => audit could not run
};

struct FixResult {
    // Finding::Kind::UNCLASSIFIED, not Finding::UNCLASSIFIED: UNCLASSIFIED is an
    // enumerator of the nested Kind, not a member of Finding. The latter compiles
    // nowhere and was a real compile error here, caught by building rather than by
    // reasoning about it.
    Finding::Kind kind = Finding::Kind::UNCLASSIFIED;
    bool        applied   = false;
    std::string note;
    std::string error;
    std::string backupPath;
    std::size_t beforeBytes = 0;
    std::size_t afterBytes  = 0;
};

// ---------------------------------------------------------------------------
// External process result
// ---------------------------------------------------------------------------
struct ProcResult {
    bool        launched = false;
    uint32_t    exitCode = 0xFFFFFFFFu;
    std::string output;
    uint32_t    win32Error = 0;
};

// ---------------------------------------------------------------------------
// Diagnosis
// ---------------------------------------------------------------------------
struct Diagnosis {
    std::string phase;      // CONFIGURE | BUILD | TEST
    uint32_t    exitCode = 0;
    std::string reason;     // stable machine-readable class
    std::string action;     // what a human or the next iteration should do
};

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------
AuditResult  audit(const Config& cfg);
FixResult    applyFix(const Config& cfg, const Finding& f);
ProcResult   configure(const Config& cfg);
ProcResult   build(const Config& cfg);
ProcResult   runTest(const Config& cfg);
Diagnosis    diagnose(const std::string& phase, const ProcResult& r);

const char* kindName(Finding::Kind k);

} // namespace autofix
} // namespace rawrxd

#endif // RAWRXD_CPU_INFERENCE_ENGINE_AUTOFIX_HPP
