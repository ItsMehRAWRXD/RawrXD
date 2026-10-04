// ============================================================================
// cli_entrypoint.cpp — RAWRXD_AUTOFIX_CLI_001
// ============================================================================
// main() for RawrXD-AutoFixCLI: the audit -> inspect -> edit -> build -> test
// -> diagnose -> retry loop described as the single feature that moves RawrXD
// from an AI-enabled IDE to an autonomous engineering IDE.
//
// This file was a 24-byte "// Auto-generated stub". The target linked to a
// binary containing none of its own code and failed with
// LNK2019: unresolved external symbol main. Both facts are recorded because the
// ghost-receipt pattern -- a target that exists, links and runs while
// implementing nothing -- is what this program exists to detect, and it was
// itself an instance of it.
//
// ----------------------------------------------------------------------------
// THE RECEIPT IS COMPUTED, NOT ASSERTED
// ----------------------------------------------------------------------------
// VERDICT=PASS requires, in the same run:
//
//   CONFIGURE_EXIT == 0
//   BUILD_EXIT     == 0
//   TEST_EXIT      == 0      (TEST_NOT_CONFIGURED cannot reach PASS)
//   FIXES_NOT_LOAD_BEARING == 0
//
// There is no code path that prints PASS without all four. A run that fixes
// nothing and builds cleanly is reported as NO_FINDINGS, not PASS, because
// "nothing was wrong" is not evidence that the loop works.
//
// ----------------------------------------------------------------------------
// LOAD-BEARING PROOF PER FIX
// ----------------------------------------------------------------------------
// Each fix is admitted only if it demonstrably removed the symptom it targeted:
//
//   * ABSENT_ACTIVE_REF -- before: CMakeLists.txt names a path that is not on
//     disk (audited directly). After: that path is no longer an active entry.
//   * STUB_TU_IN_TARGET  -- before: the referenced TU's body strips to nothing
//     or reduces to int main(){return 0;}. After: it is no longer an active
//     entry.
//
// A fix whose symptom survives is recorded as FIX_NOT_LOAD_BEARING and forces
// the run to FAIL, no matter how green the build is. That is the whole point:
// an edit that changes nothing measurable is not a repair.
//
// ----------------------------------------------------------------------------
// DRY RUN IS THE DEFAULT-SAFE PATH
// ----------------------------------------------------------------------------
// --dry-run performs the audit, the diagnosis and the receipt, and makes NO
// edit. It is the mode to use before trusting the loop with a working tree.
// CMakeLists.txt is additionally backed up to .autofix.bak before every write,
// and a failed write restores the original.
// ============================================================================

#include "cpu_inference_engine_autofix.hpp"

#include <windows.h>

#include <cstdio>
#include <cstring>
#include <string>

namespace {

using namespace rawrxd::autofix;

void usage() {
    std::printf(
        "RawrXD-AutoFixCLI -- RAWRXD_AUTOFIX_CLI_001\n"
        "\n"
        "  autofix <repo-root> [options]\n"
        "\n"
        "  --build-dir <dir>      CMake binary directory (required)\n"
        "  --config <Debug|Release>\n"
        "  --target <name>        pass --target to the build\n"
        "  --define \"<cmake -D…>\"  e.g. -DBUILD_RAWRXD_RUN_MODELNAME_001=ON\n"
        "  --test-exe <path>      test command; without it PASS is unreachable\n"
        "  --test-args \"<args>\"\n"
        "  --cmake <path>         cmake executable (default: cmake)\n"
        "  --max-iterations <n>   default 4\n"
        "  --timeout-ms <n>       per-phase timeout, default 1200000\n"
        "  --dry-run              audit and diagnose only; makes NO edit\n"
        "  --known-empty-list <path>  declaration list of accepted codeless TUs\n"
        "                        (default: <repo>/cmake/known_empty_sources.txt)\n"

        "  --help\n"
        "\n"
        "VERDICT=PASS requires CONFIGURE_EXIT==0 AND BUILD_EXIT==0 AND\n"
        "TEST_EXIT==0 AND FIXES_NOT_LOAD_BEARING==0.\n");
}

std::string argValue(int argc, char** argv, int& i, const char* flag) {
    if (i + 1 >= argc) return {};
    return argv[++i];
}

bool argHas(int argc, char** argv, int& i, const char* flag) {
    (void)argc; (void)argv; (void)i;
    return flag != nullptr;
}

// Re-audit only the finding we are about to act on, and ask whether its
// symptom is gone. Scoped deliberately: a full re-audit would also report the
// findings we have not fixed yet and could not distinguish them.
bool symptomPresent(const Config& cfg, const Finding& f) {
    AuditResult now = audit(cfg);
    for (const Finding& g : now.findings) {
        if (g.path != f.path) continue;
        // Same path, same class => still present.
        if (g.kind == f.kind) return true;
    }
    return false;
}

} // namespace

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);

    Config cfg;
    std::string root;

    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--help" || a == "-h") { usage(); return 0; }
        else if (a == "--build-dir")      cfg.buildDir = argValue(argc, argv, i, "--build-dir");
        else if (a == "--config")         cfg.config = argValue(argc, argv, i, "--config");
        else if (a == "--target")         cfg.buildTarget = argValue(argc, argv, i, "--target");
        else if (a == "--define")         cfg.defines = argValue(argc, argv, i, "--define");
        else if (a == "--test-exe")       cfg.testExe = argValue(argc, argv, i, "--test-exe");
        else if (a == "--test-args")      cfg.testArgs = argValue(argc, argv, i, "--test-args");
        else if (a == "--cmake")          cfg.cmakeExe = argValue(argc, argv, i, "--cmake");
        else if (a == "--max-iterations") cfg.maxIterations = std::atoi(argValue(argc, argv, i, "--max-iterations").c_str());
        else if (a == "--timeout-ms")     cfg.phaseTimeoutMs = (DWORD)std::atol(argValue(argc, argv, i, "--timeout-ms").c_str());
        else if (a == "--dry-run")        cfg.dryRun = true;
        else if (a == "--known-empty-list") cfg.knownEmptyList = argValue(argc, argv, i, "--known-empty-list");
        else if (!a.empty() && a[0] != '-' && root.empty()) root = a;
        else { std::fprintf(stderr, "UNKNOWN_ARG=%s\n", a.c_str()); usage(); return 2; }
    }

    if (root.empty()) { usage(); return 2; }
    cfg.repoRoot = root;

    if (cfg.buildDir.empty()) {
        std::fprintf(stderr, "FATAL=MISSING_BUILD_DIR\n"
                             "REASON=--build-dir is required; without it the loop "
                             "could not observe a build and could not fail closed.\n");
        return 2;
    }
    if (cfg.maxIterations < 1) cfg.maxIterations = 1;

    std::printf("RAWRXD_AUTOFIX_CLI_001\n");
    std::printf("REPO_ROOT=%s\n", cfg.repoRoot.c_str());
    std::printf("BUILD_DIR=%s\n", cfg.buildDir.c_str());
    std::printf("CONFIG=%s\n", cfg.config.c_str());
    std::printf("DRY_RUN=%d\n", cfg.dryRun ? 1 : 0);
    std::printf("MAX_ITERATIONS=%d\n\n", cfg.maxIterations);

    // ===================== PHASE 1: AUDIT ===============================
    std::printf("=== PHASE 1: AUDIT ===\n");
    AuditResult ar = audit(cfg);
    if (!ar.fatal.empty()) {
        std::printf("AUDIT_FATAL=%s\n", ar.fatal.c_str());
        std::printf("VERDICT=FAIL\n");
        return 1;
    }
    std::printf("CMAKE=%s\n", ar.cmakePath.c_str());
    std::printf("CMAKE_BYTES=%zu\n", ar.cmakeBytes);
    std::printf("ACTIVE_ENTRIES_SCANNED=%zu\n", ar.entriesScanned);

    // RAWRXD_AUTOFIX_CENSUS_VOCABULARY_001
    //
    // The three counts are emitted separately and RAW_CODELESS_TU_COUNT is the
    // name, not STUB_TU_IN_TARGET. "STUB" would assert that all of them are
    // defects; they are not. 352 of them are declared in
    // cmake/known_empty_sources.txt and the configure gate has accepted them for
    // that long. Collapsing the three into one number is how a census becomes a
    // complaint, and it is how this engine's first run overstated the repository's
    // defects by 2.2x.
    std::printf("KNOWN_EMPTY_LIST=%s\n", ar.knownEmptyListPath.c_str());
    std::printf("KNOWN_EMPTY_ALLOWLIST_APPLIED=%d\n", ar.allowListLoaded ? 1 : 0);
    std::printf("ALLOWLIST_ENTRIES=%zu\n", ar.allowListEntries);
    std::printf("RAW_CODELESS_TU_COUNT=%zu\n", ar.rawCodeless);
    std::printf("KNOWN_EMPTY_TU_COUNT=%zu\n", ar.knownEmptyCount);
    std::printf("UNEXPECTED_CODELESS_TU_COUNT=%zu\n", ar.unexpectedCount);

    // Actionable findings only. KNOWN_EMPTY is reported by the census above and
    // is never a repair candidate.
    std::size_t actionable = 0;
    for (const Finding& f : ar.findings)
        if (f.kind != Finding::Kind::KNOWN_EMPTY) ++actionable;
    std::printf("ACTIONABLE_FINDINGS=%zu\n", actionable);
    for (std::size_t k = 0; k < ar.findings.size(); ++k) {
        const Finding& f = ar.findings[k];
        std::printf("FINDING_%zu=%s path=%s detail=\"%s\"\n",
                    k, kindName(f.kind), f.path.c_str(), f.detail.c_str());
    }

    int  fixesApplied = 0;
    int  fixesLoadBearing = 0;
    int  fixesNotLoadBearing = 0;
    int  iterations = 0;

    uint32_t configureExit = 0xFFFFFFFFu;
    uint32_t buildExit     = 0xFFFFFFFFu;
    uint32_t testExit      = 0xFFFFFFFFu;
    bool     configureRan  = false;
    bool     buildRan      = false;
    bool     testRan       = false;
    bool     configureOk   = false;
    bool     buildOk       = false;
    bool     testOk        = false;
    Diagnosis lastDiag;

    // ===================== REPAIR LOOP ==================================
    while (iterations < cfg.maxIterations) {
        ++iterations;
        std::printf("\n=== ITERATION %d ===\n", iterations);

        // -- 2. CONFIGURE ------------------------------------------------
        std::printf("-- PHASE: CONFIGURE\n");
        ProcResult cr = configure(cfg);
        configureRan = true;
        configureExit = cr.exitCode;
        configureOk = cr.launched && cr.exitCode == 0;
        std::printf("CONFIGURE_LAUNCHED=%d CONFIGURE_EXIT=%u\n",
                    cr.launched ? 1 : 0, cr.exitCode);
        if (!configureOk) {
            lastDiag = diagnose("CONFIGURE", cr);
            std::printf("DIAGNOSIS_REASON=%s\n", lastDiag.reason.c_str());
            std::printf("DIAGNOSIS_ACTION=%s\n", lastDiag.action.c_str());
            std::printf("--- configure output (tail) ---\n%s\n",
                        cr.output.size() > 4000 ? cr.output.substr(cr.output.size() - 4000).c_str()
                                                : cr.output.c_str());
        }

        // -- 3. BUILD ----------------------------------------------------
        if (configureOk) {
            std::printf("-- PHASE: BUILD\n");
            ProcResult br = build(cfg);
            buildRan = true;
            buildExit = br.exitCode;
            buildOk = br.launched && br.exitCode == 0;
            std::printf("BUILD_LAUNCHED=%d BUILD_EXIT=%u\n",
                        br.launched ? 1 : 0, br.exitCode);
            if (!buildOk) {
                lastDiag = diagnose("BUILD", br);
                std::printf("DIAGNOSIS_REASON=%s\n", lastDiag.reason.c_str());
                std::printf("DIAGNOSIS_ACTION=%s\n", lastDiag.action.c_str());
                std::printf("--- build output (tail) ---\n%s\n",
                            br.output.size() > 4000 ? br.output.substr(br.output.size() - 4000).c_str()
                                                    : br.output.c_str());
            }
        } else {
            std::printf("-- PHASE: BUILD SKIPPED (configure did not succeed)\n");
        }

        // -- 4. TEST -----------------------------------------------------
        if (configureOk && buildOk) {
            std::printf("-- PHASE: TEST\n");
            ProcResult tr = runTest(cfg);
            testRan = tr.launched;
            testExit = tr.exitCode;
            testOk = tr.launched && tr.exitCode == 0;
            std::printf("TEST_LAUNCHED=%d TEST_EXIT=%u\n",
                        tr.launched ? 1 : 0, tr.exitCode);
            std::printf("--- test output (tail) ---\n%s\n",
                        tr.output.size() > 4000 ? tr.output.substr(tr.output.size() - 4000).c_str()
                                                : tr.output.c_str());
            if (!testOk) {
                lastDiag = diagnose("TEST", tr);
                std::printf("DIAGNOSIS_REASON=%s\n", lastDiag.reason.c_str());
                std::printf("DIAGNOSIS_ACTION=%s\n", lastDiag.action.c_str());
            }
        } else {
            std::printf("-- PHASE: TEST SKIPPED (configure or build did not succeed)\n");
        }

        // -- 5. GREEN? ---------------------------------------------------
        if (configureOk && buildOk && testOk && fixesNotLoadBearing == 0) {
            std::printf("\nGREEN at iteration %d.\n", iterations);
            break;
        }

        // -- 6. RETRY: apply at most one finding this iteration -----------
        if (cfg.dryRun) {
            std::printf("DRY_RUN=1 -> no edit attempted; loop stops here.\n");
            break;
        }

        bool appliedThisIteration = false;
        for (const Finding& f : ar.findings) {
            // Declared known-empty units are census, not defects. Acting on one
            // would "repair" an intentional empty TU by deleting its reference,
            // which is the opposite of correct.
            if (f.kind == Finding::Kind::KNOWN_EMPTY) continue;
            // Never re-attempt a finding we already fixed this run.
            bool alreadyFixed = false;
            // (fixesApplied counts everything; the symptom check below prevents
            //  a second application because a fixed finding stops being audited)
            (void)alreadyFixed;

            const bool present = symptomPresent(cfg, f);
            if (!present) continue;   // already repaired

            std::printf("\n-- APPLY FIX for %s (%s)\n", f.path.c_str(), kindName(f.kind));
            FixResult fx = applyFix(cfg, f);
            if (!fx.applied) {
                std::printf("FIX_FAILED=%s\n", fx.error.c_str());
                continue;
            }
            ++fixesApplied;
            std::printf("FIX_NOTE=%s\n", fx.note.c_str());
            std::printf("FIX_CMAKE_BYTES_BEFORE=%zu AFTER=%zu\n", fx.beforeBytes, fx.afterBytes);
            std::printf("FIX_BACKUP=%s\n", fx.backupPath.c_str());

            const bool stillThere = symptomPresent(cfg, f);
            if (stillThere) {
                ++fixesNotLoadBearing;
                std::printf("FIX_NOT_LOAD_BEARING=1  %s still present after the edit\n",
                            f.path.c_str());
            } else {
                ++fixesLoadBearing;
                std::printf("FIX_NOT_LOAD_BEARING=0  %s symptom cleared\n",
                            f.path.c_str());
            }
            appliedThisIteration = true;
            break;   // one fix per iteration, so the build result attributes
                     // cleanly to exactly one change
        }

        if (!appliedThisIteration) {
            std::printf("NO_APPLICABLE_FIX this iteration.\n");
            break;
        }

        // Refresh the finding list for the next iteration.
        AuditResult fresh = audit(cfg);
        if (!fresh.fatal.empty()) {
            std::printf("AUDIT_FATAL=%s\n", fresh.fatal.c_str());
            break;
        }
        ar = fresh;
        std::printf("REMAINING_FINDINGS=%zu\n", ar.findings.size());
    }

    // ===================== RECEIPT =====================================
    std::printf("\n=== RECEIPT ===\n");
    std::printf("ITERATIONS=%d\n", iterations);
    std::printf("AUDIT_FINDINGS_INITIAL=%zu\n", ar.findings.size());
    std::printf("FIXES_APPLIED=%d\n", fixesApplied);
    std::printf("FIXES_LOAD_BEARING=%d\n", fixesLoadBearing);
    std::printf("FIXES_NOT_LOAD_BEARING=%d\n", fixesNotLoadBearing);
    std::printf("CONFIGURE_RAN=%d CONFIGURE_EXIT=%u\n", configureRan ? 1 : 0, configureExit);
    std::printf("BUILD_RAN=%d BUILD_EXIT=%u\n", buildRan ? 1 : 0, buildExit);
    std::printf("TEST_RAN=%d TEST_EXIT=%u\n", testRan ? 1 : 0, testExit);
    if (!cfg.testExe.empty())
        std::printf("TEST_CONFIGURED=1\n");
    else
        std::printf("TEST_CONFIGURED=0  (an unrun test is not a passed test)\n");

    // The verdict is a function of observed exit codes and fix accounting only.
    const bool allGreen = configureRan && configureOk &&
                          buildRan && buildOk &&
                          testRan && testOk &&
                          fixesNotLoadBearing == 0;
    if (allGreen) {
        if (fixesApplied == 0) {
            std::printf("VERDICT=NO_FINDINGS\n");
            std::printf("REASON=configure, build and test all succeeded and the "
                        "audit found nothing to repair.\n");
            std::printf("       That is a clean tree, not evidence that the "
                        "repair loop works.\n");
            return 0;
        }
        std::printf("FIXES_VERIFIED_LOAD_BEARING=1\n");
        std::printf("VERDICT=PASS\n");
        return 0;
    }

    std::printf("VERDICT=FAIL\n");
    if (!configureRan || !configureOk)
        std::printf("BLOCKING_PHASE=CONFIGURE\n");
    else if (!buildRan || !buildOk)
        std::printf("BLOCKING_PHASE=BUILD\n");
    else if (!testRan || !testOk)
        std::printf("BLOCKING_PHASE=TEST\n");
    else if (fixesNotLoadBearing > 0)
        std::printf("BLOCKING_PHASE=VERIFICATION\n");

    if (!lastDiag.reason.empty()) {
        std::printf("LAST_DIAGNOSIS_PHASE=%s\n", lastDiag.phase.c_str());
        std::printf("LAST_DIAGNOSIS_REASON=%s\n", lastDiag.reason.c_str());
        std::printf("LAST_DIAGNOSIS_ACTION=%s\n", lastDiag.action.c_str());
    }
    return 1;
}
