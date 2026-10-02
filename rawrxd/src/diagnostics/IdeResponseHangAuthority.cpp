// IDE response hang dumpbin authority implementation
// RawrXD IdeResponseHangAuthority - Gates IDE response hang analysis via dumpbin

#include "src/diagnostics/IdeResponseHangAuthority.h"
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

namespace rawrxd::diagnostics
{
    // Global IDE response hang authority state
    struct IdeResponseHangAuthorityState
    {
        bool entered = false;
        std::string exePath;
        bool dumpbinFound = false;
        std::string subsystemLine;
        int waitImportHits = 0;
        int networkImportHits = 0;
        int responseSymbolHits = 0;
        std::string verdict = "REVIEW";
    };

    // Global state instance
    static IdeResponseHangAuthorityState g_hangState;

    // Analyze IDE binary for hang causes
    //
    // RAWRXD_UNSIMULATE_001
    //
    // This previously reported, from constants:
    //
    //     dumpbinFound        = true;  // "(simplified - would need actual dumpbin execution)"
    //     waitImportHits      = 3;     // "Example count"
    //     networkImportHits   = 2;     // "Example count"
    //     responseSymbolHits  = 5;     // "Example count"
    //     subsystemLine       = "CONSOLE";  // "Example"
    //     -> verdict = LOW_RISK
    //
    // The counts were invented, then a risk verdict was computed from the
    // invented counts, and the invented numbers (3 and 2) happened to fall
    // below the thresholds that would have flagged HANG_RISK. The authority
    // reported LOW_RISK about a binary it never opened.
    //
    // dumpbin is not invoked here. Rather than substitute a different guess,
    // the analysis reports that it did not run.
    void analyzeIdeForHang(const std::string& exePath)
    {
        g_hangState.entered = true;
        g_hangState.exePath = exePath;

        // The one fact that is real: does the path the caller gave exist?
        g_hangState.dumpbinFound = false;

        // Not measured. Declared non-results rather than zeros, so a later
        // reader cannot mistake "we did not look" for "we looked and found
        // none".
        g_hangState.waitImportHits = -1;
        g_hangState.networkImportHits = -1;
        g_hangState.responseSymbolHits = -1;
        g_hangState.subsystemLine = "NOT_ANALYSED";
        g_hangState.verdict = "INVALID";

        std::cout << "[IdeResponseHangAuthority] IDE hang analysis NOT performed:" << std::endl;
        std::cout << "  EXE=" << g_hangState.exePath << std::endl;
        std::cout << "  EXE_EXISTS=" << (std::filesystem::exists(exePath) ? "true" : "false") << std::endl;
        std::cout << "  DUMPBIN_FOUND=false" << std::endl;
        std::cout << "  SUBSYSTEM_LINE=NOT_ANALYSED" << std::endl;
        std::cout << "  WAIT_IMPORT_HITS=NOT_MEASURED" << std::endl;
        std::cout << "  NETWORK_IMPORT_HITS=NOT_MEASURED" << std::endl;
        std::cout << "  RESPONSE_SYMBOL_HITS=NOT_MEASURED" << std::endl;
        std::cout << "  VERDICT=INVALID" << std::endl;
        std::cout << "  REASON=no binary was inspected; dumpbin was not invoked. "
                     "A hang verdict computed from invented counts is not a "
                     "measurement." << std::endl;
    }

    // Write IDE response hang analysis receipt
    void writeIdeResponseHangReceipt()
    {
        std::cout << "[IdeResponseHangAuthority] Writing IDE response hang analysis receipt:" << std::endl;
        std::cout << "  RAWRXD_IDE_RESPONSE_HANG_DUMPBIN_001=ENTERED" << std::endl;
        std::cout << "  EXE=" << g_hangState.exePath << std::endl;
        std::cout << "  DUMPBIN_FOUND=" << (g_hangState.dumpbinFound ? "1" : "0") << std::endl;
        std::cout << "  SUBSYSTEM_LINE=" << g_hangState.subsystemLine << std::endl;
        std::cout << "  WAIT_IMPORT_HITS=" << g_hangState.waitImportHits << std::endl;
        std::cout << "  NETWORK_IMPORT_HITS=" << g_hangState.networkImportHits << std::endl;
        std::cout << "  RESPONSE_SYMBOL_HITS=" << g_hangState.responseSymbolHits << std::endl;
        std::cout << "  VERDICT=" << g_hangState.verdict << std::endl;
    }
}