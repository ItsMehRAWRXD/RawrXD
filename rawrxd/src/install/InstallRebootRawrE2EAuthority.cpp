// Install reboot rawr E2E authority implementation
// RawrXD InstallRebootRawrE2EAuthority - Gates install/reboot/rawr end-to-end completion

#include "src/install/InstallRebootRawrE2EAuthority.h"
#include <iostream>
#include <string>
#include <filesystem>

namespace rawrxd::install
{
    // Global install reboot rawr E2E authority state
    struct InstallRebootRawrE2EAuthorityState
    {
        bool entered = false;
        std::string autostartPolicy = "CLI_ONLY_NO_AUTOSTART";
        bool installRawrExists = false;
        std::string installRawrPath = "C:\\Users\\Garrett\\rawrxd\\bin\\rawr.exe";
        bool pathResolvesRawr = false;
        std::string pathResolvesRawrPath;
        std::string modelDir = "RAWRXD_MODEL_DIR";
        bool modelDirExists = false;
        bool freshShellRawRunStarted = false;
        bool freshShellRawRunCompleted = false;
        uint64_t generatedTokenCount = 0;
        int exitCode = 0;
        std::string verdict = "FAIL";
    };

    // Global state instance
    static InstallRebootRawrE2EAuthorityState g_installRebootState;

    // Certify install reboot rawr
    //
    // RAWRXD_UNSIMULATE_001
    //
    // This previously reported, from constants:
    //
    //     pathResolvesRawr         = true;  // "Would need actual PATH verification"
    //     freshShellRawRunStarted  = true;  // "Simulate fresh shell execution"
    //     freshShellRawRunCompleted= true;
    //     generatedTokenCount      = 42;    // "Example token count"
    //     exitCode                 = 0;
    //     -> VERDICT = PASS
    //
    // GENERATED_TOKEN_COUNT is a claim about MODEL OUTPUT. Reporting 42 tokens
    // from a model that was never launched is the single most direct way to
    // assert that a model works without running one, and it did so alongside a
    // PATH resolution that was never performed and a shell that never started.
    //
    // No shell is spawned and no model is launched here. The honest result is
    // INVALID with the reason stated, and the only fields reported are the two
    // that were genuinely measured from the filesystem.
    void certInstallRebootRawr()
    {
        g_installRebootState.entered = true;

        // Measured: the two filesystem facts below are real queries.
        g_installRebootState.installRawrExists =
            std::filesystem::exists(g_installRebootState.installRawrPath);
        g_installRebootState.modelDirExists = std::filesystem::exists("F:\\models");

        // Not measured, and no longer asserted. These stay false so that every
        // field printed below is either a measurement or a declared non-result.
        g_installRebootState.pathResolvesRawr = false;
        g_installRebootState.freshShellRawRunStarted = false;
        g_installRebootState.freshShellRawRunCompleted = false;
        g_installRebootState.generatedTokenCount = -1;  // -1 = not measured
        g_installRebootState.exitCode = -1;             // -1 = not measured
        g_installRebootState.verdict = "INVALID";

        std::cout << "[InstallRebootRawrE2EAuthority] install reboot NOT certified:" << std::endl;
        std::cout << "  AUTOSTART_POLICY=" << g_installRebootState.autostartPolicy << std::endl;
        std::cout << "  INSTALL_RAWR_EXISTS=" << (g_installRebootState.installRawrExists ? "true" : "false") << std::endl;
        std::cout << "  MODEL_DIR_EXISTS=" << (g_installRebootState.modelDirExists ? "true" : "false") << std::endl;
        std::cout << "  PATH_RESOLVES_RAWR=NOT_MEASURED" << std::endl;
        std::cout << "  FRESH_SHELL_RAW_RUN_STARTED=false" << std::endl;
        std::cout << "  FRESH_SHELL_RAW_RUN_COMPLETED=false" << std::endl;
        std::cout << "  GENERATED_TOKEN_COUNT=NOT_MEASURED" << std::endl;
        std::cout << "  EXIT_CODE=NOT_MEASURED" << std::endl;
        std::cout << "  VERDICT=INVALID" << std::endl;
        std::cout << "  REASON=this authority launches no shell and no model; "
                     "it cannot certify end-to-end execution. To certify it, run "
                     "server_generation_parity against a real model and record the "
                     "token ids that come back." << std::endl;
    }

    // Write install reboot rawr E2E receipt
    void writeInstallRebootRawrE2EReceipt()
    {
        std::cout << "[InstallRebootRawrE2EAuthority] Writing install reboot rawr E2E receipt:" << std::endl;
        std::cout << "  RAWRXD_INSTALL_REBOOT_RAWR_E2E_001=ENTERED" << std::endl;
        std::cout << "  AUTOSTART_POLICY=" << g_installRebootState.autostartPolicy << std::endl;
        std::cout << "  INSTALL_RAWR_EXISTS=" << (g_installRebootState.installRawrExists ? "1" : "0") << std::endl;
        std::cout << "  PATH_RESOLVES_RAWR=" << (g_installRebootState.pathResolvesRawr ? "1" : "0") << std::endl;
        std::cout << "  MODEL_DIR_EXISTS=" << (g_installRebootState.modelDirExists ? "1" : "0") << std::endl;
        std::cout << "  FRESH_SHELL_RAW_RUN_STARTED=" << (g_installRebootState.freshShellRawRunStarted ? "1" : "0") << std::endl;
        std::cout << "  FRESH_SHELL_RAW_RUN_COMPLETED=" << (g_installRebootState.freshShellRawRunCompleted ? "1" : "0") << std::endl;
        std::cout << "  GENERATED_TOKEN_COUNT=" << g_installRebootState.generatedTokenCount << std::endl;
        std::cout << "  EXIT_CODE=" << g_installRebootState.exitCode << std::endl;
        std::cout << "  VERDICT=" << g_installRebootState.verdict << std::endl;
    }
}