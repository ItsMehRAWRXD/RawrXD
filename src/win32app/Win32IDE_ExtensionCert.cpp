// ============================================================================
//  The extension runtime certificate, run from the production IDE binary.
//
//  The certificate lives in the shared extension runtime library, so this
//  mode exercises exactly the code the IDE ships rather than a copy of it.
//
//      RawrXD-Win32IDE-Native.exe --extension-cert <work-dir> [receipt-path]
//
//  It runs before any window is created, so it works in a headless
//  environment.
// ============================================================================

#include "Win32IDE_ExtensionCert.h"

#include "../core/runtime_cert.h"

#include <cstdio>
#include <cstring>
#include <string>

namespace {

// Writes a small receipt next to the certificate so that a supervisor can
// tell what the IDE did, even when the run is automated.
void WriteIdeReceipt(const char* path, int result) {
    if (!path || !path[0]) return;
    std::FILE* f = std::fopen(path, "wb");
    if (!f) return;
    std::fprintf(f,
        "{\n"
        "  \"schema\": \"rawrxd.ide.extension.cert/1\",\n"
        "  \"binary\": \"RawrXD-Win32IDE-Native.exe\",\n"
        "  \"result\": \"%s\",\n"
        "  \"exit_code\": %d\n"
        "}\n",
        (result == 0) ? "PASS" : "FAIL", result);
    std::fclose(f);
}

} // namespace

int RunExtensionCertProbe(int argc, char** argv) {
    const char* workDir = (argc > 2) ? argv[2] : ".";
    const char* receipt = (argc > 3) ? argv[3] : nullptr;

    std::printf("RAWRXD_WIN32_EXTENSION_GUI_001\n");
    std::printf("===================================\n");
    std::printf("binary: RawrXD-Win32IDE-Native.exe\n");
    std::printf("work:   %s\n\n", workDir);

    int rc = RawrXD::Extensions::RunExtensionRuntimeCertificate(workDir, receipt);

    if (receipt) {
        std::printf("receipt: %s\n", receipt);
        // The runtime certificate writes the detailed receipt. The IDE
        // summary goes beside it rather than over it.
        std::string ideReceipt = std::string(receipt) + ".ide.json";
        WriteIdeReceipt(ideReceipt.c_str(), rc);
    }
    return rc;
}
