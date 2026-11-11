// The standalone extension runtime certificate.
//
// The certificate logic itself lives in the runtime library, so that the
// production IDE binary runs exactly the same checks.
//
//     rawr-extension-cert <work-dir> [receipt-path]

#include "../../../src/core/runtime_cert.h"

#include <cstdio>
#include <cstring>

int main(int argc, char** argv) {
    const char* workDir = (argc > 1) ? argv[1] : ".";
    const char* receipt = (argc > 2) ? argv[2] : nullptr;

    std::printf("RAWRXD_EXTENSION_RUNTIME_001\n");
    std::printf("===============================\n");

    int rc = RawrXD::Extensions::RunExtensionRuntimeCertificate(workDir, receipt);

    if (receipt) {
        std::printf("receipt: %s\n", receipt);
    }
    return rc;
}
