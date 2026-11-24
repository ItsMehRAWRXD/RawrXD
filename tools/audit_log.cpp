// =============================================================================
// audit_log.cpp CLI — S7: append/verify a tamper-evident audit log.
// usage: audit_log <logfile> append <actor> <action> <detail>
//        audit_log <logfile> verify
// =============================================================================
#include <cstdio>
#include <string>

#include "security/audit_log.h"

int main(int argc, char** argv) {
    if (argc < 3) {
        std::fprintf(stderr,
                     "usage: audit_log <logfile> append <actor> <action> "
                     "<detail> | verify\n");
        return 2;
    }
    rawrxd::security::AuditLog log(argv[1]);
    const std::string cmd = argv[2];
    if (cmd == "append" && argc >= 6) {
        if (!log.Append(argv[3], argv[4], argv[5])) {
            std::fprintf(stderr, "append refused (broken chain or IO)\n");
            return 1;
        }
        std::printf("appended (size=%zu)\n", log.Size());
        return 0;
    }
    if (cmd == "verify") {
        std::string err;
        if (log.Verify(&err)) {
            std::printf("chain OK (size=%zu)\n", log.Size());
            return 0;
        }
        std::fprintf(stderr, "chain BROKEN: %s\n", err.c_str());
        return 1;
    }
    return 2;
}