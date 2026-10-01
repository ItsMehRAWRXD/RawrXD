#include "cfix/config_loader.h"

#include <cstdio>
#include <string>

namespace {

int g_failures = 0;
int g_checks = 0;

void check(bool condition, const char* label) {
    ++g_checks;
    if (!condition) {
        ++g_failures;
        std::printf("FAIL: %s\n", label);
    } else {
        std::printf("ok:   %s\n", label);
    }
}

bool throws_invalid_argument(const std::string& text) {
    try {
        cfix::load_config(text);
    } catch (const std::invalid_argument&) {
        return true;
    } catch (...) {
        return false;
    }
    return false;
}

}  // namespace

int main() {
    // Baseline: a well-formed configuration must still parse.
    {
        const cfix::Config cfg = cfix::load_config("host=example.com\nport=443\nverbose=true\n");
        check(cfg.host == "example.com", "valid config: host parsed");
        check(cfg.port == 443, "valid config: port parsed");
        check(cfg.verbose == true, "valid config: verbose parsed");
    }

    // Validation contract, per include/cfix/config_loader.h.
    check(throws_invalid_argument("host=\nport=8080\n"), "empty host rejected");
    check(throws_invalid_argument("host=example.com\nport=0\n"), "port 0 rejected");
    check(throws_invalid_argument("host=example.com\nport=65536\n"), "port above 65535 rejected");
    check(throws_invalid_argument("host=example.com\nport=-1\n"), "negative port rejected");
    check(throws_invalid_argument("host=example.com\nport=notanumber\n"), "non-numeric port rejected");
    check(throws_invalid_argument("port=8080\n"), "missing host rejected");

    // Boundary values that must remain valid.
    {
        bool ok_low = false;
        try {
            cfix::load_config("host=a\nport=1\n");
            ok_low = true;
        } catch (...) {
        }
        check(ok_low, "port 1 accepted");

        bool ok_high = false;
        try {
            cfix::load_config("host=a\nport=65535\n");
            ok_high = true;
        } catch (...) {
        }
        check(ok_high, "port 65535 accepted");
    }

    std::printf("\nCHECKS=%d FAILURES=%d\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
