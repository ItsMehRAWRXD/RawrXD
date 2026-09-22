// ============================================================================
// cert_stub_scan_driver.cpp — RAWR_STUB_SCAN_001 Gate 7 E2E driver.
// Compiles standalone with rawr_stub_scan.cpp; no Vulkan/Deep2 deps.
// ============================================================================
#include <cstdio>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>

#include "rawr_stub_scan.hpp"

using rawrxd::agent::ScanCandidate;
using rawrxd::agent::ScanKind;
using rawrxd::agent::ScanReport;
using rawrxd::agent::scanKindName;
using rawrxd::agent::scanSourceText;

static std::string readFile(const char* path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;

    const char* fixtures[] = {
        "cert_e2e_fixtures/cert_fixture_known_stub.cpp",
        "cert_e2e_fixtures/cert_fixture_fake_impl.cpp",
        "cert_e2e_fixtures/cert_fixture_legitimate.cpp",
        "cert_e2e_fixtures/cert_fixture_unimplemented_handler.cpp",
        nullptr
    };

    ScanReport report{};
    std::vector<ScanCandidate> all;

    for (size_t i = 0; fixtures[i]; ++i) {
        std::string text = readFile(fixtures[i]);
        if (text.empty()) {
            std::fprintf(stderr, "[CERT_GATE7] MISSING_FIXTURE path=%s\n", fixtures[i]);
            ++report.scanFailures;
            continue;
        }
        ++report.filesScanned;
        std::vector<ScanCandidate> local;
        scanSourceText(fixtures[i], text, local);
        for (auto& c : local) all.push_back(std::move(c));
    }

    report.candidates = all.size();
    report.scanComplete = true;

    // Group by fixture for readable receipt.
    std::fprintf(stderr, "RAWR_STUB_SCAN_001_RECEIPT\n");
    std::fprintf(stderr, "FILES_SCANNED=%llu\n", static_cast<unsigned long long>(report.filesScanned));
    std::fprintf(stderr, "SCAN_FAILURES=%llu\n", static_cast<unsigned long long>(report.scanFailures));
    std::fprintf(stderr, "TOTAL_CANDIDATES=%llu\n", static_cast<unsigned long long>(report.candidates));

    for (const auto& c : all) {
        std::fprintf(stderr, "CANDIDATE file=%s line=%u kind=%s snippet=%.200s\n",
                     c.file.c_str(), c.line, scanKindName(c.kind), c.snippet.c_str());
    }

    // Gate 7 PASS criteria:
    // - fixture_known_stub.cpp MUST produce >0 candidates (todo_fixme, stub_comment)
    // - fixture_fake_impl.cpp MUST produce >0 candidates (fake_success)
    // - fixture_legitimate.cpp MUST produce 0 candidates (negative control)
    // - fixture_unimplemented_handler.cpp MUST produce >0 candidates (not_implemented, disabled_path)
    size_t counts[4] = {0,0,0,0};
    for (const auto& c : all) {
        for (size_t i = 0; i < 4; ++i) {
            if (c.file.find(fixtures[i]) != std::string::npos) { ++counts[i]; break; }
        }
    }

    bool pass = true;
    pass = pass && counts[0] > 0;  // known_stub
    pass = pass && counts[1] > 0;  // fake_impl
    pass = pass && counts[2] == 0; // legitimate negative control
    pass = pass && counts[3] > 0;  // unimplemented_handler

    std::fprintf(stderr, "FIXTURE_COUNTS known_stub=%zu fake_impl=%zu legitimate=%zu unimplemented=%zu\n",
                 counts[0], counts[1], counts[2], counts[3]);
    std::fprintf(stderr, "RAWR_STUB_SCAN_001=%s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;
}
