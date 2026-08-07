// ============================================================================
// certification_runner.cpp — Standalone Certification Test Runner
// Builds and runs VAL-064 through VAL-067 certification tests
// ============================================================================
#include "../certification/CertificationTestSuite.hpp"
#include <iostream>
#include <iomanip>
#include <filesystem>

using namespace RawrXD::Certification;

void PrintReport(const CertificationReport& report) {
    std::cout << "\n========================================\n";
    std::cout << "  Certification: " << report.suite << "\n";
    std::cout << "  Timestamp: " << report.timestamp << "\n";
    std::cout << "  Results: " << report.passedTests << "/" << report.totalTests << " passed";
    if (report.failedTests > 0) {
        std::cout << " (" << report.failedTests << " failed)";
    }
    std::cout << "\n";
    std::cout << "  Duration: " << std::fixed << std::setprecision(2) 
              << report.totalDurationMs << " ms\n";
    std::cout << "  Status: " << (report.allPassed() ? "✅ ALL PASSED" : "❌ FAILURES DETECTED") << "\n";
    std::cout << "========================================\n\n";

    for (const auto& r : report.results) {
        std::cout << "  [" << (r.passed ? "PASS" : "FAIL") << "] " 
                  << r.id << " - " << r.name << "\n";
        if (!r.error.empty()) {
            std::cout << "       Error: " << r.error << "\n";
        }
        std::cout << "       Duration: " << std::fixed << std::setprecision(2) 
                  << r.durationMs << " ms\n";
    }
    std::cout << std::endl;
}

int main(int argc, char* argv[]) {
    std::cout << "RawrXD Certification Test Suite v1.0\n";
    std::cout << "====================================\n";

    CertificationTestSuite suite;
    if (!suite.Initialize()) {
        std::cerr << "Failed to initialize test suite\n";
        return 1;
    }

    // Determine which tests to run
    std::string testFilter = (argc > 1) ? argv[1] : "all";

    if (testFilter == "all" || testFilter == "VAL-064") {
        std::cout << "\n>>> Running VAL-064: Codec Layer <<<\n";
        auto report = suite.RunVAL064_CodecLayer();
        PrintReport(report);
    }

    if (testFilter == "all" || testFilter == "VAL-065") {
        std::cout << "\n>>> Running VAL-065: Backend Router <<<\n";
        auto report = suite.RunVAL065_BackendRouter();
        PrintReport(report);
    }

    if (testFilter == "all" || testFilter == "VAL-066") {
        std::cout << "\n>>> Running VAL-066: Agent Communication <<<\n";
        auto report = suite.RunVAL066_AgentCommunication();
        PrintReport(report);
    }

    if (testFilter == "all" || testFilter == "VAL-067") {
        std::cout << "\n>>> Running VAL-067: MultiResponse <<<\n";
        auto report = suite.RunVAL067_MultiResponse();
        PrintReport(report);
    }

    // Export reports
    std::string outputDir = "certification_results";
    if (suite.ExportAllReports(outputDir)) {
        std::cout << "Reports exported to: " << outputDir << "/\n";
    }

    // Run all and get combined result
    auto all = suite.RunAll();
    std::cout << "\n====================================\n";
    std::cout << "  FINAL RESULT: " << all.passedTests << "/" << all.totalTests << " passed\n";
    std::cout << "  OVERALL: " << (all.allPassed() ? "✅ CERTIFICATION PASSED" : "❌ CERTIFICATION FAILED") << "\n";
    std::cout << "====================================\n";

    suite.Shutdown();
    return all.allPassed() ? 0 : 1;
}
