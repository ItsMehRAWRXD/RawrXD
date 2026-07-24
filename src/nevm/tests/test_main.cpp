//============================================================================
// test_main.cpp
// RawrXD N-EVM - Test Suite Main Entry Point
//============================================================================

#include "test_framework.hpp"
#include <iostream>

// Include all test suites
#include "test_math_mode.hpp"
#include "test_determinism.hpp"
#include "test_kv_integrity.hpp"
#include "test_execution_plan.hpp"
#include "test_performance_thresholds.hpp"
#include "test_golden_output.hpp"
#include "test_parallel_executor.hpp"
#include "test_replay_harness.hpp"
#include "test_integration.hpp"

using namespace RawrXD::NEVM::Tests;

int main(int argc, char* argv[]) {
    TestFramework framework;
    
    // Parse command line
    bool verbose = false;
    std::string filter;
    std::string output_path;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-v" || arg == "--verbose") {
            verbose = true;
        } else if (arg == "-f" || arg == "--filter") {
            if (i + 1 < argc) filter = argv[++i];
        } else if (arg == "-o" || arg == "--output") {
            if (i + 1 < argc) output_path = argv[++i];
        } else if (arg == "-h" || arg == "--help") {
            std::cout << "Usage: " << argv[0] << " [options]\n\n";
            std::cout << "Options:\n";
            std::cout << "  -v, --verbose       Verbose output\n";
            std::cout << "  -f, --filter <pattern>  Run only tests matching pattern\n";
            std::cout << "  -o, --output <file>     Export JSON report\n";
            std::cout << "  -h, --help          Show this help\n";
            return 0;
        }
    }
    
    framework.SetVerbose(verbose);
    framework.SetFilter(filter);
    
    // Register all test suites
    std::cout << "RawrXD N-EVM Test Suite\n";
    std::cout << "======================\n\n";
    
    RegisterMathModeTests(framework);
    RegisterDeterminismTests(framework);
    RegisterKVIntegrityTests(framework);
    RegisterExecutionPlanTests(framework);
    RegisterPerformanceThresholdTests(framework);
    RegisterGoldenOutputTests(framework);
    RegisterParallelExecutorTests(framework);
    RegisterReplayHarnessTests(framework);
    RegisterIntegrationTests(framework);
    
    // Run tests
    auto results = framework.RunAll();
    
    // Print summary
    std::cout << "\n======================\n";
    std::cout << "Test Summary\n";
    std::cout << "======================\n";
    std::cout << "Total:  " << results.total_tests << "\n";
    std::cout << "Passed:  " << results.passed << "\n";
    std::cout << "Failed:  " << results.failed << "\n";
    std::cout << "Skipped: " << results.skipped << "\n";
    std::cout << "Time:    " << std::fixed << std::setprecision(2) << results.duration_ms << " ms\n";
    
    if (!output_path.empty()) {
        framework.ExportJSONReport(output_path, results);
        std::cout << "\nReport exported to: " << output_path << "\n";
    }
    
    return results.failed > 0 ? 1 : 0;
}
