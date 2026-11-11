/**
 * RawrXD Phase 7A: 24-Hour Soak Test Entry Point
 * 
 * Usage: soak_test.exe [options]
 *   -d, --duration-hours <hours>    Test duration (default: 24)
 *   -w, --warmup-minutes <mins>       Warmup period (default: 5)
 *   -m, --model <path>                Model to test
 *   -o, --output <dir>                Output directory (default: soak_reports)
 *   -f, --fault-injection             Enable fault injection
 *   -h, --help                        Show help
 */

#include "soak_test_harness.hpp"
#include <iostream>
#include <string>
#include <windows.h>

using namespace RawrXD::SoakTest;

void PrintBanner() {
    std::cout << R"(
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║   RawrXD Phase 7A: 24-Hour Soak Test                          ║
    ║   Sovereign Inference Runtime - Production Validation           ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    )" << std::endl;
}

void PrintHelp(const char* program) {
    std::cout << "Usage: " << program << " [options]\n\n";
    std::cout << "Options:\n";
    std::cout << "  -d, --duration-hours <hours>    Test duration in hours (default: 24)\n";
    std::cout << "  -w, --warmup-minutes <mins>     Warmup period in minutes (default: 5)\n";
    std::cout << "  -m, --model <path>             Path to GGUF model to test\n";
    std::cout << "  -o, --output <dir>             Output directory (default: soak_reports)\n";
    std::cout << "  -f, --fault-injection           Enable fault injection testing\n";
    std::cout << "  -h, --help                      Show this help message\n";
}

int main(int argc, char* argv[]) {
    PrintBanner();
    
    SoakConfig config;
    
    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            PrintHelp(argv[0]);
            return 0;
        }
        else if ((strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--duration-hours") == 0) && i + 1 < argc) {
            config.durationHours = std::atoi(argv[++i]);
        }
        else if ((strcmp(argv[i], "-w") == 0 || strcmp(argv[i], "--warmup-minutes") == 0) && i + 1 < argc) {
            config.warmupMinutes = std::atoi(argv[++i]);
        }
        else if ((strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--model") == 0) && i + 1 < argc) {
            config.modelPath = argv[++i];
        }
        else if ((strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) && i + 1 < argc) {
            config.outputDir = argv[++i];
        }
        else if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--fault-injection") == 0) {
            config.enableFaultInjection = true;
        }
    }
    
    // Validate configuration
    if (config.durationHours == 0) {
        std::cerr << "Error: Duration must be greater than 0\n";
        return 1;
    }
    
    // Set console output mode for Unicode
    SetConsoleOutputCP(CP_UTF8);
    
    std::cout << "\nConfiguration:\n";
    std::cout << "  Duration: " << config.durationHours << " hours\n";
    std::cout << "  Warmup: " << config.warmupMinutes << " minutes\n";
    std::cout << "  Model: " << (config.modelPath.empty() ? "(simulated)" : config.modelPath) << "\n";
    std::cout << "  Output: " << config.outputDir << "\n";
    std::cout << "  Fault Injection: " << (config.enableFaultInjection ? "enabled" : "disabled") << "\n\n";
    
    // Create and run harness
    SoakTestHarness harness(config);
    
    std::cout << "Initializing soak test harness...\n";
    if (!harness.Initialize()) {
        std::cerr << "Failed to initialize harness\n";
        return 1;
    }
    
    std::cout << "\nStarting soak test. Press Ctrl+C to abort.\n\n";
    
    bool passed = harness.Run();
    
    auto results = harness.GetResults();
    
    std::cout << "\n";
    std::cout << "═══════════════════════════════════════════════════════════════\n";
    std::cout << "                    TEST RESULTS\n";
    std::cout << "═══════════════════════════════════════════════════════════════\n\n";
    
    std::cout << "Status: " << (passed ? "✅ PASSED" : "❌ FAILED") << "\n\n";
    
    std::cout << "Duration: " << (results.duration.count() / 3600) << "h "
              << ((results.duration.count() % 3600) / 60) << "m\n";
    std::cout << "Total Tokens: " << results.totalTokensGenerated << "\n";
    std::cout << "Average TPS: " << results.avgTPS << "\n";
    std::cout << "Peak Heap: " << (results.peakHeapBytes / (1024*1024)) << " MB\n";
    std::cout << "Peak VRAM: " << (results.peakVRAMBytes / (1024*1024*1024)) << " GB\n";
    
    if (results.faultCount > 0) {
        std::cout << "Faults Injected: " << results.faultCount << "\n";
        std::cout << "Recoveries: " << results.recoveryCount << "\n";
    }
    
    if (!results.failureReasons.empty()) {
        std::cout << "\nFailures:\n";
        for (const auto& reason : results.failureReasons) {
            std::cout << "  ❌ " << reason << "\n";
        }
    }
    
    std::cout << "\n═══════════════════════════════════════════════════════════════\n";
    std::cout << "Reports saved to: " << config.outputDir << "\n";
    std::cout << "═══════════════════════════════════════════════════════════════\n";
    
    return passed ? 0 : 1;
}
