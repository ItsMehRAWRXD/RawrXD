#include "E2ETestOrchestrator.h"
#include <iostream>
#include <chrono>
#include <iomanip>

namespace RawrXD::E2E {

// Singleton implementation
E2ETestOrchestrator& E2ETestOrchestrator::instance() {
    static E2ETestOrchestrator inst;
    return inst;
}

void E2ETestOrchestrator::RegisterTest(std::unique_ptr<ITestCase> test) {
    if (test) {
        m_test_suite.push_back(std::move(test));
    }
}

bool E2ETestOrchestrator::RunCrucible() {
    std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║           PHASE 19: THE CRUCIBLE - E2E TEST SUITE            ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n\n";
    
    if (m_test_suite.empty()) {
        std::cout << "[CRUCIBLE] No tests registered. Exiting.\n";
        return false;
    }
    
    size_t passed = 0;
    size_t failed = 0;
    auto start_time = std::chrono::high_resolution_clock::now();
    
    std::cout << "[CRUCIBLE] Executing " << m_test_suite.size() << " test(s)...\n\n";
    
    for (size_t i = 0; i < m_test_suite.size(); ++i) {
        const auto& test = m_test_suite[i];
        std::cout << "[Test " << (i + 1) << "/" << m_test_suite.size() << "] " 
                  << test->GetName() << "... ";
        
        auto test_start = std::chrono::high_resolution_clock::now();
        bool result = test->Run();
        auto test_end = std::chrono::high_resolution_clock::now();
        
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(test_end - test_start);
        
        if (result) {
            std::cout << "✓ PASSED (" << duration.count() << "ms)\n";
            passed++;
        } else {
            std::cout << "✗ FAILED (" << duration.count() << "ms)\n";
            std::cout << "  Error: " << test->GetLastError() << "\n";
            failed++;
        }
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto total_duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    std::cout << "\n╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                      CRUCIBLE RESULTS                        ║\n";
    std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Total Tests:  " << std::setw(3) << m_test_suite.size() << "                                      ║\n";
    std::cout << "║  Passed:       " << std::setw(3) << passed << " ✓" << std::string(37, ' ') << "║\n";
    std::cout << "║  Failed:       " << std::setw(3) << failed << " ✗" << std::string(37, ' ') << "║\n";
    std::cout << "║  Duration:     " << std::setw(6) << total_duration.count() << " ms" << std::string(32, ' ') << "║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
    
    return failed == 0;
}

} // namespace RawrXD::E2E
