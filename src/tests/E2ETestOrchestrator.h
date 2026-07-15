#pragma once

#include "E2ETestCase.h"
#include <vector>
#include <memory>

namespace RawrXD::E2E {

/**
 * @brief Master controller for E2E test suite
 * 
 * Phase 19: The Crucible - Executes all registered tests and aggregates results
 */
class E2ETestOrchestrator {
public:
    /**
     * @brief Get singleton instance
     */
    static E2ETestOrchestrator& instance();
    
    /**
     * @brief Register a test to be executed
     * @param test Test case to register
     */
    void RegisterTest(std::unique_ptr<ITestCase> test);
    
    /**
     * @brief Execute all registered tests
     * @return true if all tests passed
     */
    bool RunCrucible();
    
    /**
     * @brief Get number of registered tests
     */
    size_t GetTestCount() const { return m_test_suite.size(); }

private:
    E2ETestOrchestrator() = default;
    ~E2ETestOrchestrator() = default;
    
    std::vector<std::unique_ptr<ITestCase>> m_test_suite;
};

} // namespace RawrXD::E2E
