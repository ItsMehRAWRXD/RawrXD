#pragma once

#include <string>
#include <chrono>

namespace RawrXD::E2E {

/**
 * @brief Base interface for E2E test cases
 */
class ITestCase {
public:
    virtual ~ITestCase() = default;
    
    /**
     * @brief Get test name
     */
    virtual std::string GetName() const = 0;
    
    /**
     * @brief Run the test
     * @return true if test passed
     */
    virtual bool Run() = 0;
    
    /**
     * @brief Get last error message
     */
    virtual std::string GetLastError() const = 0;
    
    /**
     * @brief Get test duration
     */
    virtual std::chrono::milliseconds GetDuration() const = 0;
};

} // namespace RawrXD::E2E
