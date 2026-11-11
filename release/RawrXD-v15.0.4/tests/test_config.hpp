// RawrXD Test Configuration and Utilities
// Phase AF: Testing Infrastructure

#pragma once

#include <gtest/gtest.h>
#include <string>
#include <filesystem>
#include <memory>

namespace rawrxd {
namespace test {

// Test configuration constants
constexpr const char* TEST_DATA_ENV_VAR = "RAWRXD_TEST_DATA_DIR";
constexpr const char* TEST_MODELS_ENV_VAR = "RAWRXD_TEST_MODELS_DIR";
constexpr const char* DEFAULT_TEST_DATA_DIR = "tests/data";
constexpr const char* DEFAULT_TEST_MODELS_DIR = "tests/models";

// Test timeouts (milliseconds)
constexpr int SHORT_TIMEOUT = 5000;
constexpr int MEDIUM_TIMEOUT = 30000;
constexpr int LONG_TIMEOUT = 120000;

// Test precision for floating point comparisons
constexpr double FLOAT_EPSILON = 1e-6;
constexpr double DOUBLE_EPSILON = 1e-10;

/**
 * Get test data directory
 */
inline std::string getTestDataDir() {
    const char* env = std::getenv(TEST_DATA_ENV_VAR);
    if (env) return env;
    return DEFAULT_TEST_DATA_DIR;
}

/**
 * Get test models directory
 */
inline std::string getTestModelsDir() {
    const char* env = std::getenv(TEST_MODELS_ENV_VAR);
    if (env) return env;
    return DEFAULT_TEST_MODELS_DIR;
}

/**
 * Get full path to test data file
 */
inline std::string getTestDataPath(const std::string& filename) {
    return (std::filesystem::path(getTestDataDir()) / filename).string();
}

/**
 * Get full path to test model file
 */
inline std::string getTestModelPath(const std::string& filename) {
    return (std::filesystem::path(getTestModelsDir()) / filename).string();
}

/**
 * Check if running in CI environment
 */
inline bool isCIEnvironment() {
    return std::getenv("CI") != nullptr;
}

/**
 * Test environment management
 */
class TestEnvironment {
public:
    static void initialize();
    static void cleanup();
    
    static bool isInitialized() { return initialized_; }
    
private:
    static bool initialized_;
};

// Custom matchers and assertions

/**
 * Assert that two floating point values are equal within epsilon
 */
#define EXPECT_FLOAT_EQ_EPS(val1, val2, eps) \
    EXPECT_NEAR(val1, val2, eps)

#define ASSERT_FLOAT_EQ_EPS(val1, val2, eps) \
    ASSERT_NEAR(val1, val2, eps)

/**
 * Skip test if condition is true
 */
#define SKIP_IF(condition) \
    if (condition) { \
        GTEST_SKIP() << "Skipped: " << #condition; \
    }

/**
 * Skip test in CI environment
 */
#define SKIP_IN_CI() \
    SKIP_IF(rawrxd::test::isCIEnvironment())

/**
 * Skip test if file doesn't exist
 */
#define SKIP_IF_FILE_MISSING(filepath) \
    if (!std::filesystem::exists(filepath)) { \
        GTEST_SKIP() << "Skipped: File not found: " << filepath; \
    }

} // namespace test
} // namespace rawrxd
