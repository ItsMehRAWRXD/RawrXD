#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <functional>
#include <sstream>

namespace RawrXD {
namespace Test {

// ============================================================================
// Test Result
// ============================================================================
struct TestResult {
    bool passed = false;
    std::string name;
    std::string error_message;
    uint64_t duration_us = 0;
    
    // Detailed metrics
    struct Metrics {
        size_t memory_allocated = 0;
        size_t memory_freed = 0;
        uint64_t training_time_us = 0;
        uint64_t serialization_time_us = 0;
        uint64_t inference_time_us = 0;
        float max_weight_value = 0.0f;
        float min_weight_value = 0.0f;
        bool alignment_check_passed = false;
        bool nan_check_passed = false;
    } metrics;
    
    std::string to_string() const;
};

// ============================================================================
// Test Assertion Macros
// ============================================================================
#define E2E_ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            return TestResult{false, __func__, message}; \
        } \
    } while(0)

#define E2E_ASSERT_ALIGNED(ptr, alignment) \
    do { \
        if (reinterpret_cast<uintptr_t>(ptr) % alignment != 0) { \
            std::ostringstream oss; \
            oss << "Pointer " << #ptr << " not aligned to " << alignment; \
            return TestResult{false, __func__, oss.str()}; \
        } \
    } while(0)

#define E2E_ASSERT_NO_NAN_INF(values, count) \
    do { \
        for (size_t _i = 0; _i < count; ++_i) { \
            if (std::isnan(values[_i]) || std::isinf(values[_i])) { \
                std::ostringstream oss; \
                oss << "NaN or Inf detected at index " << _i; \
                return TestResult{false, __func__, oss.str()}; \
            } \
        } \
    } while(0)

#define E2E_ASSERT_NEAR(actual, expected, tolerance) \
    do { \
        float diff = std::abs(actual - expected); \
        if (diff > tolerance) { \
            std::ostringstream oss; \
            oss << "Expected " << expected << " but got " << actual \
               << " (diff=" << diff << ", tolerance=" << tolerance << ")"; \
            return TestResult{false, __func__, oss.str()}; \
        } \
    } while(0)

// ============================================================================
// E2E Test Suite
// ============================================================================
class E2ETestSuite {
public:
    static E2ETestSuite& instance();
    
    // Test registration
    using TestFunction = std::function<TestResult()>;
    void register_test(const std::string& name, TestFunction func);
    
    // Test execution
    struct RunConfig {
        bool stop_on_failure = false;
        bool verbose = true;
        int repeat_count = 1;
        uint64_t timeout_ms = 60000;  // 60 second timeout per test
    };
    
    std::vector<TestResult> run_all(const RunConfig& config = RunConfig{});
    std::optional<TestResult> run_single(const std::string& name, 
                                             const RunConfig& config = RunConfig{});
    
    // Results
    void print_results(const std::vector<TestResult>& results) const;
    bool all_passed(const std::vector<TestResult>& results) const;
    
    // Utilities
    static std::vector<float> generate_random_input(size_t dim, uint32_t seed = 42);
    static std::vector<float> generate_random_target(size_t dim, uint32_t seed = 43);
    static bool compare_vectors(const std::vector<float>& a, 
                                const std::vector<float>& b, 
                                float tolerance = 1e-4f);

private:
    E2ETestSuite() = default;
    std::vector<std::pair<std::string, TestFunction>> m_tests;
    mutable std::mutex m_mutex;
};

// ============================================================================
// Auto-registration helper
// ============================================================================
struct AutoRegisterTest {
    AutoRegisterTest(const std::string& name, E2ETestSuite::TestFunction func);
};

#define E2E_TEST(name) \
    static TestResult _e2e_test_##name(); \
    static AutoRegisterTest _e2e_auto_##name(#name, _e2e_test_##name); \
    static TestResult _e2e_test_##name()

// ============================================================================
// Memory Tracking
// ============================================================================
class MemoryTracker {
public:
    static MemoryTracker& instance();
    
    void* allocate(size_t size, size_t alignment = 32);
    void deallocate(void* ptr);
    
    size_t get_allocated_bytes() const { return m_allocated.load(); }
    size_t get_allocation_count() const { return m_allocation_count.load(); }
    bool has_leaks() const { return m_allocated.load() > 0; }
    
    void reset();
    std::vector<std::pair<void*, size_t>> get_active_allocations() const;

private:
    MemoryTracker() = default;
    std::unordered_map<void*, size_t> m_allocations;
    std::atomic<size_t> m_allocated{0};
    std::atomic<size_t> m_allocation_count{0};
    mutable std::mutex m_mutex;
};

// ============================================================================
// Timing Utilities
// ============================================================================
class Timer {
public:
    void start();
    void stop();
    uint64_t elapsed_us() const;
    uint64_t elapsed_ms() const;
    
private:
    std::chrono::high_resolution_clock::time_point m_start;
    std::chrono::high_resolution_clock::time_point m_end;
    bool m_running = false;
};

// ============================================================================
// Mock Data Generators
// ============================================================================
struct MockFeedbackData {
    std::vector<float> input_embedding;
    std::vector<float> target_embedding;
    float reward = 1.0f;
    std::string context_hash;
};

std::vector<MockFeedbackData> generate_mock_feedback_batch(
    size_t count,
    size_t embedding_dim = 768,
    float positive_ratio = 0.5f
);

// ============================================================================
// Math Verification
// ============================================================================
std::vector<float> compute_expected_lora_output(
    const std::vector<float>& base_output,
    const std::vector<float>& input,
    const std::vector<float>& A,
    const std::vector<float>& B,
    uint32_t rank,
    float scale = 1.0f
);

std::vector<float> compute_expected_chain_output(
    const std::vector<float>& base_output,
    const std::vector<float>& input,
    const std::vector<std::tuple<std::vector<float>, std::vector<float>, float>>& adapters
);

} // namespace Test
} // namespace RawrXD
