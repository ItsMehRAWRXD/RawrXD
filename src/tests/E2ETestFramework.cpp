#include "E2ETestFramework.h"
#include "../lora/AdapterTrainer.h"
#include "../lora/AdapterSerializer.h"
#include "../lora/BeaconChainManager.h"
#include "../lora/LoRABeaconInterface.h"
#include <iostream>
#include <iomanip>
#include <cmath>
#include <random>
#include <chrono>

namespace RawrXD {
namespace Test {

// ============================================================================
// TestResult Implementation
// ============================================================================

std::string TestResult::to_string() const {
    std::ostringstream oss;
    oss << "[" << (passed ? "PASS" : "FAIL") << "] " << name;
    if (!passed && !error_message.empty()) {
        oss << ": " << error_message;
    }
    oss << " (" << duration_us << " us)";
    return oss.str();
}

// ============================================================================
// E2ETestSuite Implementation
// ============================================================================

E2ETestSuite& E2ETestSuite::instance() {
    static E2ETestSuite instance;
    return instance;
}

void E2ETestSuite::register_test(const std::string& name, TestFunction func) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_tests.push_back({name, func});
}

std::vector<TestResult> E2ETestSuite::run_all(const RunConfig& config) {
    std::vector<TestResult> results;
    
    std::cout << "Running " << m_tests.size() << " E2E tests...\n";
    std::cout << std::string(60, '=') << "\n";
    
    for (const auto& [name, func] : m_tests) {
        if (config.verbose) {
            std::cout << "Running: " << name << " ... " << std::flush;
        }
        
        Timer timer;
        timer.start();
        
        TestResult result;
        try {
            result = func();
            result.name = name;
        } catch (const std::exception& e) {
            result = {false, name, std::string("Exception: ") + e.what()};
        } catch (...) {
            result = {false, name, "Unknown exception"};
        }
        
        timer.stop();
        result.duration_us = timer.elapsed_us();
        
        if (config.verbose) {
            std::cout << (result.passed ? "PASS" : "FAIL") << "\n";
            if (!result.passed && !result.error_message.empty()) {
                std::cout << "  Error: " << result.error_message << "\n";
            }
        }
        
        results.push_back(result);
        
        if (config.stop_on_failure && !result.passed) {
            break;
        }
    }
    
    std::cout << std::string(60, '=') << "\n";
    return results;
}

std::optional<TestResult> E2ETestSuite::run_single(const std::string& name, 
                                                     const RunConfig& config) {
    for (const auto& [test_name, func] : m_tests) {
        if (test_name == name) {
            Timer timer;
            timer.start();
            
            TestResult result;
            try {
                result = func();
                result.name = name;
            } catch (const std::exception& e) {
                result = {false, name, std::string("Exception: ") + e.what()};
            }
            
            timer.stop();
            result.duration_us = timer.elapsed_us();
            return result;
        }
    }
    return std::nullopt;
}

void E2ETestSuite::print_results(const std::vector<TestResult>& results) const {
    size_t passed = 0, failed = 0;
    uint64_t total_time = 0;
    
    std::cout << "\n" << std::string(60, '=') << "\n";
    std::cout << "E2E Test Results Summary\n";
    std::cout << std::string(60, '=') << "\n\n";
    
    for (const auto& result : results) {
        std::cout << result.to_string() << "\n";
        if (result.passed) {
            passed++;
        } else {
            failed++;
        }
        total_time += result.duration_us;
    }
    
    std::cout << "\n" << std::string(60, '-') << "\n";
    std::cout << "Total: " << results.size() << " tests\n";
    std::cout << "Passed: " << passed << "\n";
    std::cout << "Failed: " << failed << "\n";
    std::cout << "Total time: " << total_time / 1000 << " ms\n";
    std::cout << std::string(60, '=') << "\n";
}

bool E2ETestSuite::all_passed(const std::vector<TestResult>& results) const {
    for (const auto& result : results) {
        if (!result.passed) return false;
    }
    return true;
}

std::vector<float> E2ETestSuite::generate_random_input(size_t dim, uint32_t seed) {
    std::mt19937 gen(seed);
    std::normal_distribution<float> dist(0.0f, 1.0f);
    
    std::vector<float> result(dim);
    for (size_t i = 0; i < dim; ++i) {
        result[i] = dist(gen);
    }
    return result;
}

std::vector<float> E2ETestSuite::generate_random_target(size_t dim, uint32_t seed) {
    return generate_random_input(dim, seed);
}

bool E2ETestSuite::compare_vectors(const std::vector<float>& a, 
                                   const std::vector<float>& b, 
                                   float tolerance) {
    if (a.size() != b.size()) return false;
    
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::abs(a[i] - b[i]) > tolerance) {
            return false;
        }
    }
    return true;
}

// ============================================================================
// AutoRegisterTest Implementation
// ============================================================================

AutoRegisterTest::AutoRegisterTest(const std::string& name, E2ETestSuite::TestFunction func) {
    E2ETestSuite::instance().register_test(name, func);
}

// ============================================================================
// MemoryTracker Implementation
// ============================================================================

MemoryTracker& MemoryTracker::instance() {
    static MemoryTracker instance;
    return instance;
}

void* MemoryTracker::allocate(size_t size, size_t alignment) {
    void* ptr = _aligned_malloc(size, alignment);
    if (ptr) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_allocations[ptr] = size;
        m_allocated += size;
        m_allocation_count++;
    }
    return ptr;
}

void MemoryTracker::deallocate(void* ptr) {
    if (!ptr) return;
    
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_allocations.find(ptr);
    if (it != m_allocations.end()) {
        m_allocated -= it->second;
        m_allocations.erase(it);
    }
    _aligned_free(ptr);
}

void MemoryTracker::reset() {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& [ptr, _] : m_allocations) {
        _aligned_free(ptr);
    }
    m_allocations.clear();
    m_allocated = 0;
    m_allocation_count = 0;
}

std::vector<std::pair<void*, size_t>> MemoryTracker::get_active_allocations() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return std::vector<std::pair<void*, size_t>>(m_allocations.begin(), m_allocations.end());
}

// ============================================================================
// Timer Implementation
// ============================================================================

void Timer::start() {
    m_start = std::chrono::high_resolution_clock::now();
    m_running = true;
}

void Timer::stop() {
    m_end = std::chrono::high_resolution_clock::now();
    m_running = false;
}

uint64_t Timer::elapsed_us() const {
    auto end = m_running ? std::chrono::high_resolution_clock::now() : m_end;
    return std::chrono::duration_cast<std::chrono::microseconds>(end - m_start).count();
}

uint64_t Timer::elapsed_ms() const {
    return elapsed_us() / 1000;
}

// ============================================================================
// Mock Data Generators
// ============================================================================

std::vector<MockFeedbackData> generate_mock_feedback_batch(
    size_t count,
    size_t embedding_dim,
    float positive_ratio) {
    
    std::vector<MockFeedbackData> result;
    result.reserve(count);
    
    size_t positive_count = static_cast<size_t>(count * positive_ratio);
    
    for (size_t i = 0; i < count; ++i) {
        MockFeedbackData data;
        data.input_embedding = E2ETestSuite::generate_random_input(embedding_dim, i);
        data.target_embedding = E2ETestSuite::generate_random_target(embedding_dim, i + 1000);
        data.reward = (i < positive_count) ? 1.0f : 0.0f;
        data.context_hash = "mock_context_" + std::to_string(i);
        result.push_back(std::move(data));
    }
    
    return result;
}

// ============================================================================
// Math Verification
// ============================================================================

std::vector<float> compute_expected_lora_output(
    const std::vector<float>& base_output,
    const std::vector<float>& input,
    const std::vector<float>& A,
    const std::vector<float>& B,
    uint32_t rank,
    float scale) {
    
    size_t hidden_dim = input.size();
    std::vector<float> result = base_output;
    
    // Compute temp = A * input (rank x 1)
    std::vector<float> temp(rank, 0.0f);
    for (uint32_t r = 0; r < rank; ++r) {
        float sum = 0.0f;
        for (size_t i = 0; i < hidden_dim; ++i) {
            sum += A[r * hidden_dim + i] * input[i];
        }
        temp[r] = sum;
    }
    
    // Compute delta = B * temp and add to result
    for (size_t o = 0; o < hidden_dim; ++o) {
        float sum = 0.0f;
        for (uint32_t r = 0; r < rank; ++r) {
            sum += B[o * rank + r] * temp[r];
        }
        result[o] += scale * sum;
    }
    
    return result;
}

std::vector<float> compute_expected_chain_output(
    const std::vector<float>& base_output,
    const std::vector<float>& input,
    const std::vector<std::tuple<std::vector<float>, std::vector<float>, float>>& adapters) {
    
    std::vector<float> result = base_output;
    
    for (const auto& [A, B, scale] : adapters) {
        // Infer rank from matrix sizes
        uint32_t rank = static_cast<uint32_t>(B.size() / result.size());
        auto delta = compute_expected_lora_output(base_output, input, A, B, rank, scale);
        // Add delta to result
        for (size_t i = 0; i < result.size(); ++i) {
            result[i] += (delta[i] - base_output[i]);
        }
    }
    
    return result;
}

} // namespace Test
} // namespace RawrXD
