// ============================================================================
// TestFramework.cpp - Testing Framework Implementation
// ============================================================================

#include "TestFramework.hpp"
#include <fstream>
#include <sstream>
#include <random>
#include <algorithm>
#include <iostream>

namespace Sovereign {

// ============================================================
// UnitTestFramework
// ============================================================

UnitTestFramework::UnitTestFramework() = default;
UnitTestFramework::~UnitTestFramework() = default;

void UnitTestFramework::Register(const std::string& suite, const std::string& name, std::function<bool()> test) {
    std::lock_guard<std::mutex> lock(mutex_);
    suites_[suite].push_back({name, test});
    stats_.totalTests++;
}

TestSuite UnitTestFramework::Run(const std::string& suite) {
    TestSuite result;
    result.name = suite;
    auto start = std::chrono::high_resolution_clock::now();
    
    auto it = suites_.find(suite);
    if (it == suites_.end()) return result;
    
    for (const auto& test : it->second) {
        TestResult tr;
        tr.name = test.name;
        auto tStart = std::chrono::high_resolution_clock::now();
        
        try {
            tr.passed = test.func();
        } catch (const std::exception& e) {
            tr.passed = false;
            tr.error = e.what();
        } catch (...) {
            tr.passed = false;
            tr.error = "Unknown exception";
        }
        
        tr.durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::high_resolution_clock::now() - tStart).count();
        
        result.results.push_back(tr);
        if (tr.passed) { result.passed++; stats_.passed++; }
        else { result.failed++; stats_.failed++; }
        
        if (outputCallback_) {
            outputCallback_((tr.passed ? "[PASS] " : "[FAIL] ") + tr.name + " (" + std::to_string(tr.durationMs) + "ms)");
        }
    }
    
    result.total = result.results.size();
    result.totalDurationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::high_resolution_clock::now() - start).count();
    stats_.totalSuites++;
    
    return result;
}

std::vector<TestSuite> UnitTestFramework::RunAll() {
    std::vector<TestSuite> results;
    for (const auto& [name, _] : suites_) {
        results.push_back(Run(name));
    }
    return results;
}

// ============================================================
// FuzzingEngine
// ============================================================

FuzzingEngine::FuzzingEngine() = default;
FuzzingEngine::~FuzzingEngine() { Shutdown(); }

bool FuzzingEngine::Initialize(uint64_t seed) {
    seed_ = seed == 0 ? std::random_device{}() : seed;
    return true;
}

void FuzzingEngine::Shutdown() { Stop(); }

void FuzzingEngine::SetTarget(std::function<bool(const std::vector<uint8_t>&)> target) {
    target_ = target;
}

void FuzzingEngine::AddMutator(std::function<std::vector<uint8_t>(const std::vector<uint8_t>&)> mutator) {
    mutators_.push_back(mutator);
}

uint64_t FuzzingEngine::Fuzz(size_t iterations, size_t maxInputSize) {
    running_ = true;
    std::mt19937 rng(seed_);
    std::uniform_int_distribution<uint8_t> byteDist(0, 255);
    
    for (size_t i = 0; i < iterations && running_; ++i) {
        std::vector<uint8_t> input(maxInputSize);
        for (auto& b : input) b = byteDist(rng);
        
        // Apply mutators
        for (const auto& mutator : mutators_) {
            input = mutator(input);
        }
        
        if (target_) {
            try {
                target_(input);
                stats_.uniquePaths++;
            } catch (...) {
                stats_.crashes++;
            }
        }
        
        stats_.totalIterations++;
    }
    
    running_ = false;
    return stats_.totalIterations;
}

void FuzzingEngine::Stop() { running_ = false; }

// ============================================================
// PropertyBasedTest
// ============================================================

PropertyBasedTest::PropertyBasedTest() = default;
PropertyBasedTest::~PropertyBasedTest() = default;

void PropertyBasedTest::Register(const std::string& name, std::function<bool()> property, size_t iterations) {
    properties_.push_back({name, property, iterations});
    stats_.totalProperties++;
}

std::vector<TestResult> PropertyBasedTest::RunAll() {
    std::vector<TestResult> results;
    for (const auto& prop : properties_) {
        auto r = Run(prop.name);
        results.insert(results.end(), r.begin(), r.end());
    }
    return results;
}

std::vector<TestResult> PropertyBasedTest::Run(const std::string& name) {
    std::vector<TestResult> results;
    for (const auto& prop : properties_) {
        if (prop.name != name) continue;
        
        for (size_t i = 0; i < prop.iterations; ++i) {
            TestResult tr;
            tr.name = prop.name + " [" + std::to_string(i) + "]";
            tr.passed = prop.func();
            if (!tr.passed) {
                tr.error = "Property failed after " + std::to_string(i) + " iterations";
                stats_.failures++;
            }
            results.push_back(tr);
            stats_.totalIterations++;
        }
    }
    return results;
}

// ============================================================
// GoldenFileTest
// ============================================================

GoldenFileTest::GoldenFileTest() = default;
GoldenFileTest::~GoldenFileTest() = default;

bool GoldenFileTest::SetGolden(const std::string& testName, const std::string& goldenPath) {
    std::lock_guard<std::mutex> lock(mutex_);
    goldenFiles_[testName] = goldenPath;
    stats_.totalTests++;
    return true;
}

bool GoldenFileTest::Compare(const std::string& testName, const std::string& actualContent) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = goldenFiles_.find(testName);
    if (it == goldenFiles_.end()) return false;
    
    std::ifstream file(it->second);
    if (!file) return false;
    
    std::string golden((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    
    if (actualContent == golden) {
        stats_.matches++;
        return true;
    }
    stats_.mismatches++;
    return false;
}

bool GoldenFileTest::UpdateGolden(const std::string& testName, const std::string& newContent) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = goldenFiles_.find(testName);
    if (it == goldenFiles_.end()) return false;
    
    std::ofstream file(it->second);
    if (!file) return false;
    file << newContent;
    stats_.updates++;
    return true;
}

// ============================================================
// DeterministicReplay
// ============================================================

DeterministicReplay::DeterministicReplay() = default;
DeterministicReplay::~DeterministicReplay() = default;

bool DeterministicReplay::Record(const std::string& sessionName) {
    events_.clear();
    recording_ = true;
    return true;
}

bool DeterministicReplay::Replay(const std::string& sessionName) {
    replayIndex_ = 0;
    replaying_ = true;
    return true;
}

bool DeterministicReplay::Stop() {
    recording_ = false;
    replaying_ = false;
    return true;
}

void DeterministicReplay::LogEvent(const std::string& event, const std::vector<uint8_t>& data) {
    if (!recording_) return;
    std::lock_guard<std::mutex> lock(mutex_);
    events_.push_back({event, data});
    stats_.totalEvents++;
}

} // namespace Sovereign
