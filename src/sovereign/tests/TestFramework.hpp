// ============================================================================
// TestFramework.hpp - Unit Test, Fuzzing, Property-Based, Golden File, Deterministic Replay
// ============================================================================

#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>
#include <chrono>

namespace Sovereign {

// Test result
struct TestResult {
    std::string name;
    bool passed;
    std::string error;
    uint64_t durationMs;
    std::string file;
    int line;
};

// Test suite
struct TestSuite {
    std::string name;
    std::vector<TestResult> results;
    uint64_t totalDurationMs;
    int passed;
    int failed;
    int total;
};

// Unit test framework
class UnitTestFramework {
public:
    UnitTestFramework();
    ~UnitTestFramework();

    void Register(const std::string& suite, const std::string& name, std::function<bool()> test);
    TestSuite Run(const std::string& suite);
    std::vector<TestSuite> RunAll();
    void SetOutputCallback(std::function<void(const std::string&)> callback);

    struct UTStats { uint64_t totalTests; uint64_t totalSuites; uint64_t passed; uint64_t failed; };
    UTStats GetStats() const { return stats_; }

private:
    struct TestCase { std::string name; std::function<bool()> func; };
    std::unordered_map<std::string, std::vector<TestCase>> suites_;
    UTStats stats_;
    std::function<void(const std::string&)> outputCallback_;
    mutable std::mutex mutex_;
};

// Fuzzing engine
class FuzzingEngine {
public:
    FuzzingEngine();
    ~FuzzingEngine();

    bool Initialize(uint64_t seed = 0);
    void Shutdown();

    void SetTarget(std::function<bool(const std::vector<uint8_t>&)> target);
    void AddMutator(std::function<std::vector<uint8_t>(const std::vector<uint8_t>&)> mutator);

    uint64_t Fuzz(size_t iterations, size_t maxInputSize = 4096);
    void Stop();
    bool IsRunning() const { return running_.load(); }

    struct FuzzStats { uint64_t totalIterations; uint64_t crashes; uint64_t hangs; uint64_t uniquePaths; };
    FuzzStats GetStats() const { return stats_; }

private:
    std::atomic<bool> running_{false};
    std::function<bool(const std::vector<uint8_t>&)> target_;
    std::vector<std::function<std::vector<uint8_t>(const std::vector<uint8_t>&)>> mutators_;
    FuzzStats stats_;
    uint64_t seed_;
    mutable std::mutex mutex_;
};

// Property-based testing
class PropertyBasedTest {
public:
    PropertyBasedTest();
    ~PropertyBasedTest();

    void Register(const std::string& name, std::function<bool()> property, size_t iterations = 100);
    std::vector<TestResult> RunAll();
    std::vector<TestResult> Run(const std::string& name);

    struct PBStats { uint64_t totalProperties; uint64_t totalIterations; uint64_t failures; };
    PBStats GetStats() const { return stats_; }

private:
    struct Property { std::string name; std::function<bool()> func; size_t iterations; };
    std::vector<Property> properties_;
    PBStats stats_;
    mutable std::mutex mutex_;
};

// Golden file testing
class GoldenFileTest {
public:
    GoldenFileTest();
    ~GoldenFileTest();

    bool SetGolden(const std::string& testName, const std::string& goldenPath);
    bool Compare(const std::string& testName, const std::string& actualContent);
    bool UpdateGolden(const std::string& testName, const std::string& newContent);
    bool HasGolden(const std::string& testName) const;

    struct GFStats { uint64_t totalTests; uint64_t matches; uint64_t mismatches; uint64_t updates; };
    GFStats GetStats() const { return stats_; }

private:
    std::unordered_map<std::string, std::string> goldenFiles_;
    GFStats stats_;
    mutable std::mutex mutex_;
};

// Deterministic replay
class DeterministicReplay {
public:
    DeterministicReplay();
    ~DeterministicReplay();

    bool Record(const std::string& sessionName);
    bool Replay(const std::string& sessionName);
    bool Stop();

    void LogEvent(const std::string& event, const std::vector<uint8_t>& data);
    std::vector<std::pair<std::string, std::vector<uint8_t>>> GetEvents() const;

    struct DRStats { uint64_t totalEvents; uint64_t replayedEvents; uint64_t mismatches; };
    DRStats GetStats() const { return stats_; }

private:
    std::vector<std::pair<std::string, std::vector<uint8_t>>> events_;
    size_t replayIndex_ = 0;
    bool recording_ = false;
    bool replaying_ = false;
    DRStats stats_;
    mutable std::mutex mutex_;
};

} // namespace Sovereign
