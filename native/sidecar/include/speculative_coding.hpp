/**
 * RawrXD Speculative Coding Engine
 * Generate multiple code branches, test in parallel, keep winner
 * 
 * Applies Medusa speculative decoding philosophy to code generation
 */

#pragma once

#include <vector>
#include <string>
#include <future>
#include <functional>
#include <filesystem>
#include <json/json.hpp>

namespace rawrxd::speculative {

using json = nlohmann::json;
namespace fs = std::filesystem;

// A speculative code branch
struct SpeculativeBranch {
    std::string id;
    std::string description;
    std::string generatedCode;
    std::vector<std::pair<fs::path, std::string>> files; // path -> content
    
    // Test results
    bool compiled{false};
    bool testsPassed{false};
    int lintErrors{0};
    float score{0.0f};
    std::string errorOutput;
    
    // Timing
    std::chrono::milliseconds generationTime{0};
    std::chrono::milliseconds testTime{0};
};

// Test result for a branch
struct TestResult {
    bool success;
    std::string output;
    int exitCode;
    std::chrono::milliseconds duration;
};

// Speculative coding configuration
struct SpeculativeConfig {
    size_t numBranches{3};           // Number of parallel branches
    size_t maxTokensPerBranch{1024}; // Max tokens per generation
    float temperature{0.2f};           // Base temperature
    float temperatureVariance{0.1f};   // Variance between branches
    bool runTests{true};             // Run tests on branches
    bool runLinter{true};            // Run linter on branches
    bool requireCompilation{true};   // Require successful compilation
    std::chrono::seconds timeout{30}; // Test timeout
};

/**
 * Speculative Coding Engine
 * Generates multiple solutions, tests them all, returns best
 */
class SpeculativeCodingEngine {
public:
    SpeculativeCodingEngine();
    ~SpeculativeCodingEngine();
    
    // Non-copyable
    SpeculativeCodingEngine(const SpeculativeCodingEngine&) = delete;
    SpeculativeCodingEngine& operator=(const SpeculativeCodingEngine&) = delete;
    
    // Generate speculative branches
    std::vector<SpeculativeBranch> generateBranches(
        std::string_view prompt,
        std::string_view context,
        const SpeculativeConfig& config
    );
    
    // Test all branches in parallel
    void testBranches(
        std::vector<SpeculativeBranch>& branches,
        const SpeculativeConfig& config
    );
    
    // Score and rank branches
    std::vector<SpeculativeBranch> rankBranches(
        std::vector<SpeculativeBranch>& branches
    );
    
    // Get best branch
    const SpeculativeBranch* getBestBranch(
        const std::vector<SpeculativeBranch>& branches
    ) const;
    
    // Apply winning branch to workspace
    bool applyBranch(
        const SpeculativeBranch& branch,
        const fs::path& workspacePath
    );
    
    // Set code generation callback (integrates with LLM)
    using GenerationCallback = std::function<std::string(
        std::string_view prompt,
        std::string_view context,
        float temperature,
        size_t maxTokens
    )>;
    void setGenerationCallback(GenerationCallback callback);
    
    // Set test execution callback
    using TestCallback = std::function<TestResult(
        const SpeculativeBranch& branch,
        const fs::path& workspacePath
    )>;
    void setTestCallback(TestCallback callback);
    
private:
    GenerationCallback m_generationCallback;
    TestCallback m_testCallback;
    
    // Internal test methods
    TestResult runCompilation(const SpeculativeBranch& branch);
    TestResult runTests(const SpeculativeBranch& branch);
    TestResult runLinter(const SpeculativeBranch& branch);
    
    // Scoring
    float calculateScore(const SpeculativeBranch& branch);
    
    // Parallel execution
    template<typename T, typename Func>
    std::vector<T> parallelMap(
        std::vector<T>& items,
        Func&& func
    );
};

// Branch generator - creates variations of prompts
class BranchGenerator {
public:
    struct BranchPrompt {
        std::string id;
        std::string prompt;
        float temperature;
        std::string strategy; // "direct", "step_by_step", "pattern_match", etc.
    };
    
    std::vector<BranchPrompt> generateBranchPrompts(
        std::string_view basePrompt,
        std::string_view context,
        size_t numBranches,
        float baseTemp,
        float tempVariance
    );
    
private:
    std::string applyStrategy(
        std::string_view prompt,
        std::string_view strategy
    );
};

// Test harness for running tests on branches
class TestHarness {
public:
    TestHarness(const fs::path& workspacePath);
    
    // Create isolated test environment for branch
    fs::path createTestEnvironment(const SpeculativeBranch& branch);
    
    // Run tests in environment
    TestResult runTests(
        const fs::path& testPath,
        std::chrono::seconds timeout
    );
    
    // Cleanup test environment
    void cleanupTestEnvironment(const fs::path& testPath);
    
private:
    fs::path m_workspacePath;
    std::vector<fs::path> m_tempPaths;
};

// Result reporter
class SpeculativeReporter {
public:
    void reportGeneration(const SpeculativeBranch& branch);
    void reportTestComplete(const SpeculativeBranch& branch);
    void reportWinner(const SpeculativeBranch& branch);
    void reportAllComplete(const std::vector<SpeculativeBranch>& branches);
    
    // Get report as JSON
    json getReport() const;
    
private:
    json m_report;
};

} // namespace rawrxd::speculative
