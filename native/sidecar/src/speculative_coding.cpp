/**
 * RawrXD Speculative Coding Engine Implementation
 * Parallel code generation with test-based selection
 */

#include "speculative_coding.hpp"
#include <iostream>
#include <fstream>
#include <thread>
#include <algorithm>
#include <random>

namespace rawrxd::speculative {

// Branch Generator Implementation
std::vector<BranchGenerator::BranchPrompt> BranchGenerator::generateBranchPrompts(
    std::string_view basePrompt,
    std::string_view context,
    size_t numBranches,
    float baseTemp,
    float tempVariance
) {
    std::vector<BranchPrompt> prompts;
    std::mt19937 rng(std::random_device{}());
    std::uniform_real_distribution<float> tempDist(
        baseTemp - tempVariance,
        baseTemp + tempVariance
    );
    
    // Strategies for different branches
    std::vector<std::string> strategies = {
        "direct",           // Direct implementation
        "step_by_step",     // Step-by-step approach
        "pattern_match",    // Pattern matching approach
        "functional",       // Functional programming style
        "optimized"         // Performance optimized
    };
    
    for (size_t i = 0; i < numBranches; ++i) {
        BranchPrompt bp;
        bp.id = "branch-" + std::to_string(i);
        bp.temperature = std::clamp(tempDist(rng), 0.0f, 1.0f);
        bp.strategy = strategies[i % strategies.size()];
        
        // Apply strategy to prompt
        bp.prompt = applyStrategy(basePrompt, bp.strategy);
        
        prompts.push_back(std::move(bp));
    }
    
    return prompts;
}

std::string BranchGenerator::applyStrategy(
    std::string_view prompt,
    std::string_view strategy
) {
    if (strategy == "step_by_step") {
        return "Implement this step by step with clear comments:\n" + std::string(prompt);
    } else if (strategy == "pattern_match") {
        return "Use design patterns where appropriate:\n" + std::string(prompt);
    } else if (strategy == "functional") {
        return "Use functional programming principles:\n" + std::string(prompt);
    } else if (strategy == "optimized") {
        return "Optimize for performance and efficiency:\n" + std::string(prompt);
    }
    // direct - no modification
    return std::string(prompt);
}

// Speculative Coding Engine Implementation
SpeculativeCodingEngine::SpeculativeCodingEngine() = default;
SpeculativeCodingEngine::~SpeculativeCodingEngine() = default;

std::vector<SpeculativeBranch> SpeculativeCodingEngine::generateBranches(
    std::string_view prompt,
    std::string_view context,
    const SpeculativeConfig& config
) {
    std::cout << "[RawrXD Speculative] Generating " << config.numBranches << " branches..." << std::endl;
    
    BranchGenerator generator;
    auto branchPrompts = generator.generateBranchPrompts(
        prompt, context, config.numBranches,
        config.temperature, config.temperatureVariance
    );
    
    std::vector<SpeculativeBranch> branches;
    branches.reserve(branchPrompts.size());
    
    // Generate each branch
    for (const auto& bp : branchPrompts) {
        SpeculativeBranch branch;
        branch.id = bp.id;
        branch.description = "Strategy: " + bp.strategy;
        
        auto start = std::chrono::steady_clock::now();
        
        // Generate code using callback
        if (m_generationCallback) {
            branch.generatedCode = m_generationCallback(
                bp.prompt, context, bp.temperature, config.maxTokensPerBranch
            );
        } else {
            // Placeholder generation
            branch.generatedCode = "// Placeholder code for " + bp.id + "\n";
        }
        
        auto end = std::chrono::steady_clock::now();
        branch.generationTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        
        branches.push_back(std::move(branch));
    }
    
    return branches;
}

void SpeculativeCodingEngine::testBranches(
    std::vector<SpeculativeBranch>& branches,
    const SpeculativeConfig& config
) {
    std::cout << "[RawrXD Speculative] Testing " << branches.size() << " branches in parallel..." << std::endl;
    
    // Launch tests in parallel
    std::vector<std::future<void>> futures;
    futures.reserve(branches.size());
    
    for (auto& branch : branches) {
        futures.push_back(std::async(std::launch::async, [&branch, &config, this]() {
            auto start = std::chrono::steady_clock::now();
            
            // Run compilation test
            if (config.requireCompilation) {
                auto compileResult = this->runCompilation(branch);
                branch.compiled = compileResult.success;
                if (!compileResult.success) {
                    branch.errorOutput = compileResult.output;
                }
            }
            
            // Run tests if compilation passed
            if (branch.compiled && config.runTests) {
                auto testResult = this->runTests(branch);
                branch.testsPassed = testResult.success;
                if (!testResult.success) {
                    branch.errorOutput += "\n" + testResult.output;
                }
            }
            
            // Run linter
            if (config.runLinter) {
                auto lintResult = this->runLinter(branch);
                // Parse lint errors from output
                branch.lintErrors = std::count(
                    lintResult.output.begin(), lintResult.output.end(), '\n'
                );
            }
            
            auto end = std::chrono::steady_clock::now();
            branch.testTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
            
            // Calculate final score
            branch.score = this->calculateScore(branch);
        }));
    }
    
    // Wait for all tests to complete
    for (auto& future : futures) {
        future.wait();
    }
}

std::vector<SpeculativeBranch> SpeculativeCodingEngine::rankBranches(
    std::vector<SpeculativeBranch>& branches
) {
    // Sort by score (descending)
    std::sort(branches.begin(), branches.end(),
        [](const SpeculativeBranch& a, const SpeculativeBranch& b) {
            return a.score > b.score;
        });
    
    return branches;
}

const SpeculativeBranch* SpeculativeCodingEngine::getBestBranch(
    const std::vector<SpeculativeBranch>& branches
) const {
    if (branches.empty()) {
        return nullptr;
    }
    
    // Find highest scoring branch that compiled
    for (const auto& branch : branches) {
        if (branch.compiled) {
            return &branch;
        }
    }
    
    // Fallback to first branch if none compiled
    return &branches[0];
}

bool SpeculativeCodingEngine::applyBranch(
    const SpeculativeBranch& branch,
    const fs::path& workspacePath
) {
    std::cout << "[RawrXD Speculative] Applying branch: " << branch.id << std::endl;
    
    try {
        for (const auto& [filePath, content] : branch.files) {
            fs::path fullPath = workspacePath / filePath;
            
            // Create directories if needed
            fs::create_directories(fullPath.parent_path());
            
            // Write file
            std::ofstream file(fullPath);
            if (!file.is_open()) {
                std::cerr << "[RawrXD Speculative] Failed to write: " << fullPath << std::endl;
                return false;
            }
            file << content;
        }
        
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[RawrXD Speculative] Apply failed: " << e.what() << std::endl;
        return false;
    }
}

void SpeculativeCodingEngine::setGenerationCallback(GenerationCallback callback) {
    m_generationCallback = std::move(callback);
}

void SpeculativeCodingEngine::setTestCallback(TestCallback callback) {
    m_testCallback = std::move(callback);
}

TestResult SpeculativeCodingEngine::runCompilation(const SpeculativeBranch& branch) {
    if (m_testCallback) {
        return m_testCallback(branch, fs::temp_directory_path());
    }
    
    // Placeholder
    return {true, "Compiled successfully", 0, std::chrono::milliseconds(100)};
}

TestResult SpeculativeCodingEngine::runTests(const SpeculativeBranch& branch) {
    if (m_testCallback) {
        return m_testCallback(branch, fs::temp_directory_path());
    }
    
    // Placeholder
    return {true, "All tests passed", 0, std::chrono::milliseconds(500)};
}

TestResult SpeculativeCodingEngine::runLinter(const SpeculativeBranch& branch) {
    // Placeholder
    return {true, "", 0, std::chrono::milliseconds(50)};
}

float SpeculativeCodingEngine::calculateScore(const SpeculativeBranch& branch) {
    float score = 0.0f;
    
    // Compilation is critical
    if (branch.compiled) {
        score += 50.0f;
    } else {
        return 0.0f; // Can't use uncompiled code
    }
    
    // Tests passing
    if (branch.testsPassed) {
        score += 30.0f;
    }
    
    // Lint score (fewer errors = higher score)
    score += std::max(0.0f, 20.0f - static_cast<float>(branch.lintErrors));
    
    // Speed bonus (faster generation + test = better)
    auto totalTime = branch.generationTime + branch.testTime;
    if (totalTime.count() < 5000) { // Under 5 seconds
        score += 10.0f;
    }
    
    return score;
}

// Test Harness Implementation
TestHarness::TestHarness(const fs::path& workspacePath)
    : m_workspacePath(workspacePath) {}

fs::path TestHarness::createTestEnvironment(const SpeculativeBranch& branch) {
    // Create temp directory
    fs::path tempPath = fs::temp_directory_path() / 
        ("rawrxd_spec_" + branch.id + "_" + std::to_string(std::time(nullptr)));
    
    fs::create_directories(tempPath);
    m_tempPaths.push_back(tempPath);
    
    // Copy workspace
    for (const auto& entry : fs::recursive_directory_iterator(m_workspacePath)) {
        if (entry.is_regular_file()) {
            fs::path relative = fs::relative(entry.path(), m_workspacePath);
            fs::path dest = tempPath / relative;
            fs::create_directories(dest.parent_path());
            fs::copy_file(entry.path(), dest, fs::copy_options::overwrite_existing);
        }
    }
    
    // Apply branch changes
    for (const auto& [filePath, content] : branch.files) {
        fs::path fullPath = tempPath / filePath;
        fs::create_directories(fullPath.parent_path());
        std::ofstream file(fullPath);
        file << content;
    }
    
    return tempPath;
}

TestResult TestHarness::runTests(
    const fs::path& testPath,
    std::chrono::seconds timeout
) {
    auto start = std::chrono::steady_clock::now();
    
    // Run npm test or equivalent
    // This is platform-specific, using placeholder
    
    auto end = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    return {true, "Tests passed", 0, duration};
}

void TestHarness::cleanupTestEnvironment(const fs::path& testPath) {
    try {
        fs::remove_all(testPath);
    } catch (...) {
        // Ignore cleanup errors
    }
}

// Reporter Implementation
void SpeculativeReporter::reportGeneration(const SpeculativeBranch& branch) {
    std::cout << "[RawrXD Speculative] Generated: " << branch.id 
              << " (" << branch.generationTime.count() << "ms)" << std::endl;
}

void SpeculativeReporter::reportTestComplete(const SpeculativeBranch& branch) {
    std::cout << "[RawrXD Speculative] Tested: " << branch.id
              << " | Compiled: " << (branch.compiled ? "Yes" : "No")
              << " | Tests: " << (branch.testsPassed ? "Pass" : "Fail")
              << " | Score: " << branch.score << std::endl;
}

void SpeculativeReporter::reportWinner(const SpeculativeBranch& branch) {
    std::cout << "[RawrXD Speculative] Winner: " << branch.id 
              << " with score " << branch.score << std::endl;
}

void SpeculativeReporter::reportAllComplete(
    const std::vector<SpeculativeBranch>& branches
) {
    json report;
    report["totalBranches"] = branches.size();
    report["successful"] = std::count_if(
        branches.begin(), branches.end(),
        [](const auto& b) { return b.compiled; }
    );
    
    json branchesJson = json::array();
    for (const auto& branch : branches) {
        branchesJson.push_back({
            {"id", branch.id},
            {"compiled", branch.compiled},
            {"testsPassed", branch.testsPassed},
            {"score", branch.score},
            {"generationTimeMs", branch.generationTime.count()},
            {"testTimeMs", branch.testTime.count()}
        });
    }
    report["branches"] = branchesJson;
    
    m_report = report;
    
    std::cout << "[RawrXD Speculative] Complete. " 
              << report["successful"] << "/" << branches.size() << " branches successful."
              << std::endl;
}

json SpeculativeReporter::getReport() const {
    return m_report;
}

} // namespace rawrxd::speculative
