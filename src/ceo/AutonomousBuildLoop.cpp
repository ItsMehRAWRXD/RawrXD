// ============================================================================
// AutonomousBuildLoop.cpp — Self-Building, Self-Testing, Self-Repairing Implementation
// ============================================================================
#include "AutonomousBuildLoop.hpp"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <regex>
#include <chrono>
#include <thread>
#include <cstdio>
#include <mutex>

#ifdef _WIN32
#include <windows.h>
#include <process.h>
#else
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem;

namespace RawrXD {
namespace CEO {

// ============================================================================
// Constructor / Destructor
// ============================================================================
AutonomousBuildLoop::AutonomousBuildLoop() = default;
AutonomousBuildLoop::~AutonomousBuildLoop() {
    Shutdown();
}

// ============================================================================
// Initialization
// ============================================================================
bool AutonomousBuildLoop::Initialize() {
    if (m_initialized) {
        return true;
    }
    
    // Detect optimal job count
    if (m_config.parallelJobs == 0) {
        unsigned int cores = std::thread::hardware_concurrency();
        m_config.parallelJobs = cores > 0 ? cores : 4;
    }
    
    m_initialized = true;
    return true;
}

void AutonomousBuildLoop::Shutdown() {
    m_cancelled = true;
    m_initialized = false;
}

// ============================================================================
// Main Operations
// ============================================================================
bool AutonomousBuildLoop::GenerateAndApplyCode(const std::string& description,
                                                const std::vector<std::string>& targetFiles) {
    printf("[BuildLoop] Generating code for: %s\n", description.c_str());
    
    // For each target file, generate code
    for (const auto& file : targetFiles) {
        // Read existing content if file exists
        std::string originalContent;
        ReadFile(file, originalContent);
        
        // Generate new content (this would call the model)
        // For now, create a placeholder
        std::string newContent = originalContent;
        newContent += "\n// Generated: " + description + "\n";
        
        // Create change record
        CodeChange change;
        change.filePath = file;
        change.originalContent = originalContent;
        change.newContent = newContent;
        change.description = description;
        change.timestamp = std::chrono::system_clock::now();
        
        // Apply the change
        if (ApplyChange(change)) {
            printf("[BuildLoop] Applied changes to: %s\n", file.c_str());
        } else {
            printf("[BuildLoop] Failed to apply changes to: %s\n", file.c_str());
            return false;
        }
    }
    
    return true;
}

bool AutonomousBuildLoop::Build() {
    if (m_isBuilding.exchange(true)) {
        return false; // Already building
    }
    
    printf("[BuildLoop] Starting build...\n");
    
    // Run the build
    m_lastBuildResult = ExecuteBuild();
    
    if (m_buildCb) {
        m_buildCb(m_lastBuildResult);
    }
    
    m_isBuilding = false;
    
    printf("[BuildLoop] Build %s\n", m_lastBuildResult.success ? "SUCCEEDED" : "FAILED");
    
    return m_lastBuildResult.success;
}

bool AutonomousBuildLoop::Test() {
    if (m_isTesting.exchange(true)) {
        return false; // Already testing
    }
    
    printf("[BuildLoop] Starting tests...\n");
    
    // Run tests
    m_lastTestResult = ExecuteTest();
    
    if (m_testCb) {
        m_testCb(m_lastTestResult);
    }
    
    m_isTesting = false;
    
    printf("[BuildLoop] Tests %s (%d/%d passed)\n", 
           m_lastTestResult.success ? "PASSED" : "FAILED",
           m_lastTestResult.passedTests,
           m_lastTestResult.totalTests);
    
    return m_lastTestResult.success;
}

bool AutonomousBuildLoop::Debug(const std::string& errorDescription) {
    printf("[BuildLoop] Debugging: %s\n", errorDescription.c_str());
    
    m_repairAttempts++;
    
    if (m_repairCb) {
        m_repairCb(errorDescription, m_repairAttempts.load());
    }
    
    // Analyze the errors
    if (!AnalyzeErrors()) {
        printf("[BuildLoop] Failed to analyze errors\n");
        return false;
    }
    
    // Generate a repair
    if (!GenerateRepair()) {
        printf("[BuildLoop] Failed to generate repair\n");
        return false;
    }
    
    // Apply the repair
    if (!ApplyRepair()) {
        printf("[BuildLoop] Failed to apply repair\n");
        return false;
    }
    
    // Try building again
    if (!Build()) {
        // Still failing, check if we should continue
        if (m_repairAttempts >= m_config.maxRepairAttempts) {
            printf("[BuildLoop] Max repair attempts reached\n");
            return false;
        }
        
        // Recursive repair attempt
        return Debug("Previous repair did not resolve all issues");
    }
    
    // Build succeeded, now test
    if (!Test()) {
        // Tests failed, debug the test failures
        return Debug("Test failures after build repair");
    }
    
    printf("[BuildLoop] Debug cycle complete - build and tests passing\n");
    return true;
}

bool AutonomousBuildLoop::RunFullCycle(const std::string& goal) {
    printf("[BuildLoop] Starting full autonomous cycle for: %s\n", goal.c_str());
    
    m_repairAttempts = 0;
    m_cancelled = false;
    
    // Phase 1: Generate code
    std::vector<std::string> files; // Would be determined by goal analysis
    if (!GenerateAndApplyCode(goal, files)) {
        printf("[BuildLoop] Code generation failed\n");
        return false;
    }
    
    // Phase 2: Build
    if (!Build()) {
        // Build failed, enter debug/repair loop
        if (!Debug("Initial build failed")) {
            printf("[BuildLoop] Could not repair build\n");
            return false;
        }
    }
    
    // Phase 3: Test
    if (!Test()) {
        // Tests failed, enter debug/repair loop
        if (!Debug("Initial tests failed")) {
            printf("[BuildLoop] Could not repair tests\n");
            return false;
        }
    }
    
    printf("[BuildLoop] Full cycle complete - goal achieved!\n");
    return true;
}

// ============================================================================
// Change Management
// ============================================================================
std::vector<CodeChange> AutonomousBuildLoop::GetPendingChanges() const {
    std::lock_guard<std::mutex> lock(m_changesMutex);
    std::vector<CodeChange> pending;
    for (const auto& change : m_changes) {
        if (!change.applied && !change.reverted) {
            pending.push_back(change);
        }
    }
    return pending;
}

bool AutonomousBuildLoop::ApplyChange(const CodeChange& change) {
    // Backup the original file
    if (!change.originalContent.empty()) {
        if (!BackupFile(change.filePath)) {
            printf("[BuildLoop] Failed to backup: %s\n", change.filePath.c_str());
        }
    }
    
    // Write the new content
    if (!WriteFile(change.filePath, change.newContent)) {
        printf("[BuildLoop] Failed to write: %s\n", change.filePath.c_str());
        return false;
    }
    
    // Record the change
    {
        std::lock_guard<std::mutex> lock(m_changesMutex);
        CodeChange recorded = change;
        recorded.applied = true;
        recorded.timestamp = std::chrono::system_clock::now();
        m_changes.push_back(recorded);
    }
    
    return true;
}

bool AutonomousBuildLoop::RevertChange(const std::string& filePath) {
    std::lock_guard<std::mutex> lock(m_changesMutex);
    
    for (auto& change : m_changes) {
        if (change.filePath == filePath && change.applied && !change.reverted) {
            // Restore original content
            if (!WriteFile(filePath, change.originalContent)) {
                return false;
            }
            change.reverted = true;
            return true;
        }
    }
    
    return false;
}

bool AutonomousBuildLoop::RevertAllChanges() {
    std::lock_guard<std::mutex> lock(m_changesMutex);
    
    bool allSuccess = true;
    for (auto& change : m_changes) {
        if (change.applied && !change.reverted) {
            if (!WriteFile(change.filePath, change.originalContent)) {
                allSuccess = false;
            } else {
                change.reverted = true;
            }
        }
    }
    
    return allSuccess;
}

// ============================================================================
// Internal Operations
// ============================================================================
BuildResult AutonomousBuildLoop::ExecuteBuild() {
    std::string command = m_config.buildCommand;
    
    if (m_config.parallelBuild) {
        command += " -j" + std::to_string(m_config.parallelJobs);
    }
    
    return RunCommand(command, m_config.buildTimeoutSec);
}

TestResult AutonomousBuildLoop::ExecuteTest() {
    BuildResult br = RunCommand(m_config.testCommand, m_config.testTimeoutSec);
    TestResult tr;
    tr.success = br.success;
    tr.output = br.stdout_output + "\n" + br.stderr_output;
    tr.duration = br.duration;
    // Parse test output for pass/fail counts
    tr.totalTests = 0;
    tr.passedTests = 0;
    tr.failedTests = 0;
    return tr;
}

bool AutonomousBuildLoop::AnalyzeErrors() {
    // Parse build errors
    auto errors = ParseCompilerErrors(m_lastBuildResult.stderr_output);
    m_lastBuildResult.errors = errors;
    
    printf("[BuildLoop] Found %zu errors\n", errors.size());
    
    return !errors.empty() || m_lastBuildResult.success;
}

bool AutonomousBuildLoop::GenerateRepair() {
    // This would use the model to generate a fix
    // For now, just log that we would generate a repair
    printf("[BuildLoop] Generating repair for %zu errors...\n", m_lastBuildResult.errors.size());
    
    // In a full implementation, this would:
    // 1. Send errors to the model
    // 2. Get suggested fixes
    // 3. Create CodeChange objects
    
    return true;
}

bool AutonomousBuildLoop::ApplyRepair() {
    // Apply the generated repairs
    printf("[BuildLoop] Applying repairs...\n");
    
    // In a full implementation, this would apply the CodeChange objects
    
    return true;
}

// ============================================================================
// Error Parsing
// ============================================================================
std::vector<std::string> AutonomousBuildLoop::ParseCompilerErrors(const std::string& output) {
    std::vector<std::string> errors;
    std::istringstream stream(output);
    std::string line;
    
    // Common error patterns
    std::regex errorPattern(R"((error|Error|ERROR):\s*(.+))");
    std::regex fileLinePattern(R"((.+\.(cpp|c|h|hpp)):(\d+):(\d+):\s*error)");
    
    while (std::getline(stream, line)) {
        std::smatch match;
        if (std::regex_search(line, match, errorPattern) ||
            std::regex_search(line, match, fileLinePattern)) {
            errors.push_back(line);
        }
    }
    
    return errors;
}

std::vector<std::string> AutonomousBuildLoop::ParseTestFailures(const std::string& output) {
    std::vector<std::string> failures;
    std::istringstream stream(output);
    std::string line;
    
    // Common test failure patterns
    std::regex failurePattern(R"((\[\s*FAILED\s*\]|Test failed|Assertion failed))");
    
    while (std::getline(stream, line)) {
        std::smatch match;
        if (std::regex_search(line, match, failurePattern)) {
            failures.push_back(line);
        }
    }
    
    return failures;
}

// ============================================================================
// File Operations
// ============================================================================
bool AutonomousBuildLoop::ReadFile(const std::string& path, std::string& content) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return false;
    }
    
    content.assign((std::istreambuf_iterator<char>(file)),
                   std::istreambuf_iterator<char>());
    return true;
}

bool AutonomousBuildLoop::WriteFile(const std::string& path, const std::string& content) {
    // Ensure directory exists
    fs::path p(path);
    if (p.has_parent_path()) {
        fs::create_directories(p.parent_path());
    }
    
    std::ofstream file(path, std::ios::binary);
    if (!file) {
        return false;
    }
    
    file.write(content.data(), content.size());
    return file.good();
}

bool AutonomousBuildLoop::BackupFile(const std::string& path) {
    std::string backupPath = path + ".backup";
    try {
        fs::copy_file(path, backupPath, fs::copy_options::overwrite_existing);
        return true;
    } catch (...) {
        return false;
    }
}

bool AutonomousBuildLoop::RestoreFile(const std::string& path) {
    std::string backupPath = path + ".backup";
    try {
        fs::copy_file(backupPath, path, fs::copy_options::overwrite_existing);
        return true;
    } catch (...) {
        return false;
    }
}

// ============================================================================
// Command Execution
// ============================================================================
BuildResult AutonomousBuildLoop::RunCommand(const std::string& command, int timeoutSec) {
    BuildResult result;
    auto start = std::chrono::steady_clock::now();
    
#ifdef _WIN32
    // Windows implementation using _popen
    FILE* pipe = _popen(command.c_str(), "r");
    if (!pipe) {
        result.success = false;
        result.exitCode = -1;
        return result;
    }
    
    char buffer[4096];
    std::string output;
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        output += buffer;
    }
    
    result.exitCode = _pclose(pipe);
    result.success = (result.exitCode == 0);
    result.stdout_output = output;
    
#else
    // Unix implementation
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        result.success = false;
        result.exitCode = -1;
        return result;
    }
    
    char buffer[4096];
    std::string output;
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        output += buffer;
    }
    
    result.exitCode = pclose(pipe);
    result.success = (result.exitCode == 0);
    result.stdout_output = output;
#endif
    
    auto end = std::chrono::steady_clock::now();
    result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    // Parse errors from output
    result.errors = ParseCompilerErrors(output);
    
    return result;
}

// ============================================================================
// Export/Import
// ============================================================================
json AutonomousBuildLoop::ExportState() const {
    json state;
    state["repair_attempts"] = m_repairAttempts.load();
    state["last_build"] = m_lastBuildResult.toJSON();
    state["last_test"] = m_lastTestResult.toJSON();
    
    std::lock_guard<std::mutex> lock(m_changesMutex);
    state["changes"] = json::array();
    for (const auto& change : m_changes) {
        json c;
        c["file"] = change.filePath;
        c["applied"] = change.applied;
        c["reverted"] = change.reverted;
        c["description"] = change.description;
        state["changes"].push_back(c);
    }
    
    return state;
}

bool AutonomousBuildLoop::ImportState(const json& state) {
    if (state.contains("repair_attempts")) {
        m_repairAttempts = state["repair_attempts"].get<int>();
    }
    
    // Note: Full implementation would restore all state
    
    return true;
}

} // namespace CEO
} // namespace RawrXD
