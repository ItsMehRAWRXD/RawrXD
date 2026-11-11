#pragma once
// SovereignBridge.hpp
// RawrXD IDE → Sovereign Runtime Integration Bridge
// War-room implementation: minimal, functional, no abstraction bloat

#include <string>
#include <vector>
#include <windows.h>

namespace RawrXD {
namespace IDE {

// Result from sovereign validation execution
struct SovereignResult
{
    bool started = false;           // Process launched successfully
    bool completed = false;         // Process finished (not crashed)
    int exitCode = -1;              // Process exit code
    bool passed = false;            // Validation passed (based on certificate)
    
    std::string runId;              // Unique run identifier
    std::string runPath;            // Path to evidence bundle
    std::string certificatePath;    // Path to certificate.json
    std::string output;             // Captured stdout/stderr
    
    // Parsed certificate data
    int gatesPassed = 0;
    int gatesFailed = 0;
    int gatesTotal = 0;
    std::string validationHash;
    double executionTimeMs = 0.0;
    
    bool IsSuccess() const { return started && completed && passed; }
};

// Configuration for sovereign execution
struct SovereignConfig
{
    std::string runtimePath = "rawrxd.exe";  // Path to sovereign runtime
    std::string modelPath = "models/phi3-mini.gguf";  // Default model
    std::string evidenceRoot = "validation/runs";     // Evidence output directory
    int maxTokens = 128;
    std::string backend = "auto";  // cpu, vulkan, auto
    unsigned int seed = 0;          // 0 = random
    bool autonomous = true;         // Enable agentic controller
    bool validate = true;           // Enable validation gates
    int timeoutMs = 300000;         // 5 minute timeout
};

// Bridge between IDE and Sovereign Runtime
class SovereignBridge
{
public:
    SovereignBridge();
    ~SovereignBridge();
    
    // Execute sovereign validation
    // Returns result with output, certificate path, and pass/fail status
    SovereignResult Validate(
        const std::string& prompt,
        const SovereignConfig& config = SovereignConfig()
    );
    
    // Quick validation with default model
    SovereignResult QuickValidate(const std::string& prompt);
    
    // Check if runtime is available
    bool IsRuntimeAvailable() const;
    
    // Get last error message
    std::string GetLastError() const { return m_lastError; }
    
    // Parse certificate from evidence bundle
    static bool ParseCertificate(
        const std::string& certificatePath,
        SovereignResult& outResult
    );
    
    // Find latest evidence bundle
    static std::string FindLatestEvidenceBundle(const std::string& evidenceRoot);

private:
    std::string m_lastError;
    
    // Execute command and capture output
    std::string ExecuteCommand(
        const std::string& command,
        int& outExitCode,
        int timeoutMs
    );
    
    // Build command line from config
    std::string BuildCommandLine(
        const std::string& prompt,
        const SovereignConfig& config
    ) const;
    
    // Escape string for command line
    static std::string EscapeCommandLine(const std::string& arg);
};

} // namespace IDE
} // namespace RawrXD
