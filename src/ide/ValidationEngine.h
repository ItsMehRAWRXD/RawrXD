/*===========================================================================
 * ValidationEngine.h
 * RawrXD IDE - Patch Validation Engine
 * 
 * Shadow compilation, test execution, and atomic rollback
 * Safety protocol for autonomous debugging
 *===========================================================================*/

#ifndef VALIDATION_ENGINE_H
#define VALIDATION_ENGINE_H

#include <windows.h>
#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <stdint.h>

namespace RawrXD {

/*===========================================================================
 * VALIDATION RESULTS
 *===========================================================================*/

enum class ValidationStage {
    StaticAnalysis,      // Syntax, AST, symbol analysis
    ShadowBuild,         // Compile in isolated environment
    UnitTests,          // Run relevant test suite
    RuntimeReplay,       // Replay crash scenario
    RegressionCheck,     // Compare against baseline
    Complete
};

enum class ValidationStatus {
    Pending,
    InProgress,
    Passed,
    Failed,
    Cancelled
};

struct ValidationError {
    ValidationStage stage;
    std::string message;
    std::string details;
    uint32_t errorCode;
    
    ValidationError() : stage(ValidationStage::StaticAnalysis), errorCode(0) {}
};

struct ValidationResult {
    ValidationStatus status;
    std::vector<ValidationError> errors;
    
    // Timing
    uint64_t startTime;
    uint64_t endTime;
    uint64_t durationMs;
    
    // Stage results
    bool staticAnalysisPassed;
    bool shadowBuildPassed;
    bool unitTestsPassed;
    bool runtimeReplayPassed;
    bool regressionPassed;
    
    // Metrics
    uint32_t warningsGenerated;
    uint32_t testsRun;
    uint32_t testsPassed;
    uint32_t testsFailed;
    float codeCoveragePercent;
    
    ValidationResult() 
        : status(ValidationStatus::Pending)
        , startTime(0), endTime(0), durationMs(0)
        , staticAnalysisPassed(false)
        , shadowBuildPassed(false)
        , unitTestsPassed(false)
        , runtimeReplayPassed(false)
        , regressionPassed(false)
        , warningsGenerated(0)
        , testsRun(0), testsPassed(0), testsFailed(0)
        , codeCoveragePercent(0.0f) {}
};

/*===========================================================================
 * SHADOW BUILD CONFIGURATION
 *===========================================================================*/

struct ShadowBuildConfig {
    std::string sourceRoot;           // Original source directory
    std::string shadowRoot;           // Temporary build directory
    std::string buildCommand;         // e.g., "cmake --build . --config Release"
    std::string outputPath;           // Where to place built binary
    
    // Isolation
    bool useSandbox;                  // Use Windows sandbox/job object
    uint32_t maxMemoryMB;            // Memory limit for build
    uint32_t timeoutSeconds;         // Build timeout
    
    ShadowBuildConfig()
        : useSandbox(true)
        , maxMemoryMB(4096)
        , timeoutSeconds(300) {}
};

/*===========================================================================
 * CRASH SIGNATURE
 *===========================================================================*/

struct CrashSignature {
    uint64_t stackHash;               // Hash of call stack
    uint64_t instructionHash;         // Hash of instruction sequence
    uint32_t exceptionCode;           // Windows exception code
    uint64_t faultAddress;            // Memory address that caused crash
    uint64_t memoryRegion;            // Heap/stack/code region
    uint64_t threadId;                // Thread where crash occurred
    uint64_t timestamp;               // When crash occurred
    
    // Derived
    std::string moduleName;           // DLL/EXE where crash occurred
    std::string functionName;         // Function symbol
    uint32_t lineNumber;              // Source line
    
    CrashSignature()
        : stackHash(0)
        , instructionHash(0)
        , exceptionCode(0)
        , faultAddress(0)
        , memoryRegion(0)
        , threadId(0)
        , timestamp(0)
        , lineNumber(0) {}
    
    // Comparison
    bool operator==(const CrashSignature& other) const;
    bool operator!=(const CrashSignature& other) const;
    bool IsSimilar(const CrashSignature& other, float threshold = 0.9f) const;
    
    // Serialization
    std::string ToString() const;
    static CrashSignature FromString(const std::string& str);
    
    // Hashing
    uint64_t ComputeCombinedHash() const;
};

/*===========================================================================
 * VALIDATION ENGINE
 *===========================================================================*/

using ValidationCallback = std::function<void(const ValidationResult&)>;
using ValidationProgressCallback = std::function<void(ValidationStage, const std::string&)>;

class ValidationEngine {
public:
    ValidationEngine();
    ~ValidationEngine();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    
    // Configuration
    void SetShadowBuildConfig(const ShadowBuildConfig& config);
    void SetValidationCallback(ValidationCallback callback);
    void SetProgressCallback(ValidationProgressCallback callback);
    
    // Main validation entry point
    void ValidatePatchAsync(
        const std::string& originalFile,
        const std::string& patchedFile,
        const CrashSignature& originalCrash,
        ValidationCallback callback
    );
    
    // Synchronous validation (blocking)
    ValidationResult ValidatePatchSync(
        const std::string& originalFile,
        const std::string& patchedFile,
        const CrashSignature& originalCrash
    );
    
    // Individual stage validation
    bool RunStaticAnalysis(const std::string& filePath, ValidationResult& result);
    bool RunShadowBuild(const std::string& sourcePath, ValidationResult& result);
    bool RunUnitTests(const std::string& binaryPath, ValidationResult& result);
    bool RunRuntimeReplay(
        const std::string& binaryPath,
        const CrashSignature& originalCrash,
        ValidationResult& result
    );
    bool RunRegressionCheck(const ValidationResult& current, ValidationResult& result);
    
    // Cancel ongoing validation
    void CancelValidation();
    bool IsValidating() const;
    
    // Utilities
    static CrashSignature ComputeSignature(
        uint32_t exceptionCode,
        uint64_t faultAddress,
        const std::vector<uint64_t>& callStack,
        uint64_t threadId
    );
    
    static std::string GenerateStackHash(const std::vector<uint64_t>& callStack);
    static std::string GenerateInstructionHash(uint64_t ip, const uint8_t* bytes, size_t len);

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
    
    // Stage implementations
    bool PerformStaticAnalysis(const std::string& file, std::vector<ValidationError>& errors);
    bool PerformShadowBuild(const ShadowBuildConfig& config, std::vector<ValidationError>& errors);
    bool PerformUnitTests(const std::string& binary, std::vector<ValidationError>& errors);
    bool PerformRuntimeReplay(
        const std::string& binary,
        const CrashSignature& signature,
        CrashSignature& outNewSignature,
        std::vector<ValidationError>& errors
    );
    
    // Helpers
    bool CreateShadowDirectory(const std::string& path);
    bool CleanupShadowDirectory(const std::string& path);
    bool CopyFileToShadow(const std::string& source, const std::string& dest);
    bool ApplyPatchInShadow(
        const std::string& original,
        const std::string& patched,
        const std::string& shadowRoot
    );
};

/*===========================================================================
 * ATOMIC TRANSACTION
 *===========================================================================*/

class PatchTransaction {
public:
    PatchTransaction();
    ~PatchTransaction();
    
    // Transaction lifecycle
    bool Begin(const std::string& filePath);
    bool StageChanges(const std::string& newContent);
    bool Commit();
    bool Rollback();
    
    // Status
    bool IsActive() const;
    bool IsCommitted() const;
    bool IsRolledBack() const;
    
    // Backup management
    std::string GetBackupPath() const;
    bool HasBackup() const;

private:
    std::string m_originalPath;
    std::string m_backupPath;
    std::string m_stagedContent;
    bool m_active;
    bool m_committed;
    bool m_rolledBack;
};

/*===========================================================================
 * EVIDENCE RECORD
 *===========================================================================*/

struct EvidenceRecord {
    // Identity
    std::string runUuid;              // Unique run identifier
    std::string gitCommit;            // Source commit hash
    uint64_t timestamp;               // When evidence was captured
    
    // Model (Source of Truth)
    std::string modelHash;          // SHA256/BLAKE3 of GGUF file
    std::string modelArchitecture;  // From GGUF header
    uint32_t modelContextLength;    // From GGUF header
    uint32_t modelQuantization;     // Q4_K_M, Q8_0, etc.
    
    // Environment (Hardware-Verified)
    std::string cpuArch;            // From CPUID
    std::string cpuFeatures;        // AVX2, AVX-512, etc.
    uint32_t cpuCores;              // Physical cores
    uint64_t systemMemory;          // Total RAM
    std::string gpuInfo;            // GPU model if applicable
    
    // Performance (Measured)
    float tokensPerSecond;          // Actual measured TPS
    float timeToFirstToken;         // TTFT in ms
    float peakMemoryUsage;          // Peak working set
    float vramPressure;             // GPU memory pressure
    
    // Validation Results
    ValidationResult validation;
    CrashSignature crashSignature;
    
    // Patch Info
    std::string patchDescription;
    float patchConfidence;            // Runtime-calculated confidence
    std::vector<std::string> patchFiles;
    
    EvidenceRecord()
        : timestamp(0)
        , modelContextLength(0)
        , modelQuantization(0)
        , cpuCores(0)
        , systemMemory(0)
        , tokensPerSecond(0.0f)
        , timeToFirstToken(0.0f)
        , peakMemoryUsage(0.0f)
        , vramPressure(0.0f)
        , patchConfidence(0.0f) {}
    
    // Serialization
    std::string ToJson() const;
    static EvidenceRecord FromJson(const std::string& json);
    bool SaveToFile(const std::string& path) const;
    static EvidenceRecord LoadFromFile(const std::string& path);
    
    // Comparison
    static EvidenceRecord Compare(const EvidenceRecord& baseline, const EvidenceRecord& current);
    std::string GenerateDeltaReport() const;
};

/*===========================================================================
 * EVIDENCE MANAGER
 *===========================================================================*/

class EvidenceManager {
public:
    static EvidenceManager& GetInstance();
    
    // Recording
    void BeginRecording(const std::string& runUuid);
    void SetModelInfo(const std::string& hash, const std::string& arch);
    void SetPerformanceMetrics(float tps, float ttft, float memory);
    void SetValidationResult(const ValidationResult& result);
    void SetCrashSignature(const CrashSignature& signature);
    EvidenceRecord FinalizeRecording();
    
    // Storage
    bool SaveEvidence(const EvidenceRecord& record, const std::string& directory);
    std::vector<EvidenceRecord> LoadEvidenceHistory(const std::string& directory);
    
    // Comparison
    EvidenceRecord CompareRuns(const std::string& baselineUuid, const std::string& currentUuid);
    std::vector<EvidenceRecord> FindRegressions(const std::string& directory, float threshold = 0.95f);
    
    // CI Integration
    bool GenerateCiArtifact(const EvidenceRecord& record, const std::string& outputPath);
    bool ValidateAgainstBaseline(const EvidenceRecord& current, const std::string& baselinePath);

private:
    EvidenceManager();
    ~EvidenceManager();
    
    EvidenceRecord m_currentRecord;
    bool m_recording;
    
    std::string GenerateUuid();
    std::string GetGitCommit();
    void CaptureEnvironment();
};

} // namespace RawrXD

#endif // VALIDATION_ENGINE_H
