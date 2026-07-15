// RawrXD-Script Engine Integration Layer
// Connects test harnesses to the actual interpreter and runtime

#pragma once

#include "../bytecode/bytecode.hpp"
#include "../compiler/bytecode_emitter.hpp"
#include "../interpreter/interpreter.hpp"
#include "../runtime/runtime.hpp"
#include "../lexer/lexer.hpp"
#include "../parser/parser.hpp"
#include <string>
#include <vector>
#include <functional>
#include <optional>

namespace RawrXD {
namespace Script {
namespace Test {

// ============================================================================
// Execution Pipeline
// ============================================================================

enum class PipelineStage {
    Lexer,
    Parser,
    Emitter,
    Interpreter,
    Runtime
};

struct PipelineResult {
    bool success;
    PipelineStage failedAt;
    std::string errorMessage;
    double stageTimesMs[5];  // Time spent in each stage
    
    // Execution results
    JsValue returnValue;
    std::string output;
    std::string stderr;
    int exitCode;
};

// ============================================================================
// Engine Integration
// ============================================================================

class EngineIntegration {
public:
    // Initialize the engine (arena, runtime, etc.)
    static bool Initialize();
    static void Shutdown();
    
    // Full pipeline: Source -> Lexer -> Parser -> Emitter -> Interpreter
    static PipelineResult ExecuteScript(
        const std::string& source,
        const std::string& filename = "<test>"
    );
    
    // Execute pre-compiled bytecode
    static PipelineResult ExecuteBytecode(
        const BytecodeModule& module,
        const std::vector<JsValue>& args = {}
    );
    
    // Execute with timeout (for fuzzing/stress tests)
    static PipelineResult ExecuteScriptWithTimeout(
        const std::string& source,
        uint32_t timeoutMs,
        const std::string& filename = "<test>"
    );
    
    // Check if engine is in valid state
    static bool IsHealthy();
    
    // Reset engine state (clear arena, IC tables, etc.)
    static void ResetState();
    
    // Get coverage information
    struct CoverageInfo {
        std::vector<bool> opcodesExecuted;
        std::vector<bool> runtimeFunctionsCalled;
        size_t icHits;
        size_t icMisses;
        size_t shapesCreated;
    };
    static CoverageInfo GetCoverage();
    static void ResetCoverage();
};

// ============================================================================
// Deterministic Replay
// ============================================================================

struct ReplayRecord {
    uint32_t seed;
    std::string source;
    BytecodeModule bytecode;
    std::vector<uint8_t> memorySnapshot;  // Arena state at crash
    std::string stackTrace;
    std::string errorMessage;
    
    // Serialize to file
    bool Save(const std::string& path);
    static std::optional<ReplayRecord> Load(const std::string& path);
};

class DeterministicReplay {
public:
    // Save a crash for later replay
    static void SaveCrash(
        uint32_t seed,
        const std::string& source,
        const std::string& error,
        const std::string& outputDir = "crashes/"
    );
    
    // Replay a saved crash
    static PipelineResult Replay(const std::string& path);
    
    // List all saved crashes
    static std::vector<std::string> ListCrashes(const std::string& dir = "crashes/");
    
    // Minimize a crash (reduce source while preserving crash)
    static std::string MinimizeCrash(const std::string& path);
};

// ============================================================================
// Coverage Tracking
// ============================================================================

class CoverageTracker {
public:
    // Opcode coverage
    static void RecordOpcode(uint8_t opcode);
    static bool WasOpcodeExecuted(uint8_t opcode);
    static float GetOpcodeCoveragePercent();
    
    // Runtime function coverage
    static void RecordRuntimeCall(const char* functionName);
    static bool WasRuntimeFunctionCalled(const char* functionName);
    
    // IC coverage
    static void RecordICHit(uint32_t slot);
    static void RecordICMiss(uint32_t slot);
    static void RecordShapeTransition(uint32_t fromShape, uint32_t toShape);
    
    // Source coverage (parser productions)
    static void RecordProduction(const char* production);
    
    // Generate coverage report
    static std::string GenerateReport();
    static void Reset();
};

// ============================================================================
// Test Utilities
// ============================================================================

class TestUtils {
public:
    // Value assertions
    static bool ValuesEqual(const JsValue& a, const JsValue& b);
    static bool ValueIsNumber(const JsValue& v, double expected);
    static bool ValueIsString(const JsValue& v, const std::string& expected);
    static bool ValueIsNull(const JsValue& v);
    static bool ValueIsUndefined(const JsValue& v);
    static bool ValueIsBoolean(const JsValue& v, bool expected);
    static bool ValueIsObject(const JsValue& v);
    static bool ValueIsArray(const JsValue& v);
    static bool ValueIsFunction(const JsValue& v);
    
    // Exception assertions
    static bool ThrewException(const PipelineResult& result);
    static bool ThrewSpecificError(const PipelineResult& result, const char* errorType);
    
    // Performance measurement
    static double MeasureExecutionTime(
        const std::string& source,
        uint32_t iterations = 1
    );
    
    // Memory measurement
    struct MemoryStats {
        size_t arenaUsed;
        size_t arenaCommitted;
        size_t objectCount;
        size_t stringCount;
    };
    static MemoryStats GetMemoryStats();
};

// ============================================================================
// Regression Database
// ============================================================================

class RegressionDatabase {
public:
    // Add a test case from a discovered bug
    static void AddTestCase(
        const std::string& name,
        const std::string& source,
        const std::string& expectedResult,
        const std::string& bugDescription
    );
    
    // Run all regression tests
    static struct RegressionResult {
        size_t total;
        size_t passed;
        size_t failed;
        std::vector<std::string> failures;
    } RunAll();
    
    // Get test case by name
    static std::optional<std::string> GetTestCase(const std::string& name);
    
    // List all test cases
    static std::vector<std::string> ListTestCases();
};

// ============================================================================
// Integration Macros
// ============================================================================

#define TEST_REQUIRES_ENGINE() \
    do { \
        if (!RawrXD::Script::Test::EngineIntegration::Initialize()) { \
            std::cerr << "Failed to initialize engine" << std::endl; \
            return 1; \
        } \
    } while(0)

#define TEST_EXECUTE(source) \
    RawrXD::Script::Test::EngineIntegration::ExecuteScript(source)

#define TEST_ASSERT_SUCCESS(result) \
    do { \
        if (!result.success) { \
            std::cerr << "Test failed at " << #result << ": " << result.errorMessage << std::endl; \
            return false; \
        } \
    } while(0)

#define TEST_ASSERT_VALUE(result, expected) \
    do { \
        if (!RawrXD::Script::Test::TestUtils::ValuesEqual(result.returnValue, expected)) { \
            std::cerr << "Value mismatch in " << #result << std::endl; \
            return false; \
        } \
    } while(0)

} // namespace Test
} // namespace Script
} // namespace RawrXD
