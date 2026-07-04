// RawrXD-Script Engine Integration Implementation
// Connects test harnesses to the actual interpreter and runtime

#include "engine_integration.hpp"
#include <chrono>
#include <fstream>
#include <iostream>
#include <filesystem>

namespace RawrXD {
namespace Script {
namespace Test {

// ============================================================================
// Static State
// ============================================================================

static bool g_initialized = false;
static Runtime* g_runtime = nullptr;
static Interpreter* g_interpreter = nullptr;

// Coverage tracking
static std::vector<bool> g_opcodeCoverage(256, false);
static std::vector<std::string> g_runtimeFunctionsCalled;
static size_t g_icHits = 0;
static size_t g_icMisses = 0;

// ============================================================================
// Engine Integration
// ============================================================================

bool EngineIntegration::Initialize() {
    if (g_initialized) {
        return true;
    }
    
    // Initialize runtime
    g_runtime = Runtime::Create();
    if (!g_runtime) {
        std::cerr << "[Engine] Failed to create runtime" << std::endl;
        return false;
    }
    
    // Initialize interpreter
    g_interpreter = Interpreter::Create(g_runtime);
    if (!g_interpreter) {
        std::cerr << "[Engine] Failed to create interpreter" << std::endl;
        Runtime::Destroy(g_runtime);
        return false;
    }
    
    g_initialized = true;
    std::cout << "[Engine] Initialized successfully" << std::endl;
    return true;
}

void EngineIntegration::Shutdown() {
    if (!g_initialized) {
        return;
    }
    
    if (g_interpreter) {
        Interpreter::Destroy(g_interpreter);
        g_interpreter = nullptr;
    }
    
    if (g_runtime) {
        Runtime::Destroy(g_runtime);
        g_runtime = nullptr;
    }
    
    g_initialized = false;
    std::cout << "[Engine] Shutdown complete" << std::endl;
}

PipelineResult EngineIntegration::ExecuteScript(
    const std::string& source,
    const std::string& filename
) {
    PipelineResult result = {};
    result.success = false;
    result.exitCode = 1;
    
    if (!g_initialized) {
        result.errorMessage = "Engine not initialized";
        result.failedAt = PipelineStage::Lexer;
        return result;
    }
    
    auto startTime = std::chrono::high_resolution_clock::now();
    
    // Stage 1: Lexing
    auto lexStart = std::chrono::high_resolution_clock::now();
    Lexer lexer(source, filename);
    auto tokens = lexer.Tokenize();
    auto lexEnd = std::chrono::high_resolution_clock::now();
    result.stageTimesMs[0] = std::chrono::duration<double, std::milli>(lexEnd - lexStart).count();
    
    if (lexer.HasErrors()) {
        result.failedAt = PipelineStage::Lexer;
        result.errorMessage = lexer.GetFirstError();
        return result;
    }
    
    // Stage 2: Parsing
    auto parseStart = std::chrono::high_resolution_clock::now();
    Parser parser(tokens);
    auto ast = parser.ParseProgram();
    auto parseEnd = std::chrono::high_resolution_clock::now();
    result.stageTimesMs[1] = std::chrono::duration<double, std::milli>(parseEnd - parseStart).count();
    
    if (parser.HasErrors()) {
        result.failedAt = PipelineStage::Parser;
        result.errorMessage = parser.GetFirstError();
        return result;
    }
    
    // Stage 3: Bytecode emission
    auto emitStart = std::chrono::high_resolution_clock::now();
    BytecodeEmitter emitter;
    auto module = emitter.Emit(ast);
    auto emitEnd = std::chrono::high_resolution_clock::now();
    result.stageTimesMs[2] = std::chrono::duration<double, std::milli>(emitEnd - emitStart).count();
    
    if (emitter.HasErrors()) {
        result.failedAt = PipelineStage::Emitter;
        result.errorMessage = emitter.GetFirstError();
        return result;
    }
    
    // Stage 4: Interpretation
    auto interpStart = std::chrono::high_resolution_clock::now();
    g_interpreter->LoadModule(module);
    auto execResult = g_interpreter->Execute();
    auto interpEnd = std::chrono::high_resolution_clock::now();
    result.stageTimesMs[3] = std::chrono::duration<double, std::milli>(interpEnd - interpStart).count();
    
    if (!execResult.success) {
        result.failedAt = PipelineStage::Interpreter;
        result.errorMessage = execResult.error;
        return result;
    }
    
    // Stage 5: Runtime finalization
    auto runtimeStart = std::chrono::high_resolution_clock::now();
    result.returnValue = execResult.value;
    result.output = g_runtime->GetOutputBuffer();
    result.stderr = g_runtime->GetErrorBuffer();
    auto runtimeEnd = std::chrono::high_resolution_clock::now();
    result.stageTimesMs[4] = std::chrono::duration<double, std::milli>(runtimeEnd - runtimeStart).count();
    
    result.success = true;
    result.exitCode = 0;
    
    auto totalEnd = std::chrono::high_resolution_clock::now();
    std::cout << "[Engine] Execution completed in " 
              << std::chrono::duration<double, std::milli>(totalEnd - startTime).count()
              << "ms" << std::endl;
    
    return result;
}

PipelineResult EngineIntegration::ExecuteBytecode(
    const BytecodeModule& module,
    const std::vector<JsValue>& args
) {
    PipelineResult result = {};
    result.success = false;
    
    if (!g_initialized) {
        result.errorMessage = "Engine not initialized";
        return result;
    }
    
    auto startTime = std::chrono::high_resolution_clock::now();
    
    g_interpreter->LoadModule(module);
    
    // Push arguments onto stack
    for (const auto& arg : args) {
        g_interpreter->PushValue(arg);
    }
    
    auto execResult = g_interpreter->Execute();
    
    if (execResult.success) {
        result.success = true;
        result.returnValue = execResult.value;
        result.exitCode = 0;
    } else {
        result.errorMessage = execResult.error;
        result.exitCode = 1;
    }
    
    auto endTime = std::chrono::high_resolution_clock::now();
    result.stageTimesMs[3] = std::chrono::duration<double, std::milli>(endTime - startTime).count();
    
    return result;
}

PipelineResult EngineIntegration::ExecuteScriptWithTimeout(
    const std::string& source,
    uint32_t timeoutMs,
    const std::string& filename
) {
    // TODO: Implement timeout using async execution or watchdog thread
    // For now, just execute normally
    std::cout << "[Engine] Warning: Timeout not yet implemented, executing without limit" << std::endl;
    return ExecuteScript(source, filename);
}

bool EngineIntegration::IsHealthy() {
    return g_initialized && g_runtime && g_interpreter;
}

void EngineIntegration::ResetState() {
    if (g_runtime) {
        g_runtime->ResetArena();
        g_runtime->ClearICCache();
    }
    if (g_interpreter) {
        g_interpreter->Reset();
    }
    ResetCoverage();
}

EngineIntegration::CoverageInfo EngineIntegration::GetCoverage() {
    CoverageInfo info;
    info.opcodesExecuted = g_opcodeCoverage;
    info.runtimeFunctionsCalled = g_runtimeFunctionsCalled;
    info.icHits = g_icHits;
    info.icMisses = g_icMisses;
    info.shapesCreated = g_runtime ? g_runtime->GetShapeCount() : 0;
    return info;
}

void EngineIntegration::ResetCoverage() {
    std::fill(g_opcodeCoverage.begin(), g_opcodeCoverage.end(), false);
    g_runtimeFunctionsCalled.clear();
    g_icHits = 0;
    g_icMisses = 0;
}

// ============================================================================
// Deterministic Replay
// ============================================================================

bool ReplayRecord::Save(const std::string& path) {
    std::ofstream file(path, std::ios::binary);
    if (!file) {
        return false;
    }
    
    // Write seed
    file.write(reinterpret_cast<const char*>(&seed), sizeof(seed));
    
    // Write source length and source
    uint32_t sourceLen = static_cast<uint32_t>(source.length());
    file.write(reinterpret_cast<const char*>(&sourceLen), sizeof(sourceLen));
    file.write(source.c_str(), sourceLen);
    
    // Write error message
    uint32_t errorLen = static_cast<uint32_t>(errorMessage.length());
    file.write(reinterpret_cast<const char*>(&errorLen), sizeof(errorLen));
    file.write(errorMessage.c_str(), errorLen);
    
    // Write stack trace
    uint32_t stackLen = static_cast<uint32_t>(stackTrace.length());
    file.write(reinterpret_cast<const char*>(&stackLen), sizeof(stackLen));
    file.write(stackTrace.c_str(), stackLen);
    
    file.close();
    return true;
}

std::optional<ReplayRecord> ReplayRecord::Load(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return std::nullopt;
    }
    
    ReplayRecord record;
    
    // Read seed
    file.read(reinterpret_cast<char*>(&record.seed), sizeof(record.seed));
    
    // Read source
    uint32_t sourceLen;
    file.read(reinterpret_cast<char*>(&sourceLen), sizeof(sourceLen));
    record.source.resize(sourceLen);
    file.read(&record.source[0], sourceLen);
    
    // Read error message
    uint32_t errorLen;
    file.read(reinterpret_cast<char*>(&errorLen), sizeof(errorLen));
    record.errorMessage.resize(errorLen);
    file.read(&record.errorMessage[0], errorLen);
    
    // Read stack trace
    uint32_t stackLen;
    file.read(reinterpret_cast<char*>(&stackLen), sizeof(stackLen));
    record.stackTrace.resize(stackLen);
    file.read(&record.stackTrace[0], stackLen);
    
    file.close();
    return record;
}

void DeterministicReplay::SaveCrash(
    uint32_t seed,
    const std::string& source,
    const std::string& error,
    const std::string& outputDir
) {
    namespace fs = std::filesystem;
    
    // Create output directory if it doesn't exist
    fs::create_directories(outputDir);
    
    // Generate unique filename
    auto timestamp = std::chrono::system_clock::now().time_since_epoch().count();
    std::string filename = outputDir + "/crash_" + std::to_string(seed) + "_" + 
                          std::to_string(timestamp) + ".replay";
    
    ReplayRecord record;
    record.seed = seed;
    record.source = source;
    record.errorMessage = error;
    
    // Capture stack trace (simplified)
    record.stackTrace = "Stack trace capture not yet implemented";
    
    if (record.Save(filename)) {
        std::cout << "[Replay] Crash saved to: " << filename << std::endl;
    } else {
        std::cerr << "[Replay] Failed to save crash" << std::endl;
    }
}

PipelineResult DeterministicReplay::Replay(const std::string& path) {
    auto record = ReplayRecord::Load(path);
    if (!record) {
        PipelineResult result;
        result.success = false;
        result.errorMessage = "Failed to load replay record";
        return result;
    }
    
    std::cout << "[Replay] Replaying crash with seed: " << record->seed << std::endl;
    std::cout << "[Replay] Source length: " << record->source.length() << " bytes" << std::endl;
    
    // Execute the script
    return EngineIntegration::ExecuteScript(record->source);
}

std::vector<std::string> DeterministicReplay::ListCrashes(const std::string& dir) {
    std::vector<std::string> crashes;
    namespace fs = std::filesystem;
    
    if (!fs::exists(dir)) {
        return crashes;
    }
    
    for (const auto& entry : fs::directory_iterator(dir)) {
        if (entry.path().extension() == ".replay") {
            crashes.push_back(entry.path().string());
        }
    }
    
    return crashes;
}

std::string DeterministicReplay::MinimizeCrash(const std::string& path) {
    auto record = ReplayRecord::Load(path);
    if (!record) {
        return "";
    }
    
    std::cout << "[Replay] Minimizing crash..." << std::endl;
    
    // Simple minimization: try removing lines/characters
    std::string minimized = record->source;
    std::string originalError = record->errorMessage;
    
    // TODO: Implement actual minimization algorithm
    // 1. Try removing each line
    // 2. Try removing each character
    // 3. Try simplifying expressions
    
    std::cout << "[Replay] Minimization not yet fully implemented" << std::endl;
    return minimized;
}

// ============================================================================
// Coverage Tracking
// ============================================================================

void CoverageTracker::RecordOpcode(uint8_t opcode) {
    if (opcode < g_opcodeCoverage.size()) {
        g_opcodeCoverage[opcode] = true;
    }
}

bool CoverageTracker::WasOpcodeExecuted(uint8_t opcode) {
    if (opcode < g_opcodeCoverage.size()) {
        return g_opcodeCoverage[opcode];
    }
    return false;
}

float CoverageTracker::GetOpcodeCoveragePercent() {
    size_t executed = 0;
    for (bool b : g_opcodeCoverage) {
        if (b) executed++;
    }
    return (100.0f * executed) / g_opcodeCoverage.size();
}

void CoverageTracker::RecordRuntimeCall(const char* functionName) {
    g_runtimeFunctionsCalled.push_back(functionName);
}

bool CoverageTracker::WasRuntimeFunctionCalled(const char* functionName) {
    for (const auto& fn : g_runtimeFunctionsCalled) {
        if (fn == functionName) {
            return true;
        }
    }
    return false;
}

void CoverageTracker::RecordICHit(uint32_t slot) {
    g_icHits++;
}

void CoverageTracker::RecordICMiss(uint32_t slot) {
    g_icMisses++;
}

void CoverageTracker::RecordShapeTransition(uint32_t fromShape, uint32_t toShape) {
    // TODO: Track shape transitions
}

void CoverageTracker::RecordProduction(const char* production) {
    // TODO: Track parser productions
}

std::string CoverageTracker::GenerateReport() {
    std::ostringstream report;
    
    report << "=== Coverage Report ===" << std::endl;
    report << "Opcode Coverage: " << GetOpcodeCoveragePercent() << "%" << std::endl;
    report << "IC Hits: " << g_icHits << std::endl;
    report << "IC Misses: " << g_icMisses << std::endl;
    report << "IC Hit Rate: " << (g_icHits + g_icMisses > 0 ? 
        (100.0 * g_icHits / (g_icHits + g_icMisses)) : 0) << "%" << std::endl;
    report << "Runtime Functions Called: " << g_runtimeFunctionsCalled.size() << std::endl;
    
    return report.str();
}

void CoverageTracker::Reset() {
    std::fill(g_opcodeCoverage.begin(), g_opcodeCoverage.end(), false);
    g_runtimeFunctionsCalled.clear();
    g_icHits = 0;
    g_icMisses = 0;
}

// ============================================================================
// Test Utilities
// ============================================================================

bool TestUtils::ValuesEqual(const JsValue& a, const JsValue& b) {
    // TODO: Implement proper value comparison
    return a.raw == b.raw;
}

bool TestUtils::ValueIsNumber(const JsValue& v, double expected) {
    // TODO: Check type tag and compare double value
    return false;
}

bool TestUtils::ValueIsString(const JsValue& v, const std::string& expected) {
    // TODO: Check type tag and compare string
    return false;
}

bool TestUtils::ValueIsNull(const JsValue& v) {
    // TODO: Check type tag
    return false;
}

bool TestUtils::ValueIsUndefined(const JsValue& v) {
    // TODO: Check type tag
    return false;
}

bool TestUtils::ValueIsBoolean(const JsValue& v, bool expected) {
    // TODO: Check type tag and boolean value
    return false;
}

bool TestUtils::ValueIsObject(const JsValue& v) {
    // TODO: Check type tag
    return false;
}

bool TestUtils::ValueIsArray(const JsValue& v) {
    // TODO: Check type tag and array flag
    return false;
}

bool TestUtils::ValueIsFunction(const JsValue& v) {
    // TODO: Check type tag
    return false;
}

bool TestUtils::ThrewException(const PipelineResult& result) {
    return !result.success && result.failedAt == PipelineStage::Interpreter;
}

bool TestUtils::ThrewSpecificError(const PipelineResult& result, const char* errorType) {
    return ThrewException(result) && result.errorMessage.find(errorType) != std::string::npos;
}

double TestUtils::MeasureExecutionTime(const std::string& source, uint32_t iterations) {
    auto start = std::chrono::high_resolution_clock::now();
    
    for (uint32_t i = 0; i < iterations; i++) {
        EngineIntegration::ResetState();
        EngineIntegration::ExecuteScript(source);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    return std::chrono::duration<double, std::milli>(end - start).count() / iterations;
}

TestUtils::MemoryStats TestUtils::GetMemoryStats() {
    MemoryStats stats = {};
    // TODO: Query runtime for actual memory stats
    return stats;
}

// ============================================================================
// Regression Database
// ============================================================================

static std::vector<std::tuple<std::string, std::string, std::string, std::string>> g_regressionTests;

void RegressionDatabase::AddTestCase(
    const std::string& name,
    const std::string& source,
    const std::string& expectedResult,
    const std::string& bugDescription
) {
    g_regressionTests.push_back({name, source, expectedResult, bugDescription});
}

RegressionDatabase::RegressionResult RegressionDatabase::RunAll() {
    RegressionResult result = {};
    result.total = g_regressionTests.size();
    
    for (const auto& test : g_regressionTests) {
        const auto& [name, source, expected, description] = test;
        
        EngineIntegration::ResetState();
        auto execResult = EngineIntegration::ExecuteScript(source);
        
        // TODO: Compare result with expected
        bool passed = execResult.success;
        
        if (passed) {
            result.passed++;
        } else {
            result.failed++;
            result.failures.push_back(name + ": " + execResult.errorMessage);
        }
    }
    
    return result;
}

std::optional<std::string> RegressionDatabase::GetTestCase(const std::string& name) {
    for (const auto& test : g_regressionTests) {
        if (std::get<0>(test) == name) {
            return std::get<1>(test);
        }
    }
    return std::nullopt;
}

std::vector<std::string> RegressionDatabase::ListTestCases() {
    std::vector<std::string> names;
    for (const auto& test : g_regressionTests) {
        names.push_back(std::get<0>(test));
    }
    return names;
}

} // namespace Test
} // namespace Script
} // namespace RawrXD
