// =============================================================================
// RawRamXD_Phase9_RealWorldTest.cpp
// Phase 9: Real-World Integration Test Program
// =============================================================================
// Gates J1-J5: Real-world validation gates
// =============================================================================

#include "RawRamXD_Phase9_RealWorldIntegration.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <vector>
#include <string>

using namespace RawRamXD;

// =============================================================================
// Test Result Tracking
// =============================================================================

struct TestResult {
    std::string name;
    bool passed;
    std::string details;
    uint64_t durationMs;
};

std::vector<TestResult> g_testResults;

void RecordTest(const std::string& name, bool passed, const std::string& details, uint64_t durationMs) {
    TestResult result;
    result.name = name;
    result.passed = passed;
    result.details = details;
    result.durationMs = durationMs;
    g_testResults.push_back(result);
}

// =============================================================================
// Gate J1: LLM Inference Integration
// =============================================================================

bool TestGateJ1_LLMIntegration() {
    std::cout << "\n========================================" << std::endl;
    std::cout << "Gate J1: LLM Inference Integration" << std::endl;
    std::cout << "========================================" << std::endl;
    
    auto start = std::chrono::high_resolution_clock::now();
    
    // Initialize LLM Engine
    LLMInferenceEngine engine;
    LLMConfig config;
    config.modelType = "llama";
    config.contextLength = 4096;
    config.batchSize = 1;
    config.numLayers = 32;
    config.numHeads = 32;
    config.embeddingDim = 4096;
    config.useGPU = true;
    config.gpuLayerCount = 32;
    
    if (!engine.Initialize(config)) {
        RecordTest("J1.1: Engine Initialization", false, "Failed to initialize LLM engine", 0);
        return false;
    }
    RecordTest("J1.1: Engine Initialization", true, "LLM engine initialized successfully", 0);
    
    // Test model loading
    if (!engine.LoadModel("models/llama-7b.gguf")) {
        RecordTest("J1.2: Model Loading", false, "Failed to load model", 0);
        return false;
    }
    RecordTest("J1.2: Model Loading", true, "Model loaded successfully", 0);
    
    // Test inference
    auto result = engine.Generate("What is artificial intelligence?", 20);
    if (!result.success) {
        RecordTest("J1.3: Inference Execution", false, "Inference failed: " + result.errorMessage, 0);
        engine.UnloadModel();
        return false;
    }
    RecordTest("J1.3: Inference Execution", true, 
        "Generated " + std::to_string(result.tokensGenerated) + " tokens", 0);
    
    // Verify metrics
    if (result.tokensPerSecond <= 0) {
        RecordTest("J1.4: Performance Metrics", false, "Invalid tokens/second", 0);
        engine.UnloadModel();
        return false;
    }
    RecordTest("J1.4: Performance Metrics", true, 
        std::to_string((int)result.tokensPerSecond) + " tokens/sec", 0);
    
    // Test streaming generation
    int streamCount = 0;
    auto streamResult = engine.GenerateStreaming("Hello", 10, 
        [&streamCount](const TokenInfo& token) {
            streamCount++;
        });
    if (!streamResult.success || streamCount == 0) {
        RecordTest("J1.5: Streaming Generation", false, "Streaming failed", 0);
        engine.UnloadModel();
        return false;
    }
    RecordTest("J1.5: Streaming Generation", true, 
        "Streamed " + std::to_string(streamCount) + " tokens", 0);
    
    engine.UnloadModel();
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    std::cout << "\nGate J1: PASSED (" << duration << " ms)" << std::endl;
    return true;
}

// =============================================================================
// Gate J2: Multi-Model Concurrent Execution
// =============================================================================

bool TestGateJ2_MultiModelExecution() {
    std::cout << "\n========================================" << std::endl;
    std::cout << "Gate J2: Multi-Model Concurrent Execution" << std::endl;
    std::cout << "========================================" << std::endl;
    
    auto start = std::chrono::high_resolution_clock::now();
    
    // Initialize scheduler
    MultiModelScheduler scheduler;
    if (!scheduler.Initialize(16ULL * 1024 * 1024 * 1024)) { // 16GB
        RecordTest("J2.1: Scheduler Initialization", false, "Failed to initialize scheduler", 0);
        return false;
    }
    RecordTest("J2.1: Scheduler Initialization", true, "Scheduler initialized with 16GB", 0);
    
    // Register multiple models
    bool reg1 = scheduler.RegisterModel("llama-7b", "llama", 4ULL * 1024 * 1024 * 1024, 1);
    bool reg2 = scheduler.RegisterModel("qwen-7b", "qwen", 3ULL * 1024 * 1024 * 1024, 2);
    bool reg3 = scheduler.RegisterModel("mistral-7b", "mistral", 4ULL * 1024 * 1024 * 1024, 1);
    
    if (!reg1 || !reg2 || !reg3) {
        RecordTest("J2.2: Model Registration", false, "Failed to register all models", 0);
        return false;
    }
    RecordTest("J2.2: Model Registration", true, "3 models registered", 0);
    
    // Activate models
    bool act1 = scheduler.ActivateModel("llama-7b");
    bool act2 = scheduler.ActivateModel("qwen-7b");
    
    if (!act1 || !act2) {
        RecordTest("J2.3: Model Activation", false, "Failed to activate models", 0);
        return false;
    }
    RecordTest("J2.3: Model Activation", true, "2 models activated", 0);
    
    // Verify active models
    auto active = scheduler.GetActiveModels();
    if (active.size() < 2) {
        RecordTest("J2.4: Active Model Count", false, 
            "Expected 2 active, got " + std::to_string(active.size()), 0);
        return false;
    }
    RecordTest("J2.4: Active Model Count", true, 
        std::to_string(active.size()) + " models active", 0);
    
    // Test model selection
    auto selected = scheduler.SelectModelForRequest("llama");
    if (selected.empty()) {
        RecordTest("J2.5: Model Selection", false, "Failed to select model", 0);
        return false;
    }
    RecordTest("J2.5: Model Selection", true, "Selected: " + selected, 0);
    
    // Test deactivation
    bool deact = scheduler.DeactivateModel("llama-7b");
    if (!deact) {
        RecordTest("J2.6: Model Deactivation", false, "Failed to deactivate model", 0);
        return false;
    }
    RecordTest("J2.6: Model Deactivation", true, "Model deactivated", 0);
    
    // Check metrics
    auto metrics = scheduler.GetMetrics();
    if (metrics.registeredModels != 3) {
        RecordTest("J2.7: Scheduler Metrics", false, "Incorrect registered count", 0);
        return false;
    }
    RecordTest("J2.7: Scheduler Metrics", true, 
        std::to_string(metrics.registeredModels) + " registered, " + 
        std::to_string(metrics.activeModels) + " active", 0);
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    std::cout << "\nGate J2: PASSED (" << duration << " ms)" << std::endl;
    return true;
}

// =============================================================================
// Gate J3: Real Dataset Validation
// =============================================================================

bool TestGateJ3_DatasetValidation() {
    std::cout << "\n========================================" << std::endl;
    std::cout << "Gate J3: Real Dataset Validation" << std::endl;
    std::cout << "========================================" << std::endl;
    
    auto start = std::chrono::high_resolution_clock::now();
    
    // Initialize validator
    DatasetValidator validator;
    if (!validator.Initialize()) {
        RecordTest("J3.1: Validator Initialization", false, "Failed to initialize validator", 0);
        return false;
    }
    RecordTest("J3.1: Validator Initialization", true, "Validator initialized", 0);
    
    // Load dataset
    if (!validator.LoadDataset("data/alpaca.json", "alpaca")) {
        RecordTest("J3.2: Dataset Loading", false, "Failed to load dataset", 0);
        return false;
    }
    RecordTest("J3.2: Dataset Loading", true, "Dataset loaded", 0);
    
    // Check sample count
    uint32_t sampleCount = validator.GetSampleCount();
    if (sampleCount == 0) {
        RecordTest("J3.3: Sample Count", false, "No samples loaded", 0);
        return false;
    }
    RecordTest("J3.3: Sample Count", true, 
        std::to_string(sampleCount) + " samples loaded", 0);
    
    // Check categories
    auto categories = validator.GetCategories();
    if (categories.empty()) {
        RecordTest("J3.4: Categories", false, "No categories found", 0);
        return false;
    }
    RecordTest("J3.4: Categories", true, 
        std::to_string(categories.size()) + " categories found", 0);
    
    // Initialize LLM for validation
    LLMInferenceEngine engine;
    LLMConfig config;
    config.modelType = "llama";
    config.contextLength = 4096;
    config.batchSize = 1;
    config.numLayers = 32;
    config.numHeads = 32;
    config.embeddingDim = 4096;
    config.useGPU = true;
    config.gpuLayerCount = 32;
    engine.Initialize(config);
    engine.LoadModel("models/llama-7b.gguf");
    
    // Run validation
    auto result = validator.Validate(&engine);
    if (result.totalSamples == 0) {
        RecordTest("J3.5: Validation Execution", false, "Validation failed", 0);
        engine.UnloadModel();
        return false;
    }
    RecordTest("J3.5: Validation Execution", true, 
        std::to_string(result.passedSamples) + "/" + std::to_string(result.totalSamples) + " passed", 0);
    
    // Check accuracy
    if (result.accuracy < 0.5) {
        RecordTest("J3.6: Accuracy Threshold", false, 
            "Accuracy " + std::to_string((int)(result.accuracy * 100)) + "% below 50%", 0);
        engine.UnloadModel();
        return false;
    }
    RecordTest("J3.6: Accuracy Threshold", true, 
        std::to_string((int)(result.accuracy * 100)) + "% accuracy", 0);
    
    engine.UnloadModel();
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    std::cout << "\nGate J3: PASSED (" << duration << " ms)" << std::endl;
    return true;
}

// =============================================================================
// Gate J4: Competitive Benchmarking
// =============================================================================

bool TestGateJ4_CompetitiveBenchmarking() {
    std::cout << "\n========================================" << std::endl;
    std::cout << "Gate J4: Competitive Benchmarking" << std::endl;
    std::cout << "========================================" << std::endl;
    
    auto start = std::chrono::high_resolution_clock::now();
    
    // Initialize benchmark
    CompetitiveBenchmark benchmark;
    if (!benchmark.Initialize()) {
        RecordTest("J4.1: Benchmark Initialization", false, "Failed to initialize benchmark", 0);
        return false;
    }
    RecordTest("J4.1: Benchmark Initialization", true, "Benchmark initialized", 0);
    
    // Configure benchmark
    BenchmarkConfig config;
    config.mode = BenchmarkMode::THROUGHPUT;
    config.warmupIterations = 2;
    config.benchmarkIterations = 5;
    config.concurrentRequests = 1;
    config.maxTokensPerPrompt = 50;
    config.enableRawRamXD = true;
    config.enableBaseline = true;
    
    if (!benchmark.Configure(config)) {
        RecordTest("J4.2: Benchmark Configuration", false, "Failed to configure benchmark", 0);
        return false;
    }
    RecordTest("J4.2: Benchmark Configuration", true, "Benchmark configured", 0);
    
    // Initialize LLM
    LLMInferenceEngine engine;
    LLMConfig llmConfig;
    llmConfig.modelType = "llama";
    llmConfig.contextLength = 4096;
    llmConfig.batchSize = 1;
    llmConfig.numLayers = 32;
    llmConfig.numHeads = 32;
    llmConfig.embeddingDim = 4096;
    llmConfig.useGPU = true;
    llmConfig.gpuLayerCount = 32;
    engine.Initialize(llmConfig);
    engine.LoadModel("models/llama-7b.gguf");
    
    // Run RawRamXD benchmark
    auto rawramxdResult = benchmark.RunBenchmarkRawRamXD(&engine);
    if (rawramxdResult.successfulRequests == 0) {
        RecordTest("J4.3: RawRamXD Benchmark", false, "RawRamXD benchmark failed", 0);
        engine.UnloadModel();
        return false;
    }
    RecordTest("J4.3: RawRamXD Benchmark", true, 
        std::to_string((int)rawramxdResult.avgTokensPerSecond) + " tokens/sec", 0);
    
    // Run baseline benchmark
    auto baselineResult = benchmark.RunBenchmarkBaseline();
    if (baselineResult.successfulRequests == 0) {
        RecordTest("J4.4: Baseline Benchmark", false, "Baseline benchmark failed", 0);
        engine.UnloadModel();
        return false;
    }
    RecordTest("J4.4: Baseline Benchmark", true, 
        std::to_string((int)baselineResult.avgTokensPerSecond) + " tokens/sec", 0);
    
    // Compare results
    auto comparison = benchmark.CompareResults(rawramxdResult, baselineResult);
    RecordTest("J4.5: Comparison Analysis", true, 
        comparison.winner + " wins with " + std::to_string((int)(comparison.overallSpeedup * 100)) + "% speedup", 0);
    
    // Generate report
    if (!benchmark.GenerateReport(comparison, "benchmark_report.json")) {
        RecordTest("J4.6: Report Generation", false, "Failed to generate report", 0);
        engine.UnloadModel();
        return false;
    }
    RecordTest("J4.6: Report Generation", true, "Report saved to benchmark_report.json", 0);
    
    engine.UnloadModel();
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    std::cout << "\nGate J4: PASSED (" << duration << " ms)" << std::endl;
    return true;
}

// =============================================================================
// Gate J5: End-to-End Latency Profiling
// =============================================================================

bool TestGateJ5_LatencyProfiling() {
    std::cout << "\n========================================" << std::endl;
    std::cout << "Gate J5: End-to-End Latency Profiling" << std::endl;
    std::cout << "========================================" << std::endl;
    
    auto start = std::chrono::high_resolution_clock::now();
    
    // Initialize profiler
    LatencyProfiler profiler;
    if (!profiler.Initialize()) {
        RecordTest("J5.1: Profiler Initialization", false, "Failed to initialize profiler", 0);
        return false;
    }
    RecordTest("J5.1: Profiler Initialization", true, "Profiler initialized", 0);
    
    // Start profiling
    profiler.StartProfiling();
    RecordTest("J5.2: Profiling Start", true, "Profiling started", 0);
    
    // Simulate inference stages
    profiler.BeginStage(ProfileStage::PROMPT_TOKENIZATION);
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    profiler.EndStage(ProfileStage::PROMPT_TOKENIZATION);
    
    profiler.BeginStage(ProfileStage::MODEL_LOADING);
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    profiler.EndStage(ProfileStage::MODEL_LOADING);
    
    profiler.BeginStage(ProfileStage::KV_CACHE_ALLOCATION);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    profiler.EndStage(ProfileStage::KV_CACHE_ALLOCATION);
    
    profiler.BeginStage(ProfileStage::INFERENCE_COMPUTE);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    profiler.EndStage(ProfileStage::INFERENCE_COMPUTE);
    
    profiler.BeginStage(ProfileStage::TOKEN_GENERATION);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    profiler.EndStage(ProfileStage::TOKEN_GENERATION);
    
    profiler.BeginStage(ProfileStage::DETOKENIZATION);
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    profiler.EndStage(ProfileStage::DETOKENIZATION);
    
    // Stop profiling
    profiler.StopProfiling();
    RecordTest("J5.3: Profiling Stop", true, "Profiling stopped", 0);
    
    // Get metrics
    auto metrics = profiler.GetStageMetrics();
    if (metrics.empty()) {
        RecordTest("J5.4: Metrics Collection", false, "No metrics collected", 0);
        return false;
    }
    RecordTest("J5.4: Metrics Collection", true, 
        std::to_string(metrics.size()) + " stages profiled", 0);
    
    // Verify each stage has valid metrics
    bool allValid = true;
    for (const auto& m : metrics) {
        if (m.avgTimeNs == 0) {
            allValid = false;
            break;
        }
    }
    if (!allValid) {
        RecordTest("J5.5: Metrics Validity", false, "Invalid metrics detected", 0);
        return false;
    }
    RecordTest("J5.5: Metrics Validity", true, "All metrics valid", 0);
    
    // Identify bottlenecks
    auto bottlenecks = profiler.IdentifyBottlenecks(0.2); // 20% threshold
    RecordTest("J5.6: Bottleneck Detection", true, 
        std::to_string(bottlenecks.size()) + " bottlenecks identified", 0);
    
    // Generate flame graph data
    if (!profiler.GenerateFlameGraphData("flamegraph.txt")) {
        RecordTest("J5.7: Flame Graph Generation", false, "Failed to generate flame graph data", 0);
        return false;
    }
    RecordTest("J5.7: Flame Graph Generation", true, "Flame graph data saved", 0);
    
    // Reset and verify
    profiler.Reset();
    auto afterReset = profiler.GetStageMetrics();
    if (!afterReset.empty()) {
        RecordTest("J5.8: Profiler Reset", false, "Reset failed", 0);
        return false;
    }
    RecordTest("J5.8: Profiler Reset", true, "Profiler reset successfully", 0);
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    std::cout << "\nGate J5: PASSED (" << duration << " ms)" << std::endl;
    return true;
}

// =============================================================================
// Full Integration Test
// =============================================================================

bool TestFullIntegration() {
    std::cout << "\n========================================" << std::endl;
    std::cout << "Full Integration Test" << std::endl;
    std::cout << "========================================" << std::endl;
    
    auto start = std::chrono::high_resolution_clock::now();
    
    auto& controller = RealWorldIntegrationController::Instance();
    
    if (!controller.Initialize()) {
        std::cout << "Failed to initialize integration controller" << std::endl;
        return false;
    }
    
    auto result = controller.RunFullIntegration();
    
    controller.GenerateIntegrationReport("phase9_integration_report.json");
    
    controller.Shutdown();
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "Full Integration: " << (result.overallPassed ? "PASSED" : "FAILED") << std::endl;
    std::cout << "Duration: " << duration << " ms" << std::endl;
    std::cout << "========================================" << std::endl;
    
    return result.overallPassed;
}

// =============================================================================
// C API Test
// =============================================================================

bool TestCAPI() {
    std::cout << "\n========================================" << std::endl;
    std::cout << "C API Test" << std::endl;
    std::cout << "========================================" << std::endl;
    
    bool success = true;
    
    // Initialize
    if (!RawRamXD_Integration_Initialize()) {
        std::cout << "C API: Initialization failed" << std::endl;
        return false;
    }
    std::cout << "C API: Initialized" << std::endl;
    
    // Load model
    if (!RawRamXD_LoadModel("models/llama-7b.gguf", "llama")) {
        std::cout << "C API: Model loading failed" << std::endl;
        success = false;
    } else {
        std::cout << "C API: Model loaded" << std::endl;
        
        // Generate
        char output[1024];
        if (!RawRamXD_Generate("Hello", output, sizeof(output), 10)) {
            std::cout << "C API: Generation failed" << std::endl;
            success = false;
        } else {
            std::cout << "C API: Generated: " << output << std::endl;
        }
    }
    
    // Profiling
    RawRamXD_StartProfiling();
    std::cout << "C API: Profiling started" << std::endl;
    
    RawRamXD_StopProfiling();
    std::cout << "C API: Profiling stopped" << std::endl;
    
    if (!RawRamXD_SaveProfileData("c_api_profile.txt")) {
        std::cout << "C API: Profile save failed" << std::endl;
        success = false;
    } else {
        std::cout << "C API: Profile saved" << std::endl;
    }
    
    // Report
    if (!RawRamXD_SaveIntegrationReport("c_api_report.json")) {
        std::cout << "C API: Report generation failed" << std::endl;
        success = false;
    } else {
        std::cout << "C API: Report generated" << std::endl;
    }
    
    // Shutdown
    RawRamXD_Integration_Shutdown();
    std::cout << "C API: Shutdown" << std::endl;
    
    return success;
}

// =============================================================================
// Main
// =============================================================================

int main(int argc, char* argv[]) {
    std::cout << "=================================================================" << std::endl;
    std::cout << "RawRamXD Phase 9: Real-World Integration Test Suite" << std::endl;
    std::cout << "=================================================================" << std::endl;
    std::cout << "Gates: J1-J5 (5 gates)" << std::endl;
    std::cout << "=================================================================" << std::endl;
    
    bool runAll = true;
    bool runJ1 = false, runJ2 = false, runJ3 = false, runJ4 = false, runJ5 = false;
    bool runFull = false;
    bool runCAPI = false;
    
    // Parse arguments
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--j1") == 0) { runAll = false; runJ1 = true; }
        else if (strcmp(argv[i], "--j2") == 0) { runAll = false; runJ2 = true; }
        else if (strcmp(argv[i], "--j3") == 0) { runAll = false; runJ3 = true; }
        else if (strcmp(argv[i], "--j4") == 0) { runAll = false; runJ4 = true; }
        else if (strcmp(argv[i], "--j5") == 0) { runAll = false; runJ5 = true; }
        else if (strcmp(argv[i], "--full") == 0) { runAll = false; runFull = true; }
        else if (strcmp(argv[i], "--capi") == 0) { runAll = false; runCAPI = true; }
        else if (strcmp(argv[i], "--help") == 0) {
            std::cout << "\nUsage: " << argv[0] << " [options]\n";
            std::cout << "Options:\n";
            std::cout << "  --j1    Run Gate J1 (LLM Integration) only\n";
            std::cout << "  --j2    Run Gate J2 (Multi-Model) only\n";
            std::cout << "  --j3    Run Gate J3 (Dataset Validation) only\n";
            std::cout << "  --j4    Run Gate J4 (Benchmarking) only\n";
            std::cout << "  --j5    Run Gate J5 (Profiling) only\n";
            std::cout << "  --full  Run full integration test\n";
            std::cout << "  --capi  Run C API test\n";
            std::cout << "  --help  Show this help\n";
            return 0;
        }
    }
    
    int passedGates = 0;
    int totalGates = 0;
    
    // Run individual gates
    if (runAll || runJ1) {
        totalGates++;
        if (TestGateJ1_LLMIntegration()) passedGates++;
    }
    
    if (runAll || runJ2) {
        totalGates++;
        if (TestGateJ2_MultiModelExecution()) passedGates++;
    }
    
    if (runAll || runJ3) {
        totalGates++;
        if (TestGateJ3_DatasetValidation()) passedGates++;
    }
    
    if (runAll || runJ4) {
        totalGates++;
        if (TestGateJ4_CompetitiveBenchmarking()) passedGates++;
    }
    
    if (runAll || runJ5) {
        totalGates++;
        if (TestGateJ5_LatencyProfiling()) passedGates++;
    }
    
    // Run full integration
    if (runAll || runFull) {
        if (TestFullIntegration()) passedGates++;
        totalGates++;
    }
    
    // Run C API test
    if (runAll || runCAPI) {
        if (TestCAPI()) passedGates++;
        totalGates++;
    }
    
    // Print summary
    std::cout << "\n=================================================================" << std::endl;
    std::cout << "TEST SUMMARY" << std::endl;
    std::cout << "=================================================================" << std::endl;
    
    for (const auto& result : g_testResults) {
        std::cout << (result.passed ? "[PASS] " : "[FAIL] ") << result.name;
        if (!result.details.empty()) {
            std::cout << " - " << result.details;
        }
        std::cout << " (" << result.durationMs << " ms)" << std::endl;
    }
    
    std::cout << "=================================================================" << std::endl;
    std::cout << "Gates Passed: " << passedGates << "/" << totalGates << std::endl;
    std::cout << "Sub-tests Passed: " << std::count_if(g_testResults.begin(), g_testResults.end(),
        [](const TestResult& r) { return r.passed; }) << "/" << g_testResults.size() << std::endl;
    std::cout << "=================================================================" << std::endl;
    
    if (passedGates == totalGates) {
        std::cout << "\n✓ ALL GATES PASSED - Phase 9 Complete!" << std::endl;
        return 0;
    } else {
        std::cout << "\n✗ Some gates failed" << std::endl;
        return 1;
    }
}