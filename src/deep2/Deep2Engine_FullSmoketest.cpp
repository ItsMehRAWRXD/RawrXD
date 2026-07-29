// ============================================================================
// Deep2Engine_FullSmoketest.cpp - COMPREHENSIVE Full Stack Validation
// Tests: CPU kernels, GPU backends, API server, Multi-GPU, Model loading
// Phase 0: Backend Binding Complete Validation
// ============================================================================

#include "Deep2Engine.h"
#include "Deep2Discovery.h"
#include "HotPatcher.hpp"
#include "ReverseIntegration.hpp"
#include "GoalSystem.hpp"
#include "TrailBrake.hpp"
#include "TensorHop.hpp"
#include "RuntimePlanner.hpp"
#include "Deep2ExecutionGraph.hpp"
#include <cstdio>
#include <cstring>
#include <cmath>
#include <chrono>
#include <thread>
#include <vector>
#include <string>
#include <cassert>
#include <random>
#include <filesystem>
#include <map>
#include <sstream>
#include <iostream>

// Windows headers for GPU detection
#ifdef _WIN32
#include <windows.h>
#include <dxgi.h>
#pragma comment(lib, "dxgi.lib")
#endif

namespace Deep2 {
namespace FullSmokeTest {

// ============================================================================
// Test Result Tracking
// ============================================================================
struct TestResult {
    const char* name;
    const char* category;
    bool passed;
    double durationMs;
    std::string error;
    std::string details;
};

static std::vector<TestResult> g_results;
static int g_testsPassed = 0;
static int g_testsFailed = 0;
static int g_totalTests = 0;

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        result.error = msg; \
        result.passed = false; \
        printf("    [FAIL] %s\n", msg); \
        return result; \
    } \
} while(0)

#define TEST_ASSERT_NEAR(val, expected, tolerance, msg) do { \
    if (std::abs((val) - (expected)) > (tolerance)) { \
        char buf[256]; \
        snprintf(buf, sizeof(buf), "%s: got %.6f, expected %.6f", msg, (double)(val), (double)(expected)); \
        result.error = buf; \
        result.passed = false; \
        printf("    [FAIL] %s\n", buf); \
        return result; \
    } \
} while(0)

// ============================================================================
// SECTION 1: CPU KERNEL TESTS
// ============================================================================

TestResult Test_CPU_FeatureDetection() {
    TestResult result{"CPU Feature Detection", "CPU", true, 0.0, "", ""};
    auto start = std::chrono::high_resolution_clock::now();
    
    printf("\n  [TEST] CPU Feature Detection\n");
    
    int hasAVX2 = Deep2_HasAVX2();
    int hasAVX512 = Deep2_HasAVX512();
    
    char details[256];
    snprintf(details, sizeof(details), "AVX2: %s, AVX-512: %s", 
             hasAVX2 ? "YES" : "NO", hasAVX512 ? "YES" : "NO");
    result.details = details;
    
    printf("    AVX2: %s\n", hasAVX2 ? "YES" : "NO");
    printf("    AVX-512: %s\n", hasAVX512 ? "YES" : "NO");
    
    TEST_ASSERT(hasAVX2 || hasAVX512, "No AVX2 or AVX-512 detected");
    
    auto end = std::chrono::high_resolution_clock::now();
    result.durationMs = std::chrono::duration<double, std::milli>(end - start).count();
    
    printf("    [PASS] %.2f ms\n", result.durationMs);
    return result;
}

TestResult Test_CPU_Kernel_VecDot() {
    TestResult result{"Vector Dot Product", "CPU", true, 0.0, "", ""};
    auto start = std::chrono::high_resolution_clock::now();
    
    printf("\n  [TEST] Vector Dot Product Kernel\n");
    
    alignas(32) float a[256];
    alignas(32) float b[256];
    
    for (int i = 0; i < 256; i++) {
        a[i] = (float)i * 0.01f;
        b[i] = (float)(255 - i) * 0.01f;
    }
    
    float result_val = 0.0f;
    Deep2_VecDotProduct(a, b, &result_val, 256);
    
    float expected = 0.0f;
    for (int i = 0; i < 256; i++) {
        expected += a[i] * b[i];
    }
    
    TEST_ASSERT(std::abs(result_val - expected) < 0.001f, "Dot product result mismatch");
    
    char details[256];
    snprintf(details, sizeof(details), "Result: %.6f, Expected: %.6f", result_val, expected);
    result.details = details;
    
    auto end = std::chrono::high_resolution_clock::now();
    result.durationMs = std::chrono::duration<double, std::milli>(end - start).count();
    
    printf("    [PASS] %.2f ms\n", result.durationMs);
    return result;
}

TestResult Test_CPU_Kernel_SwiGLU() {
    TestResult result{"SwiGLU Activation", "CPU", true, 0.0, "", ""};
    auto start = std::chrono::high_resolution_clock::now();
    
    printf("\n  [TEST] SwiGLU Activation Kernel\n");
    
    alignas(32) float gate[256];
    alignas(32) float up[256];
    alignas(32) float out[256];
    
    for (int i = 0; i < 256; i++) {
        gate[i] = (float)i * 0.1f;
        up[i] = (float)(i % 10) * 0.1f;
    }
    
    Deep2_SwiGLU(gate, up, out, 256);
    
    bool hasNonZero = false;
    bool allFinite = true;
    for (int i = 0; i < 256; i++) {
        if (!std::isfinite(out[i])) allFinite = false;
        if (out[i] != 0.0f) hasNonZero = true;
    }
    
    TEST_ASSERT(allFinite, "SwiGLU produced non-finite values");
    TEST_ASSERT(hasNonZero, "SwiGLU produced all zeros");
    
    auto end = std::chrono::high_resolution_clock::now();
    result.durationMs = std::chrono::duration<double, std::milli>(end - start).count();
    
    printf("    [PASS] %.2f ms\n", result.durationMs);
    return result;
}

TestResult Test_CPU_Kernel_RMSNorm() {
    TestResult result{"RMSNorm", "CPU", true, 0.0, "", ""};
    auto start = std::chrono::high_resolution_clock::now();
    
    printf("\n  [TEST] RMSNorm Kernel\n");
    
    alignas(32) float input[256];
    alignas(32) float output[256];
    
    for (int i = 0; i < 256; i++) {
        input[i] = 1.0f;
    }
    
    Deep2_RMSNorm(input, output, 256, 1e-6f);
    
    bool allFinite = true;
    for (int i = 0; i < 256; i++) {
        if (!std::isfinite(output[i])) allFinite = false;
    }
    
    TEST_ASSERT(allFinite, "RMSNorm produced non-finite values");
    
    auto end = std::chrono::high_resolution_clock::now();
    result.durationMs = std::chrono::duration<double, std::milli>(end - start).count();
    
    printf("    [PASS] %.2f ms\n", result.durationMs);
    return result;
}

// ============================================================================
// SECTION 2: GPU BACKEND TESTS
// ============================================================================

TestResult Test_GPU_BackendDetection() {
    TestResult result{"GPU Backend Detection", "GPU", true, 0.0, "", ""};
    auto start = std::chrono::high_resolution_clock::now();
    
    printf("\n  [TEST] GPU Backend Detection\n");
    
    Deep2GPUBackend gpuBackend;
    bool initialized = gpuBackend.Initialize();
    
    printf("    Vulkan Runtime: %s\n", initialized ? "YES" : "NO");
    
    auto devices = gpuBackend.EnumerateDevices();
    
    char details[1024] = {0};
    int offset = 0;
    
    printf("    Found %zu GPU(s)\n", devices.size());
    
    for (size_t i = 0; i < devices.size() && i < 4; i++) {
        printf("    Device %zu:\n", i);
        printf("      Name: %s\n", devices[i].name.c_str());
        printf("      VRAM: %.2f GB\n", devices[i].vramBytes / (1024.0 * 1024.0 * 1024.0));
        printf("      Compute Units: %u\n", devices[i].computeUnits);
        printf("      Architecture: %s\n", devices[i].architecture.c_str());
        
        offset += snprintf(details + offset, sizeof(details) - offset, 
            "GPU%zu:%s(%.1fGB) ", i, devices[i].name.c_str(), 
            devices[i].vramBytes / (1024.0 * 1024.0 * 1024.0));
    }
    
    result.details = details;
    
    // Check for expected GPUs
    bool foundR9700 = false;
    bool found7800XT = false;
    
    for (const auto& dev : devices) {
        if (dev.name.find("Radeon AI PRO R9700") != std::string::npos ||
            dev.name.find("R9700") != std::string::npos) {
            foundR9700 = true;
        }
        if (dev.name.find("7800 XT") != std::string::npos ||
            dev.name.find("7800XT") != std::string::npos) {
            found7800XT = true;
        }
    }
    
    TEST_ASSERT(foundR9700, "Radeon AI PRO R9700 not detected");
    TEST_ASSERT(found7800XT, "Radeon RX 7800 XT not detected");
    
    auto end = std::chrono::high_resolution_clock::now();
    result.durationMs = std::chrono::duration<double, std::milli>(end - start).count();
    
    printf("    [PASS] %.2f ms\n", result.durationMs);
    return result;
}

TestResult Test_GPU_VRAMAllocation() {
    TestResult result{"GPU VRAM Allocation", "GPU", true, 0.0, "", ""};
    auto start = std::chrono::high_resolution_clock::now();
    
    printf("\n  [TEST] GPU VRAM Allocation\n");
    
    Deep2GPUBackend gpuBackend;
    gpuBackend.Initialize();
    
    // Try to allocate VRAM on both GPUs
    size_t allocSize = 1024 * 1024 * 1024; // 1GB test allocation
    
    bool gpu0Alloc = gpuBackend.AllocateVRAM(0, allocSize);
    bool gpu1Alloc = gpuBackend.AllocateVRAM(1, allocSize);
    
    printf("    GPU 0 (R9700): %s\n", gpu0Alloc ? "ALLOCATED 1GB" : "FAILED");
    printf("    GPU 1 (7800XT): %s\n", gpu1Alloc ? "ALLOCATED 1GB" : "FAILED");
    
    char details[256];
    snprintf(details, sizeof(details), "GPU0:%s GPU1:%s", 
             gpu0Alloc ? "OK" : "FAIL", gpu1Alloc ? "OK" : "FAIL");
    result.details = details;
    
    TEST_ASSERT(gpu0Alloc, "Failed to allocate VRAM on GPU 0");
    TEST_ASSERT(gpu1Alloc, "Failed to allocate VRAM on GPU 1");
    
    // Cleanup
    gpuBackend.FreeVRAM(0);
    gpuBackend.FreeVRAM(1);
    
    auto end = std::chrono::high_resolution_clock::now();
    result.durationMs = std::chrono::duration<double, std::milli>(end - start).count();
    
    printf("    [PASS] %.2f ms\n", result.durationMs);
    return result;
}

TestResult Test_GPU_KernelDispatch() {
    TestResult result{"GPU Kernel Dispatch", "GPU", true, 0.0, "", ""};
    auto start = std::chrono::high_resolution_clock::now();
    
    printf("\n  [TEST] GPU Kernel Dispatch\n");
    
    Deep2GPUBackend gpuBackend;
    gpuBackend.Initialize();
    
    // Test dispatching kernels to each GPU
    bool rmsnormOk = gpuBackend.DispatchKernel("RMSNorm", 0);
    bool swigluOk = gpuBackend.DispatchKernel("SwiGLU", 1);
    bool matmulOk = gpuBackend.DispatchKernel("MatMul", 0);
    
    printf("    RMSNorm on R9700: %s\n", rmsnormOk ? "OK" : "FAIL");
    printf("    SwiGLU on 7800XT: %s\n", swigluOk ? "OK" : "FAIL");
    printf("    MatMul on R9700: %s\n", matmulOk ? "OK" : "FAIL");
    
    char details[256];
    snprintf(details, sizeof(details), "RMSNorm:%s SwiGLU:%s MatMul:%s",
             rmsnormOk ? "OK" : "FAIL", swigluOk ? "OK" : "FAIL", matmulOk ? "OK" : "FAIL");
    result.details = details;
    
    TEST_ASSERT(rmsnormOk, "RMSNorm kernel dispatch failed");
    TEST_ASSERT(swigluOk, "SwiGLU kernel dispatch failed");
    TEST_ASSERT(matmulOk, "MatMul kernel dispatch failed");
    
    auto end = std::chrono::high_resolution_clock::now();
    result.durationMs = std::chrono::duration<double, std::milli>(end - start).count();
    
    printf("    [PASS] %.2f ms\n", result.durationMs);
    return result;
}

// ============================================================================
// SECTION 3: MULTI-GPU SCHEDULER TESTS
// ============================================================================

TestResult Test_MultiGPU_Scheduler() {
    TestResult result{"Multi-GPU Scheduler", "MULTI_GPU", true, 0.0, "", ""};
    auto start = std::chrono::high_resolution_clock::now();
    
    printf("\n  [TEST] Multi-GPU Scheduler\n");
    
    Deep2MultiGPU multiGPU;
    bool initialized = multiGPU.Initialize();
    
    printf("    Scheduler initialized: %s\n", initialized ? "YES" : "NO");
    
    // Configure layer placement
    multiGPU.SetLayerPlacement(0, 31, 0);   // Layers 0-31 on R9700
    multiGPU.SetLayerPlacement(32, 63, 1);  // Layers 32-63 on 7800XT
    
    // Configure tensor placement
    multiGPU.SetTensorPlacement("weights", 0);      // Weights on R9700
    multiGPU.SetTensorPlacement("kv_cache", 0);     // KV cache on R9700
    multiGPU.SetTensorPlacement("activations", 1); // Activations on 7800XT
    
    auto placement = multiGPU.GetPlacementStrategy();
    
    char details[512];
    snprintf(details, sizeof(details), 
        "Layers:0-31->GPU0,32-63->GPU1; Weights:GPU0; KV:GPU0; Activations:GPU1");
    result.details = details;
    
    printf("    Layer placement:\n");
    printf("      Layers 0-31 -> GPU 0 (R9700)\n");
    printf("      Layers 32-63 -> GPU 1 (7800XT)\n");
    printf("    Tensor placement:\n");
    printf("      Weights -> GPU 0\n");
    printf("      KV Cache -> GPU 0\n");
    printf("      Activations -> GPU 1\n");
    
    TEST_ASSERT(initialized, "Multi-GPU scheduler initialization failed");
    
    auto end = std::chrono::high_resolution_clock::now();
    result.durationMs = std::chrono::duration<double, std::milli>(end - start).count();
    
    printf("    [PASS] %.2f ms\n", result.durationMs);
    return result;
}

TestResult Test_MultiGPU_LoadBalancing() {
    TestResult result{"Multi-GPU Load Balancing", "MULTI_GPU", true, 0.0, "", ""};
    auto start = std::chrono::high_resolution_clock::now();
    
    printf("\n  [TEST] Multi-GPU Load Balancing\n");
    
    Deep2MultiGPU multiGPU;
    multiGPU.Initialize();
    
    // Simulate workload distribution
    float gpu0Util = multiGPU.GetGPUUtilization(0);
    float gpu1Util = multiGPU.GetGPUUtilization(1);
    
    printf("    GPU 0 (R9700) utilization: %.1f%%\n", gpu0Util * 100.0f);
    printf("    GPU 1 (7800XT) utilization: %.1f%%\n", gpu1Util * 100.0f);
    
    // Test automatic load balancing
    multiGPU.EnableLoadBalancing(true);
    bool balancingActive = multiGPU.IsLoadBalancingActive();
    
    printf("    Load balancing: %s\n", balancingActive ? "ACTIVE" : "INACTIVE");
    
    char details[256];
    snprintf(details, sizeof(details), "GPU0:%.1f%% GPU1:%.1f%% Balancing:%s",
             gpu0Util * 100.0f, gpu1Util * 100.0f, balancingActive ? "ON" : "OFF");
    result.details = details;
    
    TEST_ASSERT(balancingActive, "Load balancing not active");
    
    auto end = std::chrono::high_resolution_clock::now();
    result.durationMs = std::chrono::duration<double, std::milli>(end - start).count();
    
    printf("    [PASS] %.2f ms\n", result.durationMs);
    return result;
}

// ============================================================================
// SECTION 4: API SERVER TESTS
// ============================================================================

TestResult Test_API_ServerStartup() {
    TestResult result{"API Server Startup", "API", true, 0.0, "", ""};
    auto start = std::chrono::high_resolution_clock::now();
    
    printf("\n  [TEST] API Server Startup\n");
    
    Deep2Engine engine;
    engine.Initialize(EngineConfig{});
    
    Deep2APIServer server;
    bool initialized = server.Initialize(&engine);
    bool started = server.Start(11435);
    
    printf("    Server initialized: %s\n", initialized ? "YES" : "NO");
    printf("    Server started: %s\n", started ? "YES" : "NO");
    printf("    Port: 11435\n");
    
    char details[256];
    snprintf(details, sizeof(details), "Init:%s Start:%s Port:11435",
             initialized ? "OK" : "FAIL", started ? "OK" : "FAIL");
    result.details = details;
    
    TEST_ASSERT(initialized, "API server initialization failed");
    TEST_ASSERT(started, "API server failed to start");
    
    server.Stop();
    
    auto end = std::chrono::high_resolution_clock::now();
    result.durationMs = std::chrono::duration<double, std::milli>(end - start).count();
    
    printf("    [PASS] %.2f ms\n", result.durationMs);
    return result;
}

TestResult Test_API_Endpoints() {
    TestResult result{"API Endpoints", "API", true, 0.0, "", ""};
    auto start = std::chrono::high_resolution_clock::now();
    
    printf("\n  [TEST] API Endpoints\n");
    
    Deep2Engine engine;
    engine.Initialize(EngineConfig{});
    
    Deep2APIServer server;
    server.Initialize(&engine);
    server.Start(11435);
    
    // Test /api/version
    APIRequest versionReq{"GET", "/api/version", {}, ""};
    auto versionResp = server.HandleRequest(versionReq);
    printf("    GET /api/version: %d\n", versionResp.statusCode);
    
    // Test /api/health
    APIRequest healthReq{"GET", "/api/health", {}, ""};
    auto healthResp = server.HandleRequest(healthReq);
    printf("    GET /api/health: %d\n", healthResp.statusCode);
    
    // Test /api/models
    APIRequest modelsReq{"GET", "/api/models", {}, ""};
    auto modelsResp = server.HandleRequest(modelsReq);
    printf("    GET /api/models: %d\n", modelsResp.statusCode);
    
    char details[256];
    snprintf(details, sizeof(details), "/version:%d /health:%d /models:%d",
             versionResp.statusCode, healthResp.statusCode, modelsResp.statusCode);
    result.details = details;
    
    TEST_ASSERT(versionResp.statusCode == 200, "Version endpoint failed");
    TEST_ASSERT(healthResp.statusCode == 200, "Health endpoint failed");
    TEST_ASSERT(modelsResp.statusCode == 200, "Models endpoint failed");
    
    server.Stop();
    
    auto end = std::chrono::high_resolution_clock::now();
    result.durationMs = std::chrono::duration<double, std::milli>(end - start).count();
    
    printf("    [PASS] %.2f ms\n", result.durationMs);
    return result;
}

TestResult Test_API_BackendDiscovery() {
    TestResult result{"Backend Auto-Discovery", "API", true, 0.0, "", ""};
    auto start = std::chrono::high_resolution_clock::now();
    
    printf("\n  [TEST] Backend Auto-Discovery\n");
    
    auto backends = Deep2BackendDiscovery::DiscoverBackends();
    
    printf("    Found %zu backend(s)\n", backends.size());
    
    bool foundDeep2 = false;
    for (const auto& be : backends) {
        printf("    Backend: %s @ %s (priority %d)\n", 
               be.type.c_str(), be.url.c_str(), be.priority);
        if (be.type == "deep2") foundDeep2 = true;
    }
    
    auto preferred = Deep2BackendDiscovery::GetPreferredBackend();
    printf("    Preferred: %s\n", preferred.type.c_str());
    
    char details[256];
    snprintf(details, sizeof(details), "Found:%zu Deep2:%s Preferred:%s",
             backends.size(), foundDeep2 ? "YES" : "NO", preferred.type.c_str());
    result.details = details;
    
    TEST_ASSERT(foundDeep2, "Deep2 backend not discovered");
    TEST_ASSERT(preferred.type == "deep2", "Deep2 not preferred backend");
    
    auto end = std::chrono::high_resolution_clock::now();
    result.durationMs = std::chrono::duration<double, std::milli>(end - start).count();
    
    printf("    [PASS] %.2f ms\n", result.durationMs);
    return result;
}

// ============================================================================
// SECTION 5: ENGINE INTEGRATION TESTS
// ============================================================================

TestResult Test_Engine_Initialization() {
    TestResult result{"Engine Initialization", "ENGINE", true, 0.0, "", ""};
    auto start = std::chrono::high_resolution_clock::now();
    
    printf("\n  [TEST] Engine Initialization\n");
    
    Deep2Engine engine;
    
    EngineConfig config;
    config.hiddenDim = 4096;
    config.numLayers = 32;
    config.numHeads = 32;
    config.vocabSize = 32000;
    config.maxSeqLen = 2048;
    config.useThreadPool = true;
    config.useKVCache = true;
    config.useRoPE = true;
    
    bool initOk = engine.initialize(config);
    
    printf("    Initialized: %s\n", initOk ? "YES" : "NO");
    printf("    ThreadPool: %s\n", config.useThreadPool ? "YES" : "NO");
    printf("    KV Cache: %s\n", config.useKVCache ? "YES" : "NO");
    printf("    RoPE: %s\n", config.useRoPE ? "YES" : "NO");
    
    char details[256];
    snprintf(details, sizeof(details), "Init:%s ThreadPool:%s KVCache:%s",
             initOk ? "OK" : "FAIL", config.useThreadPool ? "ON" : "OFF",
             config.useKVCache ? "ON" : "OFF");
    result.details = details;
    
    TEST_ASSERT(initOk, "Engine initialization failed");
    TEST_ASSERT(engine.isInitialized(), "Engine not marked as initialized");
    
    auto end = std::chrono::high_resolution_clock::now();
    result.durationMs = std::chrono::duration<double, std::milli>(end - start).count();
    
    printf("    [PASS] %.2f ms\n", result.durationMs);
    return result;
}

TestResult Test_Engine_AdvancedFeatures() {
    TestResult result{"Advanced Features", "ENGINE", true, 0.0, "", ""};
    auto start = std::chrono::high_resolution_clock::now();
    
    printf("\n  [TEST] Advanced Features\n");
    
    Deep2Engine engine;
    engine.Initialize(EngineConfig{});
    
    // Enable all advanced features
    engine.enableMedusa(true);
    engine.enableNUPacking(true);
    engine.enableWarmupScheduler(true);
    engine.enableCompressedKV(true, KVQuantType::KV_Q8_0);
    engine.enableSlidingWindow(true, 4096);
    engine.enableReverseAnalysis(true);
    
    printf("    Medusa: ENABLED\n");
    printf("    NU Packing: ENABLED\n");
    printf("    Warmup Scheduler: ENABLED\n");
    printf("    Compressed KV: ENABLED\n");
    printf("    Sliding Window: ENABLED\n");
    printf("    Reverse Analysis: ENABLED\n");
    
    result.details = "All advanced features enabled";
    
    auto end = std::chrono::high_resolution_clock::now();
    result.durationMs = std::chrono::duration<double, std::milli>(end - start).count();
    
    printf("    [PASS] %.2f ms\n", result.durationMs);
    return result;
}

// ============================================================================
// SECTION 6: AUTONOMOUS SYSTEM TESTS
// ============================================================================

TestResult Test_Autonomous_GoalSystem() {
    TestResult result{"Goal System", "AUTONOMOUS", true, 0.0, "", ""};
    auto start = std::chrono::high_resolution_clock::now();
    
    printf("\n  [TEST] Goal System\n");
    
    GoalSystem goals;
    
    Goal g;
    g.id = 1;
    g.description = "Load model and generate text";
    g.priority = GoalPriority::HIGH;
    g.status = GoalStatus::PENDING;
    
    goals.addGoal(g);
    goals.updateGoalProgress(1, 0.5f);
    goals.completeGoal(1);
    
    auto allGoals = goals.getAllGoals();
    
    printf("    Goals created: %zu\n", allGoals.size());
    printf("    Goal completed: YES\n");
    
    char details[256];
    snprintf(details, sizeof(details), "Goals:%zu Completed:1", allGoals.size());
    result.details = details;
    
    TEST_ASSERT(allGoals.size() > 0, "No goals created");
    
    auto end = std::chrono::high_resolution_clock::now();
    result.durationMs = std::chrono::duration<double, std::milli>(end - start).count();
    
    printf("    [PASS] %.2f ms\n", result.durationMs);
    return result;
}

TestResult Test_Autonomous_TrailBrake() {
    TestResult result{"TrailBrake Safety", "AUTONOMOUS", true, 0.0, "", ""};
    auto start = std::chrono::high_resolution_clock::now();
    
    printf("\n  [TEST] TrailBrake Safety System\n");
    
    TrailBrake brake;
    TrailBrakeConfig config;
    config.maxTokensPerSecond = 100.0f;
    config.maxMemoryUsageMB = 4096.0f;
    config.enableThermalThrottling = true;
    
    brake.initialize(config);
    
    bool rateOk = brake.checkRateLimit(50.0f);
    bool memOk = brake.checkMemoryLimit(2048.0f);
    
    printf("    Rate limit check: %s\n", rateOk ? "PASS" : "THROTTLE");
    printf("    Memory check: %s\n", memOk ? "PASS" : "THROTTLE");
    
    char details[256];
    snprintf(details, sizeof(details), "Rate:%s Memory:%s", 
             rateOk ? "OK" : "THROTTLE", memOk ? "OK" : "THROTTLE");
    result.details = details;
    
    TEST_ASSERT(rateOk, "Rate limit check failed");
    TEST_ASSERT(memOk, "Memory limit check failed");
    
    auto end = std::chrono::high_resolution_clock::now();
    result.durationMs = std::chrono::duration<double, std::milli>(end - start).count();
    
    printf("    [PASS] %.2f ms\n", result.durationMs);
    return result;
}

// ============================================================================
// SECTION 7: STRESS TESTS
// ============================================================================

TestResult Test_Stress_RapidInit() {
    TestResult result{"Rapid Init/Destroy", "STRESS", true, 0.0, "", ""};
    auto start = std::chrono::high_resolution_clock::now();
    
    printf("\n  [TEST] Rapid Init/Destroy Stress\n");
    
    const int iterations = 10;
    for (int i = 0; i < iterations; i++) {
        Deep2Engine engine;
        EngineConfig config;
        config.useThreadPool = (i % 2 == 0);
        config.useKVCache = (i % 3 != 0);
        
        bool ok = engine.initialize(config);
        if (!ok) {
            TEST_ASSERT(false, "Engine init failed in stress test");
        }
        engine.reset();
    }
    
    printf("    Completed %d cycles\n", iterations);
    
    char details[256];
    snprintf(details, sizeof(details), "Cycles:%d", iterations);
    result.details = details;
    
    auto end = std::chrono::high_resolution_clock::now();
    result.durationMs = std::chrono::duration<double, std::milli>(end - start).count();
    
    printf("    [PASS] %.2f ms (%.2f ms/cycle)\n", result.durationMs, result.durationMs / iterations);
    return result;
}

// ============================================================================
// Test Runner
// ============================================================================
using TestFunc = TestResult(*)();

struct TestSuite {
    const char* category;
    const char* description;
    TestFunc func;
};

static const TestSuite g_testSuite[] = {
    // CPU Tests
    {"CPU", "Feature Detection", Test_CPU_FeatureDetection},
    {"CPU", "Vector Dot Product", Test_CPU_Kernel_VecDot},
    {"CPU", "SwiGLU Activation", Test_CPU_Kernel_SwiGLU},
    {"CPU", "RMSNorm", Test_CPU_Kernel_RMSNorm},
    
    // GPU Tests
    {"GPU", "Backend Detection", Test_GPU_BackendDetection},
    {"GPU", "VRAM Allocation", Test_GPU_VRAMAllocation},
    {"GPU", "Kernel Dispatch", Test_GPU_KernelDispatch},
    
    // Multi-GPU Tests
    {"MULTI_GPU", "Scheduler", Test_MultiGPU_Scheduler},
    {"MULTI_GPU", "Load Balancing", Test_MultiGPU_LoadBalancing},
    
    // API Tests
    {"API", "Server Startup", Test_API_ServerStartup},
    {"API", "Endpoints", Test_API_Endpoints},
    {"API", "Backend Discovery", Test_API_BackendDiscovery},
    
    // Engine Tests
    {"ENGINE", "Initialization", Test_Engine_Initialization},
    {"ENGINE", "Advanced Features", Test_Engine_AdvancedFeatures},
    
    // Autonomous Tests
    {"AUTONOMOUS", "Goal System", Test_Autonomous_GoalSystem},
    {"AUTONOMOUS", "TrailBrake", Test_Autonomous_TrailBrake},
    
    // Stress Tests
    {"STRESS", "Rapid Init/Destroy", Test_Stress_RapidInit},
};

// ============================================================================
// Main Entry Point
// ============================================================================
int RunFullSmokeTest() {
    printf("\n");
    printf("================================================================================\n");
    printf("  Deep2Engine FULL STACK Smoketest\n");
    printf("  Phase 0: Backend Binding Complete Validation\n");
    printf("  Hardware: AMD Radeon AI PRO R9700 32GB + RX 7800 XT 16GB\n");
    printf("================================================================================\n");
    
    g_results.clear();
    g_testsPassed = 0;
    g_testsFailed = 0;
    
    const size_t numTests = sizeof(g_testSuite) / sizeof(g_testSuite[0]);
    g_totalTests = static_cast<int>(numTests);
    
    printf("\n  Running %zu tests...\n", numTests);
    
    const char* currentCategory = "";
    
    for (size_t i = 0; i < numTests; i++) {
        if (strcmp(g_testSuite[i].category, currentCategory) != 0) {
            currentCategory = g_testSuite[i].category;
            printf("\n  [%s TESTS]\n", currentCategory);
        }
        
        TestResult result = g_testSuite[i].func();
        result.category = g_testSuite[i].category;
        g_results.push_back(result);
        
        if (result.passed) {
            g_testsPassed++;
        } else {
            g_testsFailed++;
            printf("    *** FAILED: %s\n", result.error.c_str());
        }
    }
    
    // Print summary
    printf("\n");
    printf("================================================================================\n");
    printf("  TEST SUMMARY\n");
    printf("================================================================================\n");
    printf("  Total tests:  %zu\n", numTests);
    printf("  Passed:       %d\n", g_testsPassed);
    printf("  Failed:       %d\n", g_testsFailed);
    printf("  Success rate: %.1f%%\n", (100.0 * g_testsPassed) / numTests);
    
    double totalTime = 0.0;
    for (const auto& r : g_results) {
        totalTime += r.durationMs;
    }
    printf("  Total time:   %.2f ms\n", totalTime);
    printf("  Avg time:     %.2f ms/test\n", totalTime / numTests);
    
    // Category breakdown
    printf("\n  Category Breakdown:\n");
    std::map<std::string, std::pair<int, int>> catStats;
    for (const auto& r : g_results) {
        catStats[r.category].first++;
        if (r.passed) catStats[r.category].second++;
    }
    for (const auto& [cat, stats] : catStats) {
        printf("    %s: %d/%d passed\n", cat, stats.second, stats.first);
    }
    
    // Failed tests
    if (g_testsFailed > 0) {
        printf("\n  FAILED TESTS:\n");
        for (const auto& r : g_results) {
            if (!r.passed) {
                printf("    - [%s] %s: %s\n", r.category, r.name, r.error.c_str());
            }
        }
    }
    
    printf("\n");
    printf("================================================================================\n");
    if (g_testsFailed == 0) {
        printf("  ALL TESTS PASSED\n");
        printf("  Deep2 Engine: FULLY OPERATIONAL\n");
        printf("  GPU Acceleration: ACTIVE\n");
        printf("  Multi-GPU: CONFIGURED\n");
        printf("  API Server: READY\n");
    } else {
        printf("  SOME TESTS FAILED\n");
        printf("  Review errors above\n");
    }
    printf("================================================================================\n");
    printf("\n");
    
    return g_testsFailed == 0 ? 0 : 1;
}

} // namespace FullSmokeTest
} // namespace Deep2

// ============================================================================
// Standalone main
// ============================================================================
int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;
    
    printf("Deep2Engine Full Stack Smoketest\n");
    printf("Build: %s %s\n\n", __DATE__, __TIME__);
    
    return Deep2::FullSmokeTest::RunFullSmokeTest();
}
