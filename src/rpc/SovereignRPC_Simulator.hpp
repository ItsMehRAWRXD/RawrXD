/*===========================================================================
 * SovereignRPC_Simulator.hpp
 *
 * Local distributed simulator for testing scheduler without network
 *
 * Simulates multiple nodes on single machine:
 *   - Node A: 48GB VRAM, Q4/Q5/Q6 capable
 *   - Node B: 24GB VRAM, Q4/Q5 capable
 *   - Node C: 80GB VRAM, Q4/Q5/Q6/Q8 capable
 *
 * Validates:
 *   - Scheduler decisions
 *   - Failover behavior
 *   - Quantization fallback
 *   - Load balancing
 *   - Model residency tracking
 *
 * Usage:
 *   Simulator sim;
 *   sim.Initialize();
 *   sim.AddNode("node-a", 48000, {Q4_K_M, Q5_K_M, Q6_K});
 *   sim.AddNode("node-b", 24000, {Q4_K_M, Q5_K_M});
 *   sim.RunTest("70B_Q6_Routing");
 *===========================================================================*/

#pragma once

#include "SovereignRPC_Scheduler.hpp"
#include "SovereignRPC_AdmissionController.hpp"
#include <vector>
#include <string>
#include <memory>
#include <random>

namespace RawrXD {
namespace RPC {

/*===========================================================================
 * Lease-Based Reservation System
 * Prevents VRAM accounting race conditions
 *===========================================================================*/
#ifndef MAX_CONCURRENT_LEASES
#define MAX_CONCURRENT_LEASES 256
#endif

struct Lease {
    uint64_t leaseId;
    std::string modelHash;
    uint64_t reservedVRAM_MB;
    Deep2::QuantType format;
    bool isActive;
    std::chrono::steady_clock::time_point grantedTime;
};

/*===========================================================================
 * Simulated Node
 *===========================================================================*/
struct SimulatedNode {
    std::string nodeId;
    std::string address;
    uint64_t totalVRAM_MB;
    uint64_t freeVRAM_MB;
    std::vector<Deep2::QuantType> supportedFormats;
    std::vector<std::string> loadedModels;
    float currentLoad;
    uint32_t tokensPerSecond;
    bool healthy;
    bool shouldFailNextRequest;  // For testing failover

    // Lease management
    Lease activeLeases[MAX_CONCURRENT_LEASES];
    uint32_t activeLeaseCount = 0;
    uint64_t nextLeaseId = 1;

    // Simulate model loading (takes time)
    bool LoadModel(const std::string& modelHash, Deep2::QuantType format);
    bool UnloadModel(const std::string& modelHash);

    // Lease-based reservation (NEW)
    // Returns lease ID (0 = denied)
    uint64_t RequestLease(const std::string& modelHash,
                          Deep2::QuantType format,
                          uint64_t requiredVRAM_MB);
    bool ExecuteWithLease(uint64_t leaseId, const InferenceRequest& request);
    void ReleaseLease(uint64_t leaseId);
    void CleanupExpiredLeases(uint32_t maxAgeSeconds = 30);

    // Simulate inference (legacy - for comparison)
    struct SimulatedResult {
        bool success;
        uint32_t tokensGenerated;
        uint64_t inferenceTimeMs;
        std::string errorMessage;
    };
    SimulatedResult Execute(const InferenceRequest& request);

private:
    bool PerformInference(const InferenceRequest& request);
};

/*===========================================================================
 * Test Scenario
 *===========================================================================*/
struct TestScenario {
    std::string name;
    std::string description;
    std::vector<std::string> setupNodes;  // Node IDs to create
    std::vector<std::string> preloadModels;  // Models to preload
    std::vector<InferenceRequest> requests;
    std::vector<std::string> expectedNodeAssignments;
    std::vector<Deep2::QuantType> expectedFormats;
    std::vector<bool> expectedSuccess;
};

/*===========================================================================
 * RPC Simulator
 *===========================================================================*/
class RPCSimulator {
public:
    static RPCSimulator& Instance();

    // Initialize simulator
    void Initialize();

    // Add simulated node
    void AddNode(const std::string& nodeId,
                 uint64_t vramMB,
                 const std::vector<Deep2::QuantType>& formats);

    // Remove simulated node
    void RemoveNode(const std::string& nodeId);

    // Preload model on node
    bool PreloadModel(const std::string& nodeId,
                      const std::string& modelHash,
                      Deep2::QuantType format);

    // Simulate node failure
    void SimulateNodeFailure(const std::string& nodeId);

    // Simulate node recovery
    void SimulateNodeRecovery(const std::string& nodeId);

    // Run single test scenario
    struct TestResult {
        bool passed;
        std::string failureReason;
        std::vector<std::string> actualNodeAssignments;
        std::vector<Deep2::QuantType> actualFormats;
        std::vector<bool> actualSuccess;
        uint64_t totalTimeMs;
    };
    TestResult RunScenario(const TestScenario& scenario);

    // Run all built-in tests
    void RunAllTests();

    // Built-in test scenarios
    static TestScenario CreateTest_70B_Q6_Routing();
    static TestScenario CreateTest_ModelResidency();
    static TestScenario CreateTest_QuantFallback();
    static TestScenario CreateTest_NodeFailover();
    static TestScenario CreateTest_LoadBalancing();
    static TestScenario CreateTest_VRAMConstraints();
    static TestScenario CreateTest_LeaseProtocol();  // NEW: Lease-before-Exec
    static TestScenario CreateTest_LeaseDenyCircuitBreaker();  // NEW: Circuit breaker on DENY

    // Generate report
    void GenerateReport(const std::string& filename);

    // Lease-based execution (NEW)
    struct LeaseExecutionResult {
        bool success;
        uint64_t leaseId;
        std::string errorMessage;
        std::string fallbackNodeId;  // Set if primary denied
    };
    LeaseExecutionResult ExecuteWithLease(const std::string& nodeId,
                                          const InferenceRequest& request);

private:
    RPCSimulator() = default;

    std::unordered_map<std::string, std::unique_ptr<SimulatedNode>> nodes_;
    std::mt19937 rng_{42};  // Deterministic for reproducibility

    void RegisterNodesWithScheduler();
    void SimulateHeartbeat(const std::string& nodeId);
};

/*===========================================================================
 * Test Results Reporter
 *===========================================================================*/
class TestReporter {
public:
    struct TestRun {
        std::string name;
        bool passed;
        uint64_t durationMs;
        std::string details;
    };

    void AddResult(const TestRun& result);
    void PrintSummary();
    void SaveToFile(const std::string& filename);

    size_t GetPassCount() const { return passCount_; }
    size_t GetFailCount() const { return failCount_; }

private:
    std::vector<TestRun> results_;
    size_t passCount_ = 0;
    size_t failCount_ = 0;
};

} // namespace RPC
} // namespace RawrXD

/*===========================================================================
 * C API for Test Runner
 *===========================================================================*/

extern "C" {

// Initialize simulator
__declspec(dllexport)
int SovereignSim_Init(void);

// Add node
__declspec(dllexport)
int SovereignSim_AddNode(const char* nodeId, uint64_t vramMB,
                         int* formats, int numFormats);

// Run built-in tests
__declspec(dllexport)
int SovereignSim_RunTests(char* outReport, size_t reportSize);

// Run specific test
__declspec(dllexport)
int SovereignSim_RunTest(const char* testName, char* outResult, size_t resultSize);

} // extern "C"
