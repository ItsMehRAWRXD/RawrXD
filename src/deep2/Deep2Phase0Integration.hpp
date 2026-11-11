// ============================================================================
// Deep2Phase0Integration.hpp - Phase 0: IDE ↔ Deep2 API Binding
// 
// This is the HIGHEST LEVERAGE integration that enables the full sovereign loop:
//   RawrXD IDE → Agentic Copilot Bridge → Deep2 API Gateway → Sovereign Runtime
//
// Removes Ollama fallback assumptions. Makes Deep2 authoritative.
// ============================================================================

#pragma once

#include "Deep2Discovery.h"
#include "Deep2APIServer.hpp"
#include <string>
#include <memory>
#include <functional>
#include <vector>
#include <atomic>
#include <thread>
#include <mutex>
#include <condition_variable>

namespace Deep2 {
namespace Phase0 {

// ============================================================================
// Phase 0 Configuration
// ============================================================================
struct Phase0Config {
    // Canonical Deep2 port (replaces scattered Ollama ports)
    int apiPort = 11435;
    
    // Deep2 native engine port
    int enginePort = 11436;
    
    // Auto-discovery settings
    bool enableAutoDiscovery = true;
    int discoveryTimeoutMs = 2000;
    
    // GPU backend preferences
    bool preferGPU = true;
    std::string preferredGPUName = "Radeon";  // RX 7800 XT, R9700 AI PRO
    
    // Fallback (disabled by default in Phase 0)
    bool allowOllamaFallback = false;
    
    // Hardware reporting
    bool exposeHardwareDetails = true;
};

// ============================================================================
// Hardware Information (for demo/investor proof)
// ============================================================================
struct GPUDeviceInfo {
    int index;
    std::string name;
    std::string backend;           // "Vulkan", "HIP", "CUDA"
    uint64_t vramBytes;
    uint64_t vramUsedBytes;
    uint32_t computeUnits;
    std::string architecture;    // "RDNA3", "CDNA3", etc.
    bool available;
    float utilizationPercent;
};

struct HardwareInfo {
    std::vector<GPUDeviceInfo> gpus;
    size_t systemRAM;
    size_t availableRAM;
    std::string cpuName;
    int cpuCores;
    bool avx512Supported;
};

// ============================================================================
// API Response Types (Ollama-compatible but Deep2-native)
// ============================================================================
struct VersionResponse {
    std::string version;
    std::string engine;          // "Deep2"
    std::string runtime;         // "Sovereign"
    bool native;
    std::vector<std::string> capabilities;
};

struct BackendInfo {
    std::string name;            // "CPU AVX2", "Vulkan RX7800XT", etc.
    std::string type;          // "cpu", "vulkan", "hip"
    bool available;
    std::string status;        // "ready", "busy", "offline"
};

struct ModelInfo {
    std::string id;
    std::string name;
    std::string path;
    size_t parameterCount;
    size_t contextLength;
    std::string quantization;  // "Q4_K_M", "Q8_0", etc.
    bool loaded;
    size_t vramUsageMB;
    std::string backend;       // Which backend is running it
};

struct GenerateRequest {
    std::string model;
    std::string prompt;
    int maxTokens = 2048;
    float temperature = 0.8f;
    float topP = 0.9f;
    int topK = 40;
    bool stream = true;
    std::vector<std::string> stopSequences;
};

struct GenerateResponse {
    std::string text;
    int tokensGenerated;
    double tokensPerSecond;
    double timeToFirstTokenMs;
    double totalLatencyMs;
    bool done;
    std::string finishReason;
    std::string model;
    std::string backend;       // Which backend served it
};

// ============================================================================
// Phase 0 Integration Core
// 
// The main class that binds IDE to Deep2. Replaces Ollama assumptions.
// ============================================================================
class Phase0Integration {
public:
    Phase0Integration();
    ~Phase0Integration();

    // Initialize with configuration
    bool Initialize(const Phase0Config& config = {});
    void Shutdown();
    bool IsInitialized() const { return initialized_.load(); }

    // ------------------------------------------------------------------------
    // Deep2 Discovery (Authoritative - No Ollama Fallback)
    // ------------------------------------------------------------------------
    
    // Discover available Deep2 backends
    std::vector<DiscoveredBackend> DiscoverBackends();
    
    // Get the preferred (highest priority) backend
    // Priority: Deep2 Native (11436) > Deep2 API (11435) > None
    DiscoveredBackend GetPreferredBackend();
    
    // Check if Deep2 is available (primary check)
    bool IsDeep2Available();
    
    // Get connection status
    std::string GetConnectionStatus() const;

    // ------------------------------------------------------------------------
    // Canonical API Endpoints (Port 11435)
    // ------------------------------------------------------------------------
    
    // GET /api/version
    VersionResponse GetVersion();
    
    // GET /api/health
    bool HealthCheck();
    
    // GET /api/backends
    std::vector<BackendInfo> GetBackends();
    
    // GET /api/models
    std::vector<ModelInfo> ListModels();
    
    // POST /api/models/load
    bool LoadModel(const std::string& modelId);
    
    // POST /api/models/unload
    bool UnloadModel(const std::string& modelId);
    
    // POST /api/generate
    GenerateResponse Generate(const GenerateRequest& request);
    
    // POST /api/chat (streaming)
    void ChatStream(const GenerateRequest& request, 
                    std::function<void(const std::string& chunk)> onToken,
                    std::function<void(const GenerateResponse& final)> onComplete);
    
    // GET /api/hardware
    HardwareInfo GetHardwareInfo();

    // ------------------------------------------------------------------------
    // Hardware Proof (for demo/investor visibility)
    // ------------------------------------------------------------------------
    
    // Enumerate GPU devices with full details
    std::vector<GPUDeviceInfo> EnumerateGPUs();
    
    // Get formatted hardware summary for display
    std::string GetHardwareSummary();
    
    // Check specific GPU availability
    bool IsGPUAvailable(const std::string& gpuNameSubstring);

    // ------------------------------------------------------------------------
    // IDE Bridge Integration
    // ------------------------------------------------------------------------
    
    // Connect IDE to Deep2 (replaces Ollama connection)
    bool ConnectIDE();
    
    // Get the API base URL for IDE configuration
    std::string GetAPIBaseUrl() const;
    
    // Set callback for connection status changes
    void SetStatusCallback(std::function<void(const std::string& status)> cb);

    // ------------------------------------------------------------------------
    // Streaming Support
    // ------------------------------------------------------------------------
    
    using TokenCallback = std::function<void(const std::string& token)>;
    using CompleteCallback = std::function<void(bool success)>;
    
    // Start streaming generation
    bool StartStream(const GenerateRequest& request, 
                     TokenCallback onToken,
                     CompleteCallback onComplete);
    
    // Cancel current stream
    void CancelStream();
    bool IsStreaming() const { return streaming_.load(); }

private:
    Phase0Config config_;
    std::atomic<bool> initialized_{false};
    std::atomic<bool> streaming_{false};
    std::atomic<bool> cancelFlag_{false};
    
    std::unique_ptr<Deep2APIServer> apiServer_;
    std::unique_ptr<Deep2BackendClient> backendClient_;
    
    std::string activeBackendUrl_;
    std::string activeModelId_;
    
    std::thread streamThread_;
    std::mutex mutex_;
    std::condition_variable cv_;
    
    std::function<void(const std::string&)> statusCallback_;
    
    // Internal helpers
    bool StartAPIServer();
    bool ConnectToBackend();
    void UpdateStatus(const std::string& status);
    
    // HTTP helpers
    std::string HttpGet(const std::string& url);
    std::string HttpPost(const std::string& url, const std::string& body);
};

// ============================================================================
// Phase 0 Smoketest
// 
// Validates the full sovereign loop:
//   [PASS] Deep2 Discovery
//   [PASS] API Server Start
//   [PASS] Model Loading
//   [PASS] Token Generation
//   [PASS] GPU Acceleration
//   [PASS] IDE Bridge
// ============================================================================
class Phase0Smoketest {
public:
    struct TestResult {
        std::string name;
        bool passed;
        std::string message;
        double durationMs;
    };
    
    struct TestReport {
        std::vector<TestResult> results;
        int passedCount;
        int failedCount;
        double totalDurationMs;
        bool allPassed;
        std::string summary;
    };
    
    // Run full Phase 0 validation
    static TestReport RunAllTests();
    
    // Individual tests
    static TestResult TestDiscovery();
    static TestResult TestAPIServer();
    static TestResult TestHardwareDetection();
    static TestResult TestModelLoading();
    static TestResult TestTokenGeneration();
    static TestResult TestStreaming();
    static TestResult TestIDEBridge();
    
    // Generate certification report
    static std::string GenerateCertificationReport(const TestReport& report);
};

// ============================================================================
// Convenience Functions
// ============================================================================

// Quick-start: Initialize and connect IDE to Deep2
inline bool InitializePhase0(const Phase0Config& config = {}) {
    static Phase0Integration instance;
    return instance.Initialize(config);
}

// Get singleton instance
inline Phase0Integration& GetPhase0() {
    static Phase0Integration instance;
    return instance;
}

// Check if Phase 0 is ready (for IDE startup)
inline bool IsPhase0Ready() {
    return GetPhase0().IsInitialized() && GetPhase0().IsDeep2Available();
}

} // namespace Phase0
} // namespace Deep2

// ============================================================================
// Usage Example (for IDE integration)
// ============================================================================
/*
    // In IDE startup:
    Deep2::Phase0::Phase0Config config;
    config.apiPort = 11435;
    config.enginePort = 11436;
    config.allowOllamaFallback = false;  // Phase 0: Deep2 only
    
    if (Deep2::Phase0::InitializePhase0(config)) {
        std::cout << "Deep2 Phase 0 ready!" << std::endl;
        std::cout << GetPhase0().GetHardwareSummary() << std::endl;
    }
    
    // In agentic bridge (replaces Ollama calls):
    auto response = Deep2::Phase0::GetPhase0().Generate(request);
    
    // For streaming:
    Deep2::Phase0::GetPhase0().ChatStream(request, 
        [](const std::string& token) { /* render token */ },
        [](const auto& final) { /* done */ }
    );
*/
