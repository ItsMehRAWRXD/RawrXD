// =============================================================================
// TPS Benchmark Engine with Ghost Text Integration
// =============================================================================
// Measures tokens-per-second with real-time ghost text overlay
// Target: 20k TPS sustained throughput
// =============================================================================

#pragma once

#include "SovereignK_Client.h"
#include "inference_profiler_simple.h"
#include <cstdint.h>
#include <string.h>
#include <windows.h>

namespace rxdn {

// =============================================================================
// Configuration
// =============================================================================

struct TPSConfig {
    // Model parameters
    uint32_t    contextLength = 4096;
    uint32_t    batchSize = 1;
    uint32_t    numLayers = 32;
    uint32_t    hiddenSize = 4096;
    uint32_t    numHeads = 32;
    
    // Benchmark parameters
    uint32_t    warmupIterations = 10;
    uint32_t    benchmarkIterations = 100;
    uint32_t    maxTokens = 128;
    
    // Memory parameters
    uint64_t    hostArenaSize = 4ULL * 1024 * 1024 * 1024;  // 4GB
    uint64_t    vramTargetSize = 16ULL * 1024 * 1024 * 1024; // 16GB
    
    // Ghost text parameters
    bool        enableGhostText = true;
    uint32_t    ghostTextUpdateInterval = 16;  // Update every N tokens
    
    // Target
    float       targetTPS = 20000.0f;
};

// =============================================================================
// Benchmark Results
// =============================================================================

struct TPSResults {
    // Timing
    double      totalTimeMs;
    double      promptProcessingMs;
    double      tokenGenerationMs;
    double      avgTokenTimeMs;
    double      minTokenTimeMs;
    double      maxTokenTimeMs;
    double      p99TokenTimeMs;
    
    // Throughput
    float       actualTPS;
    float       targetTPS;
    float       efficiency;  // actual / target
    
    // Token counts
    uint32_t    promptTokens;
    uint32_t    generatedTokens;
    uint32_t    totalTokens;
    
    // Memory
    uint64_t    hostMemoryUsed;
    uint64_t    vramUsed;
    
    // Status
    bool        targetMet;
    const char* bottleneck;  // "compute", "memory", "pcie", "unknown"
};

// =============================================================================
// Ghost Text State
// =============================================================================

struct GhostTextState {
    // Current generation state
    char        currentToken[256];
    char        generatedText[8192];
    uint32_t    tokenCount;
    uint32_t    updateCount;
    
    // Performance overlay
    float       currentTPS;
    float       rollingTPS;
    uint64_t    lastUpdateTime;
    
    // Display buffer
    char        displayBuffer[16384];
    
    // Thread safety
    CRITICAL_SECTION lock;
    bool            initialized;
};

// =============================================================================
// TPS Benchmark Engine
// =============================================================================

class TPSBenchmarkEngine {
public:
    TPSBenchmarkEngine();
    ~TPSBenchmarkEngine();
    
    // Non-copyable
    TPSBenchmarkEngine(const TPSBenchmarkEngine&) = delete;
    TPSBenchmarkEngine& operator=(const TPSBenchmarkEngine&) = delete;
    
    // Initialization
    bool Initialize(const TPSConfig& config);
    void Shutdown();
    
    // Benchmark execution
    bool RunBenchmark(const char* modelPath, const char* prompt);
    const TPSResults& GetResults() const { return results_; }
    
    // Ghost text integration
    void EnableGhostText(bool enable);
    void UpdateGhostText(const char* token, float tps);
    const char* GetGhostTextDisplay() const;
    
    // Real-time metrics
    float GetCurrentTPS() const;
    float GetRollingTPS() const;
    
    // Results export
    bool ExportResults(const char* filename);
    void PrintResults();
    
private:
    TPSConfig       config_;
    TPSResults      results_;
    GhostTextState  ghostState_;
    
    // Driver interface
    SovereignKClient driver_;
    bool            driverConnected_;
    
    // Memory pools
    void*           hostArena_;
    uint64_t        vramBase_;
    
    // Timing
    LARGE_INTEGER   perfFreq_;
    LARGE_INTEGER   startTime_;
    
    // Token timing histogram
    double*         tokenTimes_;
    uint32_t        tokenTimeCount_;
    
    // Internal methods
    bool InitializeDriver();
    bool InitializeMemory();
    bool Warmup();
    bool RunInference(const char* prompt);
    void CalculateResults();
    void UpdateRollingTPS(double tokenTimeMs);
    
    // Ghost text rendering
    void RenderGhostOverlay();
    void ClearGhostText();
};

// =============================================================================
// Model Loader Interface
// =============================================================================

class TPSModelLoader {
public:
    // Load model weights into Sovereign Arena
    static bool LoadModelWeights(
        const char* ggufPath,
        void* hostArena,
        uint64_t arenaSize,
        uint64_t& outWeightsSize
        );
    
    // Upload weights to VRAM via SovereignK
    static bool UploadToVRAM(
        SovereignKClient& driver,
        void* hostWeights,
        uint64_t weightsSize,
        uint64_t vramOffset
        );
    
    // Get model info from GGUF
    static bool GetModelInfo(
        const char* ggufPath,
        TPSConfig& outConfig
        );
};

// =============================================================================
// Utility Functions
// =============================================================================

// High-resolution timing
inline double GetHighResTimeMs(LARGE_INTEGER freq) {
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    return (double)(now.QuadPart * 1000.0) / (double)freq.QuadPart;
}

// Calculate percentile from sorted array
double CalculatePercentile(double* sortedArray, size_t count, double percentile);

// Format bytes to human-readable
const char* FormatBytes(uint64_t bytes);

// Format TPS with color coding
const char* FormatTPS(float tps, float target);

} // namespace rxdn
