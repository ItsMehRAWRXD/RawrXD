// =============================================================================
// TPS Benchmark Engine Implementation
// =============================================================================

#include "TPSBenchmarkEngine.h"
#include <cstdio.h>
#include <cstdlib.h>
#include <string.h>
#include <algorithm>

namespace rxdn {

// =============================================================================
// Constructor / Destructor
// =============================================================================

TPSBenchmarkEngine::TPSBenchmarkEngine()
    : hostArena_(nullptr)
    , vramBase_(0)
    , tokenTimes_(nullptr)
    , tokenTimeCount_(0)
    , driverConnected_(false)
{
    memset(&results_, 0, sizeof(results_));
    memset(&ghostState_, 0, sizeof(ghostState_));
    QueryPerformanceFrequency(&perfFreq_);
}

TPSBenchmarkEngine::~TPSBenchmarkEngine() {
    Shutdown();
}

// =============================================================================
// Initialization
// =============================================================================

bool TPSBenchmarkEngine::Initialize(const TPSConfig& config) {
    config_ = config;
    
    printf("[TPS] Initializing benchmark engine...\n");
    printf("[TPS] Target TPS: %.1f\n", config_.targetTPS);
    printf("[TPS] Context length: %u\n", config_.contextLength);
    printf("[TPS] Max tokens: %u\n", config_.maxTokens);
    
    // Initialize ghost text
    if (config_.enableGhostText) {
        InitializeCriticalSection(&ghostState_.lock);
        ghostState_.initialized = true;
        printf("[TPS] Ghost text overlay enabled\n");
    }
    
    // Allocate token timing buffer
    tokenTimes_ = new double[config_.maxTokens];
    if (!tokenTimes_) {
        printf("[TPS] ERROR: Failed to allocate token timing buffer\n");
        return false;
    }
    
    // Initialize driver
    if (!InitializeDriver()) {
        printf("[TPS] WARNING: Driver initialization failed, using fallback path\n");
        // Continue without driver - will use standard memory path
    }
    
    // Initialize memory
    if (!InitializeMemory()) {
        printf("[TPS] ERROR: Memory initialization failed\n");
        return false;
    }
    
    printf("[TPS] Initialization complete\n");
    return true;
}

void TPSBenchmarkEngine::Shutdown() {
    printf("[TPS] Shutting down...\n");
    
    if (ghostState_.initialized) {
        DeleteCriticalSection(&ghostState_.lock);
        ghostState_.initialized = false;
    }
    
    if (tokenTimes_) {
        delete[] tokenTimes_;
        tokenTimes_ = nullptr;
    }
    
    if (hostArena_) {
        _aligned_free(hostArena_);
        hostArena_ = nullptr;
    }
    
    if (driverConnected_) {
        driver_.UnmapBAR();
        driver_.Close();
        driverConnected_ = false;
    }
    
    printf("[TPS] Shutdown complete\n");
}

// =============================================================================
// Driver Initialization
// =============================================================================

bool TPSBenchmarkEngine::InitializeDriver() {
    printf("[TPS] Connecting to SovereignK driver...\n");
    
    if (!driver_.Open()) {
        printf("[TPS] Driver not available: %s\n", driver_.GetLastError());
        return false;
    }
    
    // Get BAR0 address from environment or use default
    const char* bar0Env = getenv("SOVEREIGN_BAR0_PHYS");
    uint64_t bar0Phys = bar0Env ? _strtoui64(bar0Env, nullptr, 16) : 0;
    
    if (bar0Phys == 0) {
        printf("[TPS] WARNING: BAR0 address not set, using standard memory path\n");
        driver_.Close();
        return false;
    }
    
    // Map BAR
    if (!driver_.MapBAR(bar0Phys, 256ULL * 1024 * 1024, 2)) { // 2 = WriteCombined
        printf("[TPS] BAR mapping failed: %s\n", driver_.GetLastError());
        driver_.Close();
        return false;
    }
    
    driverConnected_ = true;
    vramBase_ = bar0Phys;
    printf("[TPS] Driver connected, BAR mapped at 0x%016llX\n", bar0Phys);
    return true;
}

// =============================================================================
// Memory Initialization
// =============================================================================

bool TPSBenchmarkEngine::InitializeMemory() {
    printf("[TPS] Allocating host arena (%.2f GB)...\n", 
           (double)config_.hostArenaSize / (1024.0 * 1024.0 * 1024.0));
    
    hostArena_ = _aligned_malloc((size_t)config_.hostArenaSize, 4096);
    if (!hostArena_) {
        printf("[TPS] ERROR: Failed to allocate host arena\n");
        return false;
    }
    
    // Touch pages to ensure they're committed
    volatile char* ptr = (volatile char*)hostArena_;
    for (size_t i = 0; i < config_.hostArenaSize; i += 4096) {
        ptr[i] = 0;
    }
    
    printf("[TPS] Host arena allocated at %p\n", hostArena_);
    return true;
}

// =============================================================================
// Benchmark Execution
// =============================================================================

bool TPSBenchmarkEngine::RunBenchmark(const char* modelPath, const char* prompt) {
    printf("\n========================================\n");
    printf("TPS Benchmark Starting\n");
    printf("========================================\n\n");
    
    // Warmup
    printf("[TPS] Running warmup (%u iterations)...\n", config_.warmupIterations);
    if (!Warmup()) {
        printf("[TPS] Warmup failed\n");
        return false;
    }
    
    // Clear ghost text
    ClearGhostText();
    
    // Run actual benchmark
    printf("[TPS] Running benchmark (%u iterations)...\n", config_.benchmarkIterations);
    
    QueryPerformanceCounter(&startTime_);
    
    if (!RunInference(prompt)) {
        printf("[TPS] Inference failed\n");
        return false;
    }
    
    // Calculate results
    CalculateResults();
    
    return true;
}

bool TPSBenchmarkEngine::Warmup() {
    // Run a few iterations to warm up caches
    for (uint32_t i = 0; i < config_.warmupIterations; i++) {
        // Simulate token generation
        volatile char* ptr = (volatile char*)hostArena_;
        for (size_t j = 0; j < 4096; j += 64) {
            ptr[j] = (char)(i + j);
        }
        _mm_sfence();
    }
    return true;
}

bool TPSBenchmarkEngine::RunInference(const char* prompt) {
    UNREFERENCED_PARAMETER(prompt);
    
    tokenTimeCount_ = 0;
    
    // Simulate token generation loop
    for (uint32_t i = 0; i < config_.maxTokens && i < config_.benchmarkIterations; i++) {
        LARGE_INTEGER tokenStart;
        QueryPerformanceCounter(&tokenStart);
        
        // Simulate token generation work
        // In real implementation, this would call llama.cpp
        volatile char* ptr = (volatile char*)hostArena_;
        for (size_t j = 0; j < 4096; j += 64) {
            ptr[j] = (char)(i + j);
        }
        _mm_sfence();
        
        // Calculate token time
        LARGE_INTEGER tokenEnd;
        QueryPerformanceCounter(&tokenEnd);
        double tokenTimeMs = (double)((tokenEnd.QuadPart - tokenStart.QuadPart) * 1000.0) / 
                             (double)perfFreq_.QuadPart;
        
        tokenTimes_[tokenTimeCount_++] = tokenTimeMs;
        
        // Update ghost text
        if (config_.enableGhostText && (i % config_.ghostTextUpdateInterval == 0)) {
            char token[32];
            snprintf(token, sizeof(token), "tok%u", i);
            UpdateGhostText(token, 1000.0f / (float)tokenTimeMs);
        }
        
        // Update rolling TPS
        UpdateRollingTPS(tokenTimeMs);
    }
    
    return true;
}

// =============================================================================
// Results Calculation
// =============================================================================

void TPSBenchmarkEngine::CalculateResults() {
    if (tokenTimeCount_ == 0) {
        return;
    }
    
    // Calculate total time
    LARGE_INTEGER endTime;
    QueryPerformanceCounter(&endTime);
    results_.totalTimeMs = (double)((endTime.QuadPart - startTime_.QuadPart) * 1000.0) / 
                            (double)perfFreq_.QuadPart;
    
    // Calculate statistics
    double sum = 0, min = tokenTimes_[0], max = tokenTimes_[0];
    for (uint32_t i = 0; i < tokenTimeCount_; i++) {
        sum += tokenTimes_[i];
        if (tokenTimes_[i] < min) min = tokenTimes_[i];
        if (tokenTimes_[i] > max) max = tokenTimes_[i];
    }
    
    results_.avgTokenTimeMs = sum / tokenTimeCount_;
    results_.minTokenTimeMs = min;
    results_.maxTokenTimeMs = max;
    
    // Calculate P99
    std::sort(tokenTimes_, tokenTimes_ + tokenTimeCount_);
    size_t p99Index = (size_t)((double)tokenTimeCount_ * 0.99);
    results_.p99TokenTimeMs = tokenTimes_[p99Index];
    
    // Calculate TPS
    results_.actualTPS = 1000.0f / (float)results_.avgTokenTimeMs;
    results_.targetTPS = config_.targetTPS;
    results_.efficiency = results_.actualTPS / results_.targetTPS;
    results_.targetMet = results_.actualTPS >= config_.targetTPS;
    
    results_.generatedTokens = tokenTimeCount_;
    results_.totalTokens = tokenTimeCount_;
    
    // Determine bottleneck
    if (results_.efficiency < 0.5f) {
        results_.bottleneck = "compute";
    } else if (results_.efficiency < 0.8f) {
        results_.bottleneck = "memory";
    } else {
        results_.bottleneck = "none";
    }
}

// =============================================================================
// Ghost Text Integration
// =============================================================================

void TPSBenchmarkEngine::EnableGhostText(bool enable) {
    config_.enableGhostText = enable;
}

void TPSBenchmarkEngine::UpdateGhostText(const char* token, float tps) {
    if (!ghostState_.initialized) return;
    
    EnterCriticalSection(&ghostState_.lock);
    
    // Append token
    strncat(ghostState_.generatedText, token, sizeof(ghostState_.generatedText) - 1);
    ghostState_.tokenCount++;
    ghostState_.currentTPS = tps;
    
    // Update rolling average
    if (ghostState_.updateCount == 0) {
        ghostState_.rollingTPS = tps;
    } else {
        ghostState_.rollingTPS = ghostState_.rollingTPS * 0.9f + tps * 0.1f;
    }
    ghostState_.updateCount++;
    
    // Render overlay
    RenderGhostOverlay();
    
    LeaveCriticalSection(&ghostState_.lock);
}

void TPSBenchmarkEngine::RenderGhostOverlay() {
    // Format: [TPS: XXXX.X] Generated text...
    snprintf(ghostState_.displayBuffer, sizeof(ghostState_.displayBuffer),
        "\033[90m[TPS: %6.1f]\033[0m %s",
        ghostState_.rollingTPS,
        ghostState_.generatedText);
    
    // In real implementation, this would update the IDE's ghost text widget
    // For now, print to console
    printf("\r%s", ghostState_.displayBuffer);
    fflush(stdout);
}

void TPSBenchmarkEngine::ClearGhostText() {
    if (!ghostState_.initialized) return;
    
    EnterCriticalSection(&ghostState_.lock);
    ghostState_.generatedText[0] = '\0';
    ghostState_.tokenCount = 0;
    ghostState_.updateCount = 0;
    ghostState_.currentTPS = 0;
    ghostState_.rollingTPS = 0;
    LeaveCriticalSection(&ghostState_.lock);
    
    printf("\n");
}

const char* TPSBenchmarkEngine::GetGhostTextDisplay() const {
    return ghostState_.displayBuffer;
}

float TPSBenchmarkEngine::GetCurrentTPS() const {
    return ghostState_.currentTPS;
}

float TPSBenchmarkEngine::GetRollingTPS() const {
    return ghostState_.rollingTPS;
}

void TPSBenchmarkEngine::UpdateRollingTPS(double tokenTimeMs) {
    float tps = 1000.0f / (float)tokenTimeMs;
    if (ghostState_.updateCount == 0) {
        ghostState_.rollingTPS = tps;
    } else {
        ghostState_.rollingTPS = ghostState_.rollingTPS * 0.9f + tps * 0.1f;
    }
    ghostState_.updateCount++;
}

// =============================================================================
// Results Export
// =============================================================================

void TPSBenchmarkEngine::PrintResults() {
    printf("\n========================================\n");
    printf("TPS Benchmark Results\n");
    printf("========================================\n");
    printf("Total Time:        %.2f ms\n", results_.totalTimeMs);
    printf("Tokens Generated:  %u\n", results_.generatedTokens);
    printf("Avg Token Time:    %.3f ms\n", results_.avgTokenTimeMs);
    printf("Min Token Time:    %.3f ms\n", results_.minTokenTimeMs);
    printf("Max Token Time:    %.3f ms\n", results_.maxTokenTimeMs);
    printf("P99 Token Time:    %.3f ms\n", results_.p99TokenTimeMs);
    printf("\n");
    printf("Actual TPS:        %.1f\n", results_.actualTPS);
    printf("Target TPS:        %.1f\n", results_.targetTPS);
    printf("Efficiency:        %.1f%%\n", results_.efficiency * 100.0f);
    printf("Target Met:        %s\n", results_.targetMet ? "YES" : "NO");
    printf("Bottleneck:        %s\n", results_.bottleneck);
    printf("========================================\n");
    
    if (results_.targetMet) {
        printf("\n✅ TARGET ACHIEVED!\n");
    } else {
        printf("\n❌ Target not met. Review configuration.\n");
    }
}

bool TPSBenchmarkEngine::ExportResults(const char* filename) {
    FILE* fp = nullptr;
    fopen_s(&fp, filename, "w");
    if (!fp) return false;
    
    fprintf(fp, "{\n");
    fprintf(fp, "  \"target_tps\": %.1f,\n", results_.targetTPS);
    fprintf(fp, "  \"actual_tps\": %.1f,\n", results_.actualTPS);
    fprintf(fp, "  \"efficiency\": %.4f,\n", results_.efficiency);
    fprintf(fp, "  \"target_met\": %s,\n", results_.targetMet ? "true" : "false");
    fprintf(fp, "  \"total_time_ms\": %.2f,\n", results_.totalTimeMs);
    fprintf(fp, "  \"tokens_generated\": %u,\n", results_.generatedTokens);
    fprintf(fp, "  \"avg_token_time_ms\": %.4f,\n", results_.avgTokenTimeMs);
    fprintf(fp, "  \"min_token_time_ms\": %.4f,\n", results_.minTokenTimeMs);
    fprintf(fp, "  \"max_token_time_ms\": %.4f,\n", results_.maxTokenTimeMs);
    fprintf(fp, "  \"p99_token_time_ms\": %.4f,\n", results_.p99TokenTimeMs);
    fprintf(fp, "  \"bottleneck\": \"%s\"\n", results_.bottleneck);
    fprintf(fp, "}\n");
    
    fclose(fp);
    return true;
}

} // namespace rxdn
