// ============================================================================
// Deep2.cpp - Deep2 Engine Implementation
// C++ wrapper for MASM kernels with MoE orchestration
// ============================================================================

#include "Deep2.h"
#include <cstring>
#include <cstdlib>
#include <random>
#include <chrono>

#ifdef _WIN32
    #include <windows.h>
    #include <intrin.h>
#else
    #include <cpuid.h>
    #include <x86intrin.h>
#endif

namespace Deep2 {

// ============================================================================
// CPU Feature Detection
// ============================================================================
static bool g_avx2Checked = false;
static bool g_hasAVX2 = false;
static bool g_hasAVX512 = false;

static void CheckCPUFeatures() {
    if (g_avx2Checked) return;
    
    int cpuInfo[4] = {0};
    
#ifdef _WIN32
    __cpuid(cpuInfo, 1);
    bool hasAVX = (cpuInfo[2] & (1 << 28)) != 0;
    
    __cpuidex(cpuInfo, 7, 0);
    g_hasAVX2 = hasAVX && ((cpuInfo[1] & (1 << 5)) != 0);
    g_hasAVX512 = g_hasAVX2 && ((cpuInfo[1] & (1 << 16)) != 0); // AVX-512F
#else
    __cpuid(1, cpuInfo[0], cpuInfo[1], cpuInfo[2], cpuInfo[3]);
    bool hasAVX = (cpuInfo[2] & (1 << 28)) != 0;
    
    __cpuid_count(7, 0, cpuInfo[0], cpuInfo[1], cpuInfo[2], cpuInfo[3]);
    g_hasAVX2 = hasAVX && ((cpuInfo[1] & (1 << 5)) != 0);
    g_hasAVX512 = g_hasAVX2 && ((cpuInfo[1] & (1 << 16)) != 0);
#endif
    
    g_avx2Checked = true;
}

// ============================================================================
// Utility Functions
// ============================================================================
namespace Utils {

float* AlignedAlloc(size_t count) {
#ifdef _WIN32
    return (float*)_aligned_malloc(count * sizeof(float), 32);
#else
    return (float*)aligned_alloc(32, count * sizeof(float));
#endif
}

void AlignedFree(float* ptr) {
    if (!ptr) return;
#ifdef _WIN32
    _aligned_free(ptr);
#else
    free(ptr);
#endif
}

bool HasAVX2() {
    CheckCPUFeatures();
    return g_hasAVX2;
}

bool HasAVX512() {
    CheckCPUFeatures();
    return g_hasAVX512;
}

void AlignedCopy(float* dst, const float* src, size_t count) {
    // Check alignment
    bool dstAligned = ((uintptr_t)dst & 31) == 0;
    bool srcAligned = ((uintptr_t)src & 31) == 0;
    
    if (dstAligned && srcAligned && (count & 7) == 0) {
        // Fast path: both aligned, count multiple of 8
        for (size_t i = 0; i < count; i += 8) {
            _mm256_store_ps(dst + i, _mm256_load_ps(src + i));
        }
    } else {
        // Fallback: standard copy
        memcpy(dst, src, count * sizeof(float));
    }
}

void InitRandom(float* data, size_t count, float scale) {
    static std::mt19937 gen(std::random_device{}());
    std::normal_distribution<float> dist(0.0f, scale);
    
    for (size_t i = 0; i < count; ++i) {
        data[i] = dist(gen);
    }
}

void Zero(float* data, size_t count) {
    memset(data, 0, count * sizeof(float));
}

} // namespace Utils

// ============================================================================
// Performance Metrics
// ============================================================================
namespace Perf {

uint64_t ReadTSC() {
#ifdef _WIN32
    return __rdtsc();
#else
    unsigned int lo, hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
#endif
}

void Metrics::Start() {
    cyclesStart = ReadTSC();
}

void Metrics::Stop() {
    cyclesEnd = ReadTSC();
}

} // namespace Perf

// ============================================================================
// Context Implementation
// ============================================================================
Context::Context() = default;

Context::~Context() {
    FreeBuffers();
}

bool Context::Initialize(const Config& config) {
    if (!Utils::HasAVX2()) {
        strncpy(m_lastError, "AVX2 not supported on this CPU", sizeof(m_lastError) - 1);
        return false;
    }
    
    m_config = config;
    
    // Allocate scratch buffer for intermediate computations
    // Size: hiddenDim * expertsPerToken * 2 (for safety)
    m_scratchSize = config.hiddenDim * config.expertsPerToken * 2;
    if (!AllocateBuffers()) {
        strncpy(m_lastError, "Failed to allocate scratch buffer", sizeof(m_lastError) - 1);
        return false;
    }
    
    m_initialized = true;
    return true;
}

bool Context::AllocateBuffers() {
    m_scratchBuffer = Utils::AlignedAlloc(m_scratchSize);
    return m_scratchBuffer != nullptr;
}

void Context::FreeBuffers() {
    if (m_scratchBuffer) {
        Utils::AlignedFree(m_scratchBuffer);
        m_scratchBuffer = nullptr;
    }
}

void Context::Forward(const float* input, float* output, size_t tokenCount) {
    if (!m_initialized || !input || !output) return;
    
    // Simplified forward pass for demonstration
    // In production, this would orchestrate the full transformer layers
    
    for (size_t t = 0; t < tokenCount; ++t) {
        const float* tokenIn = input + t * m_config.hiddenDim;
        float* tokenOut = output + t * m_config.hiddenDim;
        
        // Route to experts
        ExpertRouting routing;
        RouteExperts(tokenIn, &routing, 1);
        
        // Process through selected experts
        // (Simplified - would call expert kernels here)
        Utils::Zero(tokenOut, m_config.hiddenDim);
        
        // Accumulate expert outputs weighted by routing weights
        for (int i = 0; i < routing.numExperts; ++i) {
            // Expert computation would go here
            // For now, just copy input weighted by routing weight
            for (size_t j = 0; j < m_config.hiddenDim; ++j) {
                tokenOut[j] += tokenIn[j] * routing.weights[i];
            }
        }
        
        // Apply RMSNorm
        Deep2_RMSNorm(tokenOut, tokenOut, m_config.hiddenDim, m_config.eps);
    }
}

void Context::RouteExperts(const float* input, ExpertRouting* routing, size_t count) {
    if (!routing) return;
    
    // Simplified top-k routing
    // In production, this would use a learned gating network
    
    for (size_t i = 0; i < count; ++i) {
        // Mock routing: select experts 0-7 with equal weights
        routing[i].numExperts = static_cast<int32_t>(m_config.expertsPerToken);
        
        float weightSum = 0.0f;
        for (size_t j = 0; j < m_config.expertsPerToken; ++j) {
            routing[i].expertIds[j] = static_cast<int32_t>(j);
            // Mock weight based on input magnitude
            float w = 1.0f + (input[i * m_config.hiddenDim] * 0.1f);
            routing[i].weights[j] = w > 0 ? w : 0.01f;
            weightSum += routing[i].weights[j];
        }
        
        // Normalize weights
        for (size_t j = 0; j < m_config.expertsPerToken; ++j) {
            routing[i].weights[j] /= weightSum;
        }
    }
}

} // namespace Deep2

// ============================================================================
// C Interface Implementation
// ============================================================================
extern "C" {

void* Deep2_CreateEngine() {
    return new Deep2::Context();
}

void Deep2_DestroyEngine(void* engine) {
    delete static_cast<Deep2::Context*>(engine);
}

int Deep2_Initialize(void* engine, const Deep2::Config* config) {
    if (!engine || !config) return -1;
    auto* ctx = static_cast<Deep2::Context*>(engine);
    return ctx->Initialize(*config) ? 0 : -1;
}

void Deep2_Forward(void* engine, const float* input, float* output, size_t count) {
    if (!engine || !input || !output) return;
    auto* ctx = static_cast<Deep2::Context*>(engine);
    ctx->Forward(input, output, count);
}

void Deep2_RouteExperts(void* engine, const float* input, Deep2::ExpertRouting* routing, size_t count) {
    if (!engine || !input || !routing) return;
    auto* ctx = static_cast<Deep2::Context*>(engine);
    ctx->RouteExperts(input, routing, count);
}

int Deep2_HasAVX2() {
    return Deep2::Utils::HasAVX2() ? 1 : 0;
}

int Deep2_HasAVX512() {
    return Deep2::Utils::HasAVX512() ? 1 : 0;
}

float* Deep2_AlignedAlloc(size_t count) {
    return Deep2::Utils::AlignedAlloc(count);
}

void Deep2_AlignedFree(float* ptr) {
    Deep2::Utils::AlignedFree(ptr);
}

} // extern "C"
