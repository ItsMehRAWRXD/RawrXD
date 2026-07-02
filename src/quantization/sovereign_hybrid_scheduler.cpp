// =============================================================================
// sovereign_hybrid_scheduler.cpp
// Hybrid Auto Scheduler - Intelligent Compute Path Selection
// Phase 17: Hybrid Auto / AMX Optimizations
//
// Automatically selects optimal compute path based on:
// - Hardware capabilities (AMX, AVX-512, GPU)
// - Workload characteristics (matrix size, batch size)
// - Runtime profiling data
// =============================================================================

#include "sovereign_hybrid_scheduler.h"
#include <windows.h>
#include <intrin.h>
#include <chrono>
#include <unordered_map>
#include <cmath>

// =============================================================================
// CPU Feature Detection
// =============================================================================

struct CPUFeatures {
    bool hasAMX_TILE;
    bool hasAMX_BF16;
    bool hasAVX512F;
    bool hasAVX512_VNNI;
    bool hasAVX2;
    bool hasFMA;
    
    int family;
    int model;
    int stepping;
    char vendor[13];
};

static CPUFeatures g_cpuFeatures = {};
static bool g_featuresDetected = false;

void DetectCPUFeatures() {
    if (g_featuresDetected) return;
    
    int cpuInfo[4] = {0};
    
    // Get vendor string
    __cpuid(cpuInfo, 0);
    int nIds = cpuInfo[0];
    memcpy(g_cpuFeatures.vendor, &cpuInfo[1], 4);
    memcpy(g_cpuFeatures.vendor + 4, &cpuInfo[3], 4);
    memcpy(g_cpuFeatures.vendor + 8, &cpuInfo[2], 4);
    g_cpuFeatures.vendor[12] = '\0';
    
    // Get family/model/stepping
    __cpuid(cpuInfo, 1);
    g_cpuFeatures.family = ((cpuInfo[0] >> 8) & 0xF) + ((cpuInfo[0] >> 20) & 0xFF);
    g_cpuFeatures.model = ((cpuInfo[0] >> 4) & 0xF) | ((cpuInfo[0] >> 12) & 0xF0);
    g_cpuFeatures.stepping = cpuInfo[0] & 0xF;
    
    // Check AVX2/FMA
    __cpuid(cpuInfo, 1);
    g_cpuFeatures.hasAVX2 = (cpuInfo[2] & (1 << 28)) != 0;
    g_cpuFeatures.hasFMA = (cpuInfo[2] & (1 << 12)) != 0;
    
    // Check AVX-512
    if (nIds >= 7) {
        __cpuid(cpuInfo, 7);
        g_cpuFeatures.hasAVX512F = (cpuInfo[1] & (1 << 16)) != 0;
        g_cpuFeatures.hasAVX512_VNNI = (cpuInfo[2] & (1 << 11)) != 0;
        
        // Check AMX (requires leaf 7, subleaf 0)
        g_cpuFeatures.hasAMX_TILE = (cpuInfo[3] & (1 << 24)) != 0;
        g_cpuFeatures.hasAMX_BF16 = (cpuInfo[3] & (1 << 22)) != 0;
    }
    
    // Check OS support for AMX via XCR0
    if (g_cpuFeatures.hasAMX_TILE) {
        unsigned __int64 xcr0 = _xgetbv(0);
        if ((xcr0 & 0x60000) != 0x60000) {
            // OS hasn't enabled AMX
            g_cpuFeatures.hasAMX_TILE = false;
            g_cpuFeatures.hasAMX_BF16 = false;
        }
    }
    
    g_featuresDetected = true;
}

// =============================================================================
// Workload Characterization
// =============================================================================

enum class WorkloadType {
    ATTENTION_QK,           // Q × K^T
    ATTENTION_SOFTMAX_V,    // Softmax(QK) × V
    FFN_UP_PROJECTION,      // Gate + Up projection
    FFN_DOWN_PROJECTION,    // Down projection
    EMBEDDING_LOOKUP,       // Token embedding
    RMS_NORM,               // RMS normalization
    ROPE,                   // Rotary position embedding
    UNKNOWN
};

struct WorkloadDesc {
    WorkloadType type;
    uint32_t batchSize;
    uint32_t seqLen;
    uint32_t headDim;
    uint32_t hiddenDim;
    uint32_t intermediateDim;
    bool isTransposed;
    
    // Derived metrics
    uint64_t matrixSize() const {
        return static_cast<uint64_t>(seqLen) * headDim;
    }
    
    uint64_t totalFlops() const {
        switch (type) {
            case WorkloadType::ATTENTION_QK:
                return 2ULL * batchSize * seqLen * seqLen * headDim;
            case WorkloadType::FFN_UP_PROJECTION:
                return 2ULL * batchSize * seqLen * hiddenDim * intermediateDim;
            default:
                return matrixSize();
        }
    }
};

// =============================================================================
// Compute Path Selection
// =============================================================================

enum class ComputePath {
    AMX_TILE,           // Intel AMX (fastest for large matrices)
    AVX512_VNNI,        // AVX-512 with VNNI
    AVX512_FMA,         // Standard AVX-512
    AVX2_FMA,           // AVX2 fallback
    SCALAR,             // Scalar fallback
    GPU_COMPUTE,        // GPU offload (if available)
    PATH_COUNT
};

struct PathMetrics {
    ComputePath path;
    float avgLatencyMs;
    float minLatencyMs;
    float maxLatencyMs;
    uint64_t invocationCount;
    float successRate;
    uint64_t totalFlopsProcessed;
    
    float efficiency() const {
        if (avgLatencyMs <= 0) return 0;
        return static_cast<float>(totalFlopsProcessed) / (avgLatencyMs * 1000000.0f);
    }
};

class HybridScheduler {
private:
    std::unordered_map<WorkloadType, PathMetrics> pathCache;
    std::unordered_map<WorkloadType, ComputePath> optimalPaths;
    
    bool gpuAvailable = false;
    
public:
    void Initialize() {
        DetectCPUFeatures();
        
        // Log detected features
        printf("[HybridScheduler] CPU Features Detected:\n");
        printf("  Vendor: %s\n", g_cpuFeatures.vendor);
        printf("  Family: %d, Model: %d, Stepping: %d\n", 
               g_cpuFeatures.family, g_cpuFeatures.model, g_cpuFeatures.stepping);
        printf("  AMX-TILE: %s\n", g_cpuFeatures.hasAMX_TILE ? "YES" : "NO");
        printf("  AMX-BF16: %s\n", g_cpuFeatures.hasAMX_BF16 ? "YES" : "NO");
        printf("  AVX-512F: %s\n", g_cpuFeatures.hasAVX512F ? "YES" : "NO");
        printf("  AVX-512-VNNI: %s\n", g_cpuFeatures.hasAVX512_VNNI ? "YES" : "NO");
        printf("  AVX2: %s\n", g_cpuFeatures.hasAVX2 ? "YES" : "NO");
        printf("  FMA: %s\n", g_cpuFeatures.hasFMA ? "YES" : "NO");
    }
    
    ComputePath SelectOptimalPath(const WorkloadDesc& workload) {
        // Check cache for established optimal path
        auto it = optimalPaths.find(workload.type);
        if (it != optimalPaths.end()) {
            auto& metrics = pathCache[workload.type];
            if (metrics.invocationCount > 10 && metrics.successRate > 0.95f) {
                return it->second;
            }
        }
        
        // Dynamic path selection based on workload characteristics
        ComputePath selectedPath = ComputePath::AVX2_FMA;  // Default fallback
        
        // AMX path: Best for large matrix multiplies
        if (g_cpuFeatures.hasAMX_TILE && g_cpuFeatures.hasAMX_BF16) {
            if (workload.matrixSize() >= 1024 && 
                (workload.type == WorkloadType::ATTENTION_QK ||
                 workload.type == WorkloadType::FFN_UP_PROJECTION)) {
                selectedPath = ComputePath::AMX_TILE;
            }
        }
        
        // AVX-512 VNNI: Good for quantized operations
        else if (g_cpuFeatures.hasAVX512_VNNI) {
            if (workload.batchSize > 1 || workload.matrixSize() >= 512) {
                selectedPath = ComputePath::AVX512_VNNI;
            }
        }
        
        // Standard AVX-512
        else if (g_cpuFeatures.hasAVX512F) {
            if (workload.matrixSize() >= 256) {
                selectedPath = ComputePath::AVX512_FMA;
            }
        }
        
        // AVX2 fallback
        else if (g_cpuFeatures.hasAVX2) {
            selectedPath = ComputePath::AVX2_FMA;
        }
        
        // GPU path (if available and suitable)
        if (gpuAvailable && workload.totalFlops() > 1000000) {
            // Only offload large workloads to GPU
            // selectedPath = ComputePath::GPU_COMPUTE;
        }
        
        return selectedPath;
    }
    
    void RecordMetrics(const WorkloadDesc& workload, ComputePath usedPath, 
                       float latencyMs, bool success) {
        auto& metrics = pathCache[workload.type];
        
        // Update running statistics
        if (metrics.invocationCount == 0) {
            metrics.path = usedPath;
            metrics.avgLatencyMs = latencyMs;
            metrics.minLatencyMs = latencyMs;
            metrics.maxLatencyMs = latencyMs;
        } else {
            // Exponential moving average
            metrics.avgLatencyMs = 0.9f * metrics.avgLatencyMs + 0.1f * latencyMs;
            metrics.minLatencyMs = std::min(metrics.minLatencyMs, latencyMs);
            metrics.maxLatencyMs = std::max(metrics.maxLatencyMs, latencyMs);
        }
        
        metrics.invocationCount++;
        metrics.totalFlopsProcessed += workload.totalFlops();
        
        // Update success rate
        float successVal = success ? 1.0f : 0.0f;
        metrics.successRate = 0.95f * metrics.successRate + 0.05f * successVal;
        
        // Update optimal path if we have enough samples
        if (metrics.invocationCount >= 20) {
            optimalPaths[workload.type] = usedPath;
        }
    }
    
    void ForcePath(WorkloadType type, ComputePath path) {
        optimalPaths[type] = path;
    }
    
    const char* GetPathName(ComputePath path) {
        switch (path) {
            case ComputePath::AMX_TILE: return "AMX_TILE";
            case ComputePath::AVX512_VNNI: return "AVX512_VNNI";
            case ComputePath::AVX512_FMA: return "AVX512_FMA";
            case ComputePath::AVX2_FMA: return "AVX2_FMA";
            case ComputePath::SCALAR: return "SCALAR";
            case ComputePath::GPU_COMPUTE: return "GPU_COMPUTE";
            default: return "UNKNOWN";
        }
    }
    
    void PrintStats() {
        printf("\n[HybridScheduler] Performance Statistics:\n");
        printf("%-20s %-12s %-12s %-12s %-10s\n", 
               "Workload", "Path", "Avg(ms)", "Count", "Success");
        printf("%-20s %-12s %-12s %-12s %-10s\n", 
               "--------", "----", "-------", "-----", "-------");
        
        for (const auto& [type, metrics] : pathCache) {
            const char* typeName = "UNKNOWN";
            switch (type) {
                case WorkloadType::ATTENTION_QK: typeName = "ATTENTION_QK"; break;
                case WorkloadType::FFN_UP_PROJECTION: typeName = "FFN_UP"; break;
                case WorkloadType::FFN_DOWN_PROJECTION: typeName = "FFN_DOWN"; break;
                default: break;
            }
            
            printf("%-20s %-12s %-12.3f %-12llu %-10.1f%%\n",
                   typeName,
                   GetPathName(metrics.path),
                   metrics.avgLatencyMs,
                   metrics.invocationCount,
                   metrics.successRate * 100.0f);
        }
    }
};

// =============================================================================
// Global Instance
// =============================================================================

static HybridScheduler g_scheduler;

// =============================================================================
// C API
// =============================================================================

extern "C" {

__declspec(dllexport) void Sovereign_Hybrid_Init() {
    g_scheduler.Initialize();
}

__declspec(dllexport) int Sovereign_Hybrid_SelectPath(int workloadType,
                                                       uint32_t batchSize,
                                                       uint32_t seqLen,
                                                       uint32_t headDim) {
    WorkloadDesc desc;
    desc.type = static_cast<WorkloadType>(workloadType);
    desc.batchSize = batchSize;
    desc.seqLen = seqLen;
    desc.headDim = headDim;
    
    ComputePath path = g_scheduler.SelectOptimalPath(desc);
    return static_cast<int>(path);
}

__declspec(dllexport) void Sovereign_Hybrid_RecordMetrics(int workloadType,
                                                           int usedPath,
                                                           float latencyMs,
                                                           int success) {
    WorkloadDesc desc;
    desc.type = static_cast<WorkloadType>(workloadType);
    
    g_scheduler.RecordMetrics(desc, 
                               static_cast<ComputePath>(usedPath),
                               latencyMs,
                               success != 0);
}

__declspec(dllexport) void Sovereign_Hybrid_PrintStats() {
    g_scheduler.PrintStats();
}

__declspec(dllexport) int Sovereign_Hybrid_GetCPUFeatures() {
    DetectCPUFeatures();
    int features = 0;
    if (g_cpuFeatures.hasAMX_TILE) features |= 0x01;
    if (g_cpuFeatures.hasAMX_BF16) features |= 0x02;
    if (g_cpuFeatures.hasAVX512F) features |= 0x04;
    if (g_cpuFeatures.hasAVX512_VNNI) features |= 0x08;
    if (g_cpuFeatures.hasAVX2) features |= 0x10;
    if (g_cpuFeatures.hasFMA) features |= 0x20;
    return features;
}

} // extern "C"
