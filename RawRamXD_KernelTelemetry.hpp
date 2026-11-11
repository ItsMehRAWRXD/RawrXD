// =============================================================================
// RawRamXD_KernelTelemetry.hpp - Kernel-Backed Residency Telemetry
// =============================================================================
// Uses real Windows kernel APIs:
//   - DXGI QueryVideoMemoryInfo for VRAM residency
//   - QueryWorkingSetEx for RAM page residency
//   - GetProcessMemoryInfo for page fault counters
//   - DeviceIoControl(IOCTL_DISK_PERFORMANCE) for NVMe I/O
//   - ETW for high-resolution I/O tracing
// =============================================================================

#ifndef RAWRAMXD_KERNEL_TELEMETRY_HPP
#define RAWRAMXD_KERNEL_TELEMETRY_HPP

#include <cstdint>
#include <cstddef>
#include <atomic>
#include <vector>
#include <chrono>
#include <functional>
#include <thread>
#include <mutex>

// Windows kernel APIs
#include <windows.h>
#include <psapi.h>
#include <d3d12.h>
#include <dxgi1_6.h>
#include <wrl/client.h>

// For ETW
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>

#pragma comment(lib, "d3d12.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")

namespace rawramxd {

using Microsoft::WRL::ComPtr;

// =============================================================================
// Kernel-Backed Telemetry Structures
// =============================================================================

struct VRAMResidencyInfo {
    uint64_t budget;                    // DXGI_QUERY_VIDEO_MEMORY_INFO.Budget
    uint64_t currentUsage;              // DXGI_QUERY_VIDEO_MEMORY_INFO.CurrentUsage
    uint64_t availableForReservation;   // DXGI_QUERY_VIDEO_MEMORY_INFO.AvailableForReservation
    uint64_t currentReservation;          // DXGI_QUERY_VIDEO_MEMORY_INFO.CurrentReservation
    float residencyPressure;              // 0.0 - 1.0 (usage / budget)
    uint64_t evictedSize;               // Bytes evicted by OS
    uint32_t evictionCount;             // Number of evictions
};

struct RAMPagingInfo {
    SIZE_T workingSetSize;              // Current working set
    SIZE_T peakWorkingSet;              // Peak working set
    SIZE_T pageFaultCount;              // Total page faults
    SIZE_T quotaPagedPoolUsage;         // Paged pool usage
    SIZE_T quotaNonPagedPoolUsage;      // Non-paged pool usage
    SIZE_T pagefileUsage;               // Pagefile usage
    
    // Working set breakdown (from QueryWorkingSetEx)
    SIZE_T wsSharedPages;               // Shared pages in working set
    SIZE_T wsPrivatePages;              // Private pages in working set
    SIZE_T wsShareablePages;            // Shareable pages
    float ramPressure;                  // 0.0 - 1.0
};

struct NVMeIOInfo {
    uint64_t bytesRead;                 // Total bytes read
    uint64_t bytesWritten;              // Total bytes written
    uint64_t readTime;                  // Time spent reading (100ns units)
    uint64_t writeTime;                 // Time spent writing (100ns units)
    uint64_t queueDepth;                // Current queue depth
    uint32_t splitIOCount;              // Split I/O operations
    uint64_t ioLatencyUs;               // Average I/O latency (microseconds)
    float ioPressure;                   // 0.0 - 1.0 (queue depth / max)
};

struct TensorHotness {
    uint64_t handle;                    // Tensor handle
    uint64_t accessCount;               // Total accesses
    uint64_t lastAccessTick;            // Last access timestamp
    uint64_t bytesRead;                 // Bytes read from this tensor
    uint64_t bytesWritten;              // Bytes written to this tensor
    uint32_t currentTier;               // Current residency tier
    float hotnessScore;                 // 0.0 - 1.0 calculated hotness
    bool isResident;                    // Currently resident in fast tier
};

struct TPSCollapsePoint {
    uint64_t timestamp;                 // When collapse occurred
    float tpsBefore;                    // TPS before collapse
    float tpsAfter;                     // TPS after collapse
    float vramPressureAtCollapse;       // VRAM pressure 0-1
    float ramPressureAtCollapse;        // RAM pressure 0-1
    float ioPressureAtCollapse;         // I/O pressure 0-1
    uint32_t migrationCount;              // Migrations in progress
    uint64_t pageFaults;                // Page faults at collapse
    std::string triggerReason;          // Why collapse occurred
};

struct KernelTelemetrySnapshot {
    uint64_t timestamp;                 // Sample timestamp
    uint64_t tickCount;                 // Sample number
    
    VRAMResidencyInfo vram;
    RAMPagingInfo ram;
    NVMeIOInfo nvme;
    
    float currentTPS;                   // Measured TPS
    float targetTPS;                    // Target TPS
    float tpsDelta;                     // TPS change from last sample
    
    std::vector<TensorHotness> hotTensors;  // Top hot tensors
    std::vector<TPSCollapsePoint> recentCollapses;  // Recent collapse events
    
    // Elastic memory curve data
    float elasticEfficiency;            // 0-1 efficiency score
    float degradationFactor;            // Current degradation multiplier
};

// =============================================================================
// Kernel Telemetry Collector
// =============================================================================

class KernelTelemetryCollector {
public:
    using TelemetryCallback = std::function<void(const KernelTelemetrySnapshot&)>;
    using CollapseCallback = std::function<void(const TPSCollapsePoint&)>;

    KernelTelemetryCollector();
    ~KernelTelemetryCollector();

    // Initialize with real hardware handles
    bool Initialize(IDXGIAdapter3* adapter, HANDLE processHandle = GetCurrentProcess());
    
    // Start/stop collection
    bool StartCollection(uint32_t sampleIntervalMs = 16);  // ~60Hz default
    void StopCollection();
    
    // Manual sampling
    KernelTelemetrySnapshot SampleNow();
    
    // Callbacks
    void SetTelemetryCallback(TelemetryCallback cb) { telemetryCallback_ = cb; }
    void SetCollapseCallback(CollapseCallback cb) { collapseCallback_ = cb; }
    
    // TPS tracking
    void ReportTokenGenerated(uint64_t timestamp);
    void SetTargetTPS(float tps) { targetTPS_ = tps; }
    
    // Tensor registration for hotness tracking
    void RegisterTensor(uint64_t handle, size_t size, uint32_t tier);
    void UpdateTensorAccess(uint64_t handle, size_t bytesRead, size_t bytesWritten);
    void UpdateTensorTier(uint64_t handle, uint32_t newTier);
    void UnregisterTensor(uint64_t handle);
    
    // Get current state
    float GetCurrentTPS() const { return currentTPS_.load(); }
    float GetVRAMPressure() const;
    float GetRAMPressure() const;
    float GetIOPressure() const;
    
    // Elastic curve calculation
    float CalculateElasticEfficiency() const;
    float CalculateDegradationFactor() const;

private:
    // Collection thread
    void CollectionLoop();
    
    // Kernel API queries
    VRAMResidencyInfo QueryVRAMResidency();
    RAMPagingInfo QueryRAMPaging();
    NVMeIOInfo QueryNVMeIO();
    
    // Working set query (kernel-level)
    bool QueryWorkingSetDetailed(RAMPagingInfo& info);
    
    // Disk performance query
    bool QueryDiskPerformance(NVMeIOInfo& info);
    
    // TPS calculation
    void UpdateTPS();
    bool DetectCollapse(const KernelTelemetrySnapshot& current, 
                        const KernelTelemetrySnapshot& previous);
    
    // Hotness calculation
    void UpdateTensorHotness();
    std::vector<TensorHotness> GetTopHotTensors(size_t count = 10);
    
    // ETW trace session (for high-res I/O)
    bool StartETWSession();
    void StopETWSession();
    static VOID WINAPI ETWEventCallback(PEVENT_RECORD eventRecord);

private:
    // DXGI handles
    ComPtr<IDXGIAdapter3> dxgiAdapter_;
    ComPtr<ID3D12Device> d3dDevice_;
    uint32_t nodeMask_ = 0;
    DXGI_MEMORY_SEGMENT_GROUP memorySegment_ = DXGI_MEMORY_SEGMENT_GROUP_LOCAL;
    
    // Process handle
    HANDLE processHandle_ = nullptr;
    bool ownsProcessHandle_ = false;
    
    // Collection state
    std::atomic<bool> collecting_{false};
    std::thread collectionThread_;
    uint32_t sampleIntervalMs_ = 16;
    
    // TPS tracking
    std::atomic<float> currentTPS_{0.0f};
    std::atomic<float> targetTPS_{0.0f};
    std::vector<uint64_t> tokenTimestamps_;
    std::mutex tokenMutex_;
    static constexpr size_t TPS_WINDOW_SIZE = 60;  // 1 second at 60Hz
    
    // Tensor tracking
    struct TrackedTensor {
        uint64_t handle;
        size_t size;
        uint32_t tier;
        std::atomic<uint64_t> accessCount{0};
        std::atomic<uint64_t> lastAccessTick{0};
        std::atomic<uint64_t> bytesRead{0};
        std::atomic<uint64_t> bytesWritten{0};
    };
    std::unordered_map<uint64_t, std::unique_ptr<TrackedTensor>> tensors_;
    std::mutex tensorMutex_;
    uint64_t tickCounter_ = 0;
    
    // Collapse detection
    std::vector<TPSCollapsePoint> collapseHistory_;
    std::mutex collapseMutex_;
    float lastTPS_ = 0.0f;
    static constexpr float COLLAPSE_THRESHOLD = 0.7f;  // TPS drops below 70% of target
    
    // Callbacks
    TelemetryCallback telemetryCallback_;
    CollapseCallback collapseCallback_;
    
    // ETW
    TRACEHANDLE etwSession_ = 0;
    TRACEHANDLE etwTrace_ = 0;
    static KernelTelemetryCollector* instance_;  // For ETW callback
    
    // Previous values for delta calculation
    KernelTelemetrySnapshot lastSnapshot_;
    std::mutex snapshotMutex_;
};

// =============================================================================
// Elastic Memory Curve Generator
// =============================================================================

class ElasticMemoryCurve {
public:
    struct DataPoint {
        float vramPressure;     // 0-1
        float ramPressure;      // 0-1
        float ioPressure;       // 0-1
        float tps;              // Actual TPS
        float efficiency;       // tps / (1 + pressure)
        float degradation;      // tps / max_tps
    };
    
    void AddSample(const KernelTelemetrySnapshot& snapshot);
    std::vector<DataPoint> GetCurve() const;
    
    // Find collapse points
    std::vector<float> FindCollapsePressures() const;
    
    // Generate curve equation: TPS = f(VRAM_pressure, RAM_pressure, IO_pressure)
    std::string GenerateCurveEquation() const;
    
    // Predict TPS at given pressure levels
    float PredictTPS(float vramPressure, float ramPressure, float ioPressure) const;

private:
    std::vector<DataPoint> dataPoints_;
    mutable std::mutex mutex_;
};

} // namespace rawramxd

#endif // RAWRAMXD_KERNEL_TELEMETRY_HPP